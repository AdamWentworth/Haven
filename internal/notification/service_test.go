package notification

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

type fakeSender struct {
	statuses []int
	errors   []error
	payloads [][]byte
}

func (sender *fakeSender) Send(_ context.Context, _ Subscription, payload []byte, _ DeliveryOptions) (int, error) {
	sender.payloads = append(sender.payloads, append([]byte(nil), payload...))
	index := len(sender.payloads) - 1
	status := http.StatusCreated
	if index < len(sender.statuses) {
		status = sender.statuses[index]
	}
	if index < len(sender.errors) {
		return status, sender.errors[index]
	}
	return status, nil
}

func notificationTestService(t *testing.T, sender Sender) (*Service, *storage.Store) {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, t.TempDir(), "https://haven.example.invalid", slog.New(slog.NewTextHandler(io.Discard, nil)), WithSender(sender))
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return service, store
}

func validSubscription() Subscription {
	public := make([]byte, 65)
	public[0] = 4
	for index := 1; index < len(public); index++ {
		public[index] = byte(index)
	}
	auth := []byte("0123456789abcdef")
	return Subscription{
		Endpoint: "https://push.example.invalid/delivery/capability-token",
		Keys: SubscriptionKeys{
			Auth:   base64.RawURLEncoding.EncodeToString(auth),
			P256dh: base64.RawURLEncoding.EncodeToString(public),
		},
	}
}

func alertInstance(instance, severity string) model.Alert {
	return model.Alert{ID: "finding:device-a:firewall", InstanceID: instance, DeviceID: "device-a", DeviceName: "Test workstation", Kind: "finding", Severity: severity, Title: "Sensitive finding title", Summary: "Sensitive finding details", StartedAt: time.Now().UTC()}
}

func TestSubscribeBaselinesExistingAlertsAndEncryptsCapabilityEndpoint(t *testing.T) {
	sender := &fakeSender{}
	service, store := notificationTestService(t, sender)
	defer store.Close()
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	record, created, err := service.Subscribe(context.Background(), validSubscription(), "Test browser", []model.Alert{alertInstance("existing", "high")}, now)
	if err != nil || !created {
		t.Fatalf("expected a new subscription: %#v, %v", record, err)
	}
	if strings.Contains(string(record.EncryptedSubscription), "push.example.invalid") {
		t.Fatal("the push capability endpoint must be encrypted at rest")
	}
	if err := service.Reconcile(context.Background(), []model.Alert{alertInstance("existing", "high")}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 0 {
		t.Fatal("alerts present when notifications are enabled must be baselined")
	}
	status, err := service.Status(context.Background(), time.Minute)
	if err != nil || len(status.Destinations) != 1 || status.PendingCount != 0 {
		t.Fatalf("unexpected notification status: %#v, %v", status, err)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "encryptedSubscription") || strings.Contains(string(encoded), "push.example.invalid") {
		t.Fatal("notification status must not expose endpoint capability data")
	}
}

func TestReconcileDeliversOneGenericNotificationPerAlertInstance(t *testing.T) {
	sender := &fakeSender{}
	service, store := notificationTestService(t, sender)
	defer store.Close()
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	if _, _, err := service.Subscribe(context.Background(), validSubscription(), "Test browser", nil, now); err != nil {
		t.Fatal(err)
	}
	alert := alertInstance("first-instance", "medium")
	if err := service.Reconcile(context.Background(), []model.Alert{alert}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background(), []model.Alert{alert}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 1 {
		t.Fatalf("expected exactly one delivery, got %d", len(sender.payloads))
	}
	payload := string(sender.payloads[0])
	if strings.Contains(payload, alert.Title) || strings.Contains(payload, alert.Summary) || !strings.Contains(payload, "Open HAVEN to review") {
		t.Fatalf("push payload must stay generic: %s", payload)
	}
	recurrence := alert
	recurrence.InstanceID = "second-instance"
	if err := service.Reconcile(context.Background(), []model.Alert{recurrence}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 2 {
		t.Fatal("a resolved-and-recurred alert must create a new delivery")
	}
}

func TestReconcileRetriesTransientFailuresAndNeverSendsLowAlerts(t *testing.T) {
	sender := &fakeSender{statuses: []int{0, http.StatusCreated}, errors: []error{errors.New("temporary network failure")}}
	service, store := notificationTestService(t, sender)
	defer store.Close()
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	if _, _, err := service.Subscribe(context.Background(), validSubscription(), "Test browser", nil, now); err != nil {
		t.Fatal(err)
	}
	medium := alertInstance("retry-instance", "medium")
	low := alertInstance("low-instance", "low")
	if err := service.Reconcile(context.Background(), []model.Alert{medium, low}, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background(), []model.Alert{medium, low}, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 1 {
		t.Fatal("a retry must respect its durable backoff")
	}
	if err := service.Reconcile(context.Background(), []model.Alert{medium, low}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 2 {
		t.Fatalf("expected one retry and no low-severity delivery, got %d calls", len(sender.payloads))
	}
}

func TestReconcileExpiresRetryWhenAlertIsNoLongerCurrent(t *testing.T) {
	sender := &fakeSender{statuses: []int{0}, errors: []error{errors.New("temporary network failure")}}
	service, store := notificationTestService(t, sender)
	defer store.Close()
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	if _, _, err := service.Subscribe(context.Background(), validSubscription(), "Test browser", nil, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background(), []model.Alert{alertInstance("resolved-before-retry", "medium")}, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background(), nil, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(context.Background(), time.Minute)
	if err != nil || status.PendingCount != 0 {
		t.Fatalf("resolved alerts must cancel queued retries: %#v, %v", status, err)
	}
	if err := service.Reconcile(context.Background(), nil, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.payloads) != 1 {
		t.Fatal("a resolved alert must not retry")
	}
}

func TestReconcileRemovesExpiredPushDestination(t *testing.T) {
	sender := &fakeSender{statuses: []int{http.StatusGone}}
	service, store := notificationTestService(t, sender)
	defer store.Close()
	now := time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)
	if _, _, err := service.Subscribe(context.Background(), validSubscription(), "Test browser", nil, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(context.Background(), []model.Alert{alertInstance("expired-destination", "high")}, now); err != nil {
		t.Fatal(err)
	}
	status, err := service.Status(context.Background(), time.Minute)
	if err != nil || len(status.Destinations) != 0 {
		t.Fatalf("HTTP 410 must remove the unusable capability endpoint: %#v, %v", status, err)
	}
}

func TestSubscriptionValidationRejectsSSRFAndMalformedKeys(t *testing.T) {
	subscription := validSubscription()
	subscription.Endpoint = "https://127.0.0.1/push"
	if _, err := validateSubscription(subscription, time.Now()); err == nil {
		t.Fatal("literal-IP push endpoints must be rejected")
	}
	subscription = validSubscription()
	subscription.Keys.Auth = "short"
	if _, err := validateSubscription(subscription, time.Now()); err == nil {
		t.Fatal("malformed subscription keys must be rejected")
	}
	privateAddresses := []netip.Addr{
		netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		netip.AddrFrom4([4]byte{10, 0, 0, 1}),
		netip.AddrFrom4([4]byte{169, 254, 1, 1}),
		netip.IPv6Loopback(),
		netip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
	}
	for _, address := range privateAddresses {
		if allowedPushAddress(address) {
			t.Fatalf("private push destination %s must be blocked", address)
		}
	}
}
