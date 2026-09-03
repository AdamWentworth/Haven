package notification

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
	webpush "github.com/SherClockHolmes/webpush-go"
)

const (
	subscriptionAAD = "HAVEN Web Push subscription v1"
	maximumAttempts = 6
)

type Subscription struct {
	Endpoint       string           `json:"endpoint"`
	ExpirationTime *int64           `json:"expirationTime"`
	Keys           SubscriptionKeys `json:"keys"`
}

type SubscriptionKeys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

type Status struct {
	Available        bool                             `json:"available"`
	VAPIDPublicKey   string                           `json:"vapidPublicKey"`
	Destinations     []storage.PushSubscriptionRecord `json:"destinations"`
	PendingCount     int                              `json:"pendingCount"`
	FailedCount      int                              `json:"failedCount"`
	LastSuccessAt    *time.Time                       `json:"lastSuccessAt"`
	LastFailureAt    *time.Time                       `json:"lastFailureAt"`
	EvaluationPeriod int64                            `json:"evaluationPeriodSeconds"`
}

type DeliveryOptions struct {
	Topic   string
	Urgency string
}

type Sender interface {
	Send(context.Context, Subscription, []byte, DeliveryOptions) (int, error)
}

type Option func(*Service)

func WithSender(sender Sender) Option {
	return func(service *Service) { service.sender = sender }
}

type Service struct {
	store        *storage.Store
	logger       *slog.Logger
	key          []byte
	vapidPublic  string
	vapidPrivate string
	subscriber   string
	sender       Sender
	mutex        sync.Mutex
}

func New(store *storage.Store, stateDirectory, subscriber string, logger *slog.Logger, options ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("notification storage is required")
	}
	parsed, err := url.Parse(subscriber)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("notification subscriber must be an HTTPS origin")
	}
	key, err := loadOrCreateKey(filepath.Join(stateDirectory, "push-subscription.key"))
	if err != nil {
		return nil, err
	}
	privateKey, publicKey, err := loadOrCreateVAPIDKeys(filepath.Join(stateDirectory, "vapid-keys.json"))
	if err != nil {
		return nil, err
	}
	service := &Service{store: store, logger: logger, key: key, vapidPublic: publicKey, vapidPrivate: privateKey, subscriber: subscriber}
	for _, option := range options {
		option(service)
	}
	if service.sender == nil {
		service.sender = &webPushSender{
			subscriber: subscriber,
			publicKey:  publicKey,
			privateKey: privateKey,
			client:     safeHTTPClient(),
		}
	}
	return service, nil
}

func (service *Service) PublicKey() string { return service.vapidPublic }

func (service *Service) Status(ctx context.Context, evaluationPeriod time.Duration) (Status, error) {
	destinations, err := service.store.ListPushSubscriptions(ctx)
	if err != nil {
		return Status{}, err
	}
	delivery, err := service.store.PushDeliveryStatus(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Available:        true,
		VAPIDPublicKey:   service.vapidPublic,
		Destinations:     destinations,
		PendingCount:     delivery.PendingCount,
		FailedCount:      delivery.FailedCount,
		LastSuccessAt:    delivery.LastSuccessAt,
		LastFailureAt:    delivery.LastFailureAt,
		EvaluationPeriod: int64(evaluationPeriod / time.Second),
	}, nil
}

func (service *Service) Subscribe(ctx context.Context, input Subscription, label string, currentAlerts []model.Alert, now time.Time) (storage.PushSubscriptionRecord, bool, error) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	input, err := validateSubscription(input, now)
	if err != nil {
		return storage.PushSubscriptionRecord{}, false, err
	}
	plain, err := json.Marshal(input)
	if err != nil {
		return storage.PushSubscriptionRecord{}, false, err
	}
	encrypted, err := encrypt(service.key, plain)
	if err != nil {
		return storage.PushSubscriptionRecord{}, false, err
	}
	digest := sha256.Sum256([]byte(input.Endpoint))
	record, created, err := service.store.UpsertPushSubscription(ctx, digest[:], encrypted, normalizeLabel(label), now)
	if err != nil {
		return storage.PushSubscriptionRecord{}, false, err
	}
	if created {
		if err := service.store.BaselinePushDeliveries(ctx, record.ID, currentAlerts, now); err != nil {
			_, _ = service.store.DeletePushSubscription(ctx, digest[:])
			return storage.PushSubscriptionRecord{}, false, err
		}
	}
	return record, created, nil
}

func (service *Service) Unsubscribe(ctx context.Context, endpoint string) (bool, error) {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	parsed, err := validateEndpoint(endpoint)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(parsed.String()))
	return service.store.DeletePushSubscription(ctx, digest[:])
}

// Reconcile persists per-destination delivery state before attempting Web
// Push. A restart therefore cannot turn the one-notification-per-instance rule
// into repeated noise, and resolved alerts cancel queued retries.
func (service *Service) Reconcile(ctx context.Context, alerts []model.Alert, now time.Time) error {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	candidates, err := service.store.PreparePushDeliveries(ctx, alerts, now)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := service.deliver(ctx, candidate, now.UTC()); err != nil {
			service.logger.Warn("background alert delivery could not be recorded", "error", err)
		}
	}
	return nil
}

func (service *Service) deliver(ctx context.Context, candidate storage.PushDeliveryCandidate, now time.Time) error {
	subscription, err := service.decryptSubscription(candidate.Subscription.EncryptedSubscription)
	if err != nil {
		return service.store.RecordPushDelivery(ctx, candidate.Alert.InstanceID, candidate.Subscription.ID, "failed", "stored-subscription-unreadable", now, now)
	}
	payload, err := notificationPayload(candidate.Alert)
	if err != nil {
		return err
	}
	deliveryContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	statusCode, sendErr := service.sender.Send(deliveryContext, subscription, payload, DeliveryOptions{Topic: topicForAlert(candidate.Alert.ID), Urgency: urgency(candidate.Alert.Severity)})
	cancel()
	if sendErr == nil && statusCode >= 200 && statusCode < 300 {
		return service.store.RecordPushDelivery(ctx, candidate.Alert.InstanceID, candidate.Subscription.ID, "delivered", "push-service-accepted", now, now)
	}
	if statusCode == http.StatusNotFound || statusCode == http.StatusGone {
		if err := service.store.DeletePushSubscriptionByID(ctx, candidate.Subscription.ID); err != nil {
			return err
		}
		_ = service.store.AppendAudit(ctx, storage.AuditEvent{Actor: "system", Action: "notification.destination.expired", Target: "owner", Outcome: "succeeded", Detail: "A browser push destination expired and was removed.", OccurredAt: now})
		return nil
	}
	attempt := candidate.AttemptCount + 1
	if attempt >= maximumAttempts || (statusCode >= 400 && statusCode < 500 && statusCode != http.StatusTooManyRequests) {
		return service.store.RecordPushDelivery(ctx, candidate.Alert.InstanceID, candidate.Subscription.ID, "failed", deliveryResult(statusCode, sendErr), now, now)
	}
	return service.store.RecordPushDelivery(ctx, candidate.Alert.InstanceID, candidate.Subscription.ID, "retry", deliveryResult(statusCode, sendErr), now, now.Add(retryDelay(attempt)))
}

func (service *Service) decryptSubscription(value []byte) (Subscription, error) {
	plain, err := decrypt(service.key, value)
	if err != nil {
		return Subscription{}, err
	}
	var subscription Subscription
	if err := json.Unmarshal(plain, &subscription); err != nil {
		return Subscription{}, err
	}
	return validateSubscription(subscription, time.Now().UTC())
}

type webPushSender struct {
	subscriber string
	publicKey  string
	privateKey string
	client     *http.Client
}

func (sender *webPushSender) Send(ctx context.Context, subscription Subscription, payload []byte, options DeliveryOptions) (int, error) {
	response, err := webpush.SendNotificationWithContext(ctx, payload, &webpush.Subscription{
		Endpoint: subscription.Endpoint,
		Keys:     webpush.Keys{Auth: subscription.Keys.Auth, P256dh: subscription.Keys.P256dh},
	}, &webpush.Options{
		Subscriber:      sender.subscriber,
		VAPIDPublicKey:  sender.publicKey,
		VAPIDPrivateKey: sender.privateKey,
		TTL:             3600,
		Topic:           options.Topic,
		Urgency:         webpush.Urgency(options.Urgency),
		HTTPClient:      sender.client,
	})
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}

func validateSubscription(input Subscription, now time.Time) (Subscription, error) {
	parsed, err := validateEndpoint(input.Endpoint)
	if err != nil {
		return Subscription{}, err
	}
	input.Endpoint = parsed.String()
	if input.ExpirationTime != nil && *input.ExpirationTime > 0 && time.UnixMilli(*input.ExpirationTime).Before(now.Add(-time.Minute)) {
		return Subscription{}, errors.New("push subscription has expired")
	}
	auth, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(input.Keys.Auth, "="))
	if err != nil || len(auth) != 16 {
		return Subscription{}, errors.New("push subscription auth key is invalid")
	}
	public, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(input.Keys.P256dh, "="))
	if err != nil || len(public) != 65 || public[0] != 4 {
		return Subscription{}, errors.New("push subscription public key is invalid")
	}
	return input, nil
}

func validateEndpoint(value string) (*url.URL, error) {
	if len(value) == 0 || len(value) > 2048 {
		return nil, errors.New("push endpoint is invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("push endpoint must be an HTTPS URL")
	}
	if net.ParseIP(parsed.Hostname()) != nil || (parsed.Port() != "" && parsed.Port() != "443") {
		return nil, errors.New("push endpoint must use a public service hostname on HTTPS")
	}
	return parsed, nil
}

func notificationPayload(alert model.Alert) ([]byte, error) {
	return json.Marshal(map[string]string{
		"title": "HAVEN needs attention",
		"body":  fmt.Sprintf("%s has a %s security alert. Open HAVEN to review.", alert.DeviceName, alert.Severity),
		"tag":   "haven-" + topicForAlert(alert.ID),
		"url":   "/",
	})
}

func topicForAlert(alertID string) string {
	digest := sha256.Sum256([]byte(alertID))
	return base64.RawURLEncoding.EncodeToString(digest[:18])
}

func urgency(severity string) string {
	if severity == "high" {
		return "high"
	}
	return "normal"
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		attempt = 6
	}
	return time.Minute * time.Duration(1<<(attempt-1))
}

func deliveryResult(statusCode int, sendErr error) string {
	if sendErr != nil {
		return "network-or-encryption-error"
	}
	if statusCode == http.StatusTooManyRequests {
		return "push-service-rate-limited"
	}
	if statusCode >= 500 {
		return "push-service-unavailable"
	}
	return "push-service-rejected"
}

func normalizeLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Browser"
	}
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte(subscriptionAAD)), nil
}

func decrypt(key, encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < gcm.NonceSize() {
		return nil, errors.New("stored push subscription is invalid")
	}
	plain, err := gcm.Open(nil, encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():], []byte(subscriptionAAD))
	if err != nil {
		return nil, errors.New("stored push subscription could not be decrypted")
	}
	return plain, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if value, err := os.ReadFile(path); err == nil {
		if len(value) != 32 {
			return nil, errors.New("HAVEN push-subscription encryption key has an invalid length")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read push-subscription encryption key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ReadFile(path)
		}
		return nil, fmt.Errorf("create push-subscription encryption key: %w", err)
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}

func loadOrCreateVAPIDKeys(path string) (string, string, error) {
	type keyFile struct {
		Private string `json:"private"`
		Public  string `json:"public"`
	}
	if value, err := os.ReadFile(path); err == nil {
		var keys keyFile
		if json.Unmarshal(value, &keys) != nil || keys.Private == "" || keys.Public == "" {
			return "", "", errors.New("HAVEN VAPID key file is invalid")
		}
		return keys.Private, keys.Public, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("read VAPID keys: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return "", "", err
	}
	encoded, err := json.Marshal(keyFile{Private: privateKey, Public: publicKey})
	if err != nil {
		return "", "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateVAPIDKeys(path)
		}
		return "", "", fmt.Errorf("create VAPID keys: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return "", "", err
	}
	if err := file.Close(); err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

func safeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("push destination address is invalid")
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, errors.New("push destination could not be resolved")
			}
			for _, address := range addresses {
				if !allowedPushAddress(address.Unmap()) {
					return nil, errors.New("push destination resolved to a non-public address")
				}
			}
			if len(addresses) == 0 {
				return nil, errors.New("push destination had no addresses")
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("push service redirects are not followed")
		},
	}
}

func allowedPushAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
}
