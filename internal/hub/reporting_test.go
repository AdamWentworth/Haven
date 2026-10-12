package hub

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

func TestReportingExpectationRequiresSessionOriginCSRFAndValidOwnerPolicy(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	hash := sha256.Sum256([]byte("synthetic enrollment token"))
	if err := store.CreateEnrollmentToken(ctx, hash[:], "Test laptop", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeEnrollmentToken(ctx, hash[:], storage.EnrollmentDevice{ID: "test-laptop", CertificateSerial: "test-serial", CertificateExpiresAt: now.Add(24 * time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	auth, err := authn.New(store, filepath.Join(t.TempDir(), "auth.key"), "http://localhost:5080")
	if err != nil {
		t.Fatal(err)
	}
	server.auth = auth
	session, err := auth.NewSession(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, origin  string
		authenticated, csrf bool
		want                int
	}{
		{"unauthenticated", `{"reportingExpectation":"intermittent"}`, "", false, false, 401},
		{"no origin", `{"reportingExpectation":"intermittent"}`, "", true, true, 403},
		{"wrong origin", `{"reportingExpectation":"intermittent"}`, "http://other.example", true, true, 403},
		{"no csrf", `{"reportingExpectation":"intermittent"}`, "http://localhost:5080", true, false, 403},
		{"invalid enum", `{"reportingExpectation":"disabled"}`, "http://localhost:5080", true, true, 400},
		{"unknown field", `{"reportingExpectation":"intermittent","status":"current"}`, "http://localhost:5080", true, true, 400},
		{"valid", `{"reportingExpectation":"intermittent"}`, "http://localhost:5080", true, true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/devices/test-laptop/reporting-expectation", strings.NewReader(tc.body))
			req.Header.Set("Origin", tc.origin)
			if tc.authenticated {
				req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: session.Token})
			}
			if tc.csrf {
				req.Header.Set("X-HAVEN-CSRF", session.CSRFToken)
				req.AddCookie(&http.Cookie{Name: authn.CSRFCookie, Value: session.CSRFToken})
			}
			res := httptest.NewRecorder()
			server.Handler().ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("HTTP %d: %s", res.Code, res.Body.String())
			}
			if tc.want == 200 && !strings.Contains(res.Body.String(), `"reportingExpectation":"intermittent"`) {
				t.Fatal("saved policy not returned")
			}
		})
	}
	detail, err := store.DeviceDetail(ctx, "test-laptop", now)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ReportingExpectation != "intermittent" || detail.Device.Status != "awaiting-first-report" {
		t.Fatal("policy forged report freshness")
	}
	events, err := store.ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Action == "device.reporting-expectation" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("rejected mutations changed audit or policy: %d", count)
	}
	server.demoMode = true
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/devices/test-laptop/reporting-expectation", strings.NewReader(`{"reportingExpectation":"always-on"}`)))
	if res.Code != 403 {
		t.Fatal("demo changed real policy")
	}
}

func TestStalePostureUsesObservationTimeAndReporterCannotChangeOwnerPolicy(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	ctx := context.Background()
	collected := time.Now().UTC().Add(-4 * 24 * time.Hour)
	hash := sha256.Sum256([]byte("synthetic older report token"))
	if err := store.CreateEnrollmentToken(ctx, hash[:], "Test laptop", collected.Add(time.Hour), collected); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeEnrollmentToken(ctx, hash[:], storage.EnrollmentDevice{ID: "test-laptop", CertificateSerial: "test-serial", CertificateExpiresAt: collected.Add(90 * 24 * time.Hour)}, collected); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReportingExpectation(ctx, "test-laptop", "intermittent", collected); err != nil {
		t.Fatal(err)
	}
	enabled, disabled := true, false
	signature := collected.Add(-time.Hour)
	envelope := model.ObservationEnvelope{SchemaVersion: model.ObservationSchemaVersion, ObservationID: "test-observation", DeviceID: "test-laptop", Sequence: 1, SentAt: collected,
		Snapshot: model.SecuritySnapshot{CollectedAt: collected, Device: model.DeviceSummary{DeviceID: "test-laptop", HostName: "test-laptop", OperatingSystem: "Microsoft Windows test"}, Defender: &model.DefenderStatus{AntivirusEnabled: &enabled, RealTimeProtectionEnabled: &enabled, TamperProtected: &enabled, SignatureUpdatedAt: &signature}, FirewallProfiles: []model.FirewallProfileStatus{{Name: "Private", Enabled: &disabled}}}}
	if err := store.AcceptObservation(ctx, "test-serial", envelope, collected); err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/devices/test-laptop", nil))
	if res.Code != 200 || strings.Contains(res.Body.String(), `"id":"defender-signatures"`) || !strings.Contains(res.Body.String(), `"reportingStatus":"away"`) {
		t.Fatalf("old evidence newly aged or policy overwritten: %s", res.Body.String())
	}
	alerts, err := server.alertProjector.Current(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) == 0 {
		t.Fatal("known disabled firewall must stay visible")
	}
	for _, alert := range alerts {
		if strings.Contains(alert.ID, "defender-signatures") || alert.Kind == "stale-agent" {
			t.Fatalf("manufactured alert from old evidence: %#v", alert)
		}
		if alert.Kind == "finding" && !strings.HasPrefix(alert.Evidence, "Last observed endpoint posture:") {
			t.Fatal("old finding presented as current evidence")
		}
	}
	envelope.Sequence = 2
	envelope.ObservationID = "test-fresh-observation"
	envelope.SentAt = time.Now().UTC()
	envelope.Snapshot.CollectedAt = envelope.SentAt
	if err := store.AcceptObservation(ctx, "test-serial", envelope, envelope.SentAt); err != nil {
		t.Fatal(err)
	}
	detail, err := store.DeviceDetail(ctx, "test-laptop", envelope.SentAt)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ReportingStatus != "current" || detail.Device.ReportingExpectation != "intermittent" {
		t.Fatal("fresh report failed to clear absence or changed owner policy")
	}
}
