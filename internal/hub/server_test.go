package hub

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

type staticCollector struct {
	snapshot model.SecuritySnapshot
}

func (collector staticCollector) Collect(context.Context) model.SecuritySnapshot {
	return collector.snapshot
}

type signalingCollector struct {
	snapshot model.SecuritySnapshot
	calls    chan struct{}
}

func (collector signalingCollector) Collect(context.Context) model.SecuritySnapshot {
	collector.calls <- struct{}{}
	return collector.snapshot
}

func testServer(t *testing.T) (*Server, *storage.Store) {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	webFiles := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>HAVEN</title>")},
	}
	snapshot := model.SecuritySnapshot{
		CollectedAt:      time.Now().UTC(),
		Device:           model.DeviceSummary{DeviceID: "test-device", HostName: "Test device", OperatingSystem: "Microsoft Windows test"},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(staticCollector{snapshot: snapshot}, store, logger, fs.FS(webFiles)), store
}

func TestHealthEndpointHasSecurityHeaders(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/health", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing security headers")
	}
	if !strings.Contains(response.Body.String(), `"agentIngestion":"mutual-tls"`) {
		t.Fatal("health response must disclose the agent trust mode")
	}
}

func TestAuthenticatedBoundaryAndAntiforgery(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	service, err := authn.New(store, filepath.Join(t.TempDir(), "auth.key"), "http://localhost:5080")
	if err != nil {
		t.Fatal(err)
	}
	server.auth = service

	unauthenticated := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected authentication boundary, got HTTP %d", unauthenticated.Code)
	}

	session, err := service.NewSession(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	authenticatedRequest.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: session.Token})
	authenticated := httptest.NewRecorder()
	server.Handler().ServeHTTP(authenticated, authenticatedRequest)
	if authenticated.Code != http.StatusOK {
		t.Fatalf("expected authenticated read, got HTTP %d: %s", authenticated.Code, authenticated.Body.String())
	}

	forbiddenRequest := httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil)
	forbiddenRequest.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: session.Token})
	forbidden := httptest.NewRecorder()
	server.Handler().ServeHTTP(forbidden, forbiddenRequest)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("expected origin or antiforgery rejection, got HTTP %d", forbidden.Code)
	}

	allowedRequest := httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil)
	allowedRequest.Header.Set("Origin", "http://localhost:5080")
	allowedRequest.Header.Set("X-HAVEN-CSRF", session.CSRFToken)
	allowedRequest.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: session.Token})
	allowedRequest.AddCookie(&http.Cookie{Name: authn.CSRFCookie, Value: session.CSRFToken})
	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected authenticated mutation, got HTTP %d: %s", allowed.Code, allowed.Body.String())
	}

	sensitiveRequest := httptest.NewRequest(http.MethodPost, "/api/devices/test-device/revoke", nil)
	sensitiveRequest.Header.Set("Origin", "http://localhost:5080")
	sensitiveRequest.Header.Set("X-HAVEN-CSRF", session.CSRFToken)
	sensitiveRequest.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: session.Token})
	sensitiveRequest.AddCookie(&http.Cookie{Name: authn.CSRFCookie, Value: session.CSRFToken})
	sensitive := httptest.NewRecorder()
	server.Handler().ServeHTTP(sensitive, sensitiveRequest)
	if sensitive.Code != http.StatusForbidden || !strings.Contains(sensitive.Body.String(), "passkey") {
		t.Fatalf("expected fresh passkey confirmation boundary, got HTTP %d: %s", sensitive.Code, sensitive.Body.String())
	}
}

func TestAuthenticationStatusAcceptsConfiguredPrivateOrigin(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	service, err := authn.New(store, filepath.Join(t.TempDir(), "auth.key"), "https://haven.home.arpa:8443")
	if err != nil {
		t.Fatal(err)
	}
	server.auth = service

	request := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	request.Host = "haven.home.arpa:8443"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected authentication status, got HTTP %d: %s", response.Code, response.Body.String())
	}
	var status authStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.UseConfiguredOrigin {
		t.Fatal("configured private origin must not be redirected")
	}

	request = httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	request.Host = "192.0.2.77:8443"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.UseConfiguredOrigin {
		t.Fatal("an alternate address must redirect to the configured private origin")
	}
}

func TestDeviceInventoryEndpoints(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	collect := httptest.NewRecorder()
	server.Handler().ServeHTTP(collect, httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil))
	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"id":"test-device"`) {
		t.Fatalf("unexpected device list: %d %s", list.Code, list.Body.String())
	}
	detail := httptest.NewRecorder()
	server.Handler().ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/devices/test-device", nil))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"hostName":"Test device"`) {
		t.Fatalf("unexpected device detail: %d %s", detail.Code, detail.Body.String())
	}
}

func TestSnapshotEndpointPersistsObservation(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security observations must not be cached")
	}
	stored, err := store.LatestSnapshot(context.Background(), "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Device.HostName != "Test device" {
		t.Fatalf("unexpected stored device: %q", stored.Device.HostName)
	}
	if len(stored.BaselineChecks) == 0 {
		t.Fatal("expected the hub to derive baseline checks before persistence")
	}
	latest := httptest.NewRecorder()
	server.Handler().ServeHTTP(latest, httptest.NewRequest(http.MethodGet, "/api/security/latest", nil))
	if latest.Code != http.StatusOK || !strings.Contains(latest.Body.String(), `"hostName":"Test device"`) {
		t.Fatalf("unexpected latest observation: %d %s", latest.Code, latest.Body.String())
	}
}

func TestSecurityEventEndpointReturnsFindingTransitions(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	disabled := false
	snapshot := server.collector.Collect(context.Background())
	snapshot.Defender = &model.DefenderStatus{
		AntivirusEnabled:          &disabled,
		RealTimeProtectionEnabled: &disabled,
	}
	server.collector = staticCollector{snapshot: snapshot}

	collect := httptest.NewRecorder()
	server.Handler().ServeHTTP(collect, httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil))
	events := httptest.NewRecorder()
	server.Handler().ServeHTTP(events, httptest.NewRequest(http.MethodGet, "/api/events?deviceId=test-device&limit=10", nil))

	if events.Code != http.StatusOK || !strings.Contains(events.Body.String(), `"kind":"opened"`) || !strings.Contains(events.Body.String(), `"findingId":"defender-disabled"`) {
		t.Fatalf("unexpected security events: %d %s", events.Code, events.Body.String())
	}
}

func TestContinuousMonitorCollectsImmediatelyAndOnInterval(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	calls := make(chan struct{}, 4)
	snapshot := server.collector.Collect(context.Background())
	server.collector = signalingCollector{snapshot: snapshot, calls: calls}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.RunMonitor(ctx, 10*time.Millisecond)

	for index := 0; index < 2; index++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("continuous monitor did not collect on schedule")
		}
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for server.monitorStatus().LastSuccessfulAt == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	status := server.monitorStatus()
	if !status.Enabled || status.IntervalSeconds != 0 || status.LastSuccessfulAt == nil {
		t.Fatalf("unexpected monitor status: %#v", status)
	}
}

func TestWebFallbackServesApplication(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/devices/example", nil))

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "HAVEN") {
		t.Fatalf("unexpected web response: %d %s", response.Code, response.Body.String())
	}
}

func TestDemoModeExcludesLiveDevices(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	ctx := context.Background()
	if err := store.SaveSnapshot(ctx, server.collector.Collect(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedSyntheticDevices(ctx, 2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	normalList := httptest.NewRecorder()
	server.Handler().ServeHTTP(normalList, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if normalList.Code != http.StatusOK || !strings.Contains(normalList.Body.String(), `"id":"test-device"`) || strings.Contains(normalList.Body.String(), `"trustState":"synthetic"`) {
		t.Fatalf("normal inventory exposed synthetic fixtures: %d %s", normalList.Code, normalList.Body.String())
	}

	server.demoMode = true

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), `"id":"test-device"`) || !strings.Contains(list.Body.String(), `"trustState":"synthetic"`) {
		t.Fatalf("demo inventory leaked a live device: %d %s", list.Code, list.Body.String())
	}
	liveDetail := httptest.NewRecorder()
	server.Handler().ServeHTTP(liveDetail, httptest.NewRequest(http.MethodGet, "/api/devices/test-device", nil))
	if liveDetail.Code != http.StatusNotFound {
		t.Fatalf("demo mode exposed live device detail with HTTP %d", liveDetail.Code)
	}
	snapshot := httptest.NewRecorder()
	server.Handler().ServeHTTP(snapshot, httptest.NewRequest(http.MethodPost, "/api/security/snapshot", nil))
	if snapshot.Code != http.StatusOK || !strings.Contains(snapshot.Body.String(), `"deviceId":"demo-`) {
		t.Fatalf("demo snapshot was not synthetic: %d %s", snapshot.Code, snapshot.Body.String())
	}
}
