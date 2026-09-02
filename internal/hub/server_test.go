package hub

import (
	"context"
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

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

type staticCollector struct {
	snapshot model.SecuritySnapshot
}

func (collector staticCollector) Collect(context.Context) model.SecuritySnapshot {
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

func TestDeviceInventoryEndpoints(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	collect := httptest.NewRecorder()
	server.Handler().ServeHTTP(collect, httptest.NewRequest(http.MethodGet, "/api/security/snapshot", nil))
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
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/security/snapshot", nil))

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
	server.Handler().ServeHTTP(snapshot, httptest.NewRequest(http.MethodGet, "/api/security/snapshot", nil))
	if snapshot.Code != http.StatusOK || !strings.Contains(snapshot.Body.String(), `"deviceId":"demo-`) {
		t.Fatalf("demo snapshot was not synthetic: %d %s", snapshot.Code, snapshot.Body.String())
	}
}
