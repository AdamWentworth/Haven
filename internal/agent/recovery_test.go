package agent_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/agent"
	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/hub"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/AdamWentworth/haven/internal/trust"
)

// TestSyntheticContinuityRestoreAndCleanReinitialization exercises the two
// supported recovery paths entirely inside temporary directories. It must
// never depend on, inspect, or modify a real HAVEN state directory.
func TestSyntheticContinuityRestoreAndCleanReinitialization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	originalState := t.TempDir()
	originalStore := openRecoveryStore(t, originalState)
	originalPKI := ensureRecoveryPKI(t, originalState, now)
	authKeyPath := filepath.Join(originalState, "auth.key")
	if _, err := authn.New(originalStore, authKeyPath, "https://haven.example.invalid"); err != nil {
		t.Fatalf("initialize original authentication key: %v", err)
	}
	assertBootstrapAvailable(t, ctx, originalStore, now)

	originalServer := startRecoveryAgentServer(t, originalStore, originalPKI)
	originalAgentState := t.TempDir()
	originalConfig := enrollRecoveryAgent(t, ctx, originalStore, originalPKI, originalServer.URL, originalAgentState, "Synthetic workstation", now)
	originalClient, err := agent.Load(originalAgentState)
	if err != nil {
		t.Fatalf("load original synthetic agent: %v", err)
	}
	if _, err := originalClient.Report(ctx, recoverySnapshot(now), "systemd-user"); err != nil {
		t.Fatalf("submit original synthetic observation: %v", err)
	}

	backupState := t.TempDir()
	if err := originalStore.Backup(ctx, filepath.Join(backupState, "haven.db")); err != nil {
		t.Fatalf("create consistent SQLite backup: %v", err)
	}
	copyRecoveryTree(t, filepath.Join(originalState, "pki"), filepath.Join(backupState, "pki"))
	copyRecoveryFile(t, authKeyPath, filepath.Join(backupState, "auth.key"))
	originalServer.Close()
	if err := originalStore.Close(); err != nil {
		t.Fatalf("close original store: %v", err)
	}

	restoredStore := openRecoveryStore(t, backupState)
	defer restoredStore.Close()
	restoredPKI := ensureRecoveryPKI(t, backupState, now.Add(time.Hour))
	if string(restoredPKI.CACertificatePEM) != string(originalPKI.CACertificatePEM) {
		t.Fatal("continuity restore generated a different agent trust root")
	}
	if _, err := authn.New(restoredStore, filepath.Join(backupState, "auth.key"), "https://haven.example.invalid"); err != nil {
		t.Fatalf("load restored authentication key: %v", err)
	}
	restoredServer := startRecoveryAgentServer(t, restoredStore, restoredPKI)
	defer restoredServer.Close()
	updateRecoveryAgentHubURL(t, originalAgentState, restoredServer.URL)
	continuityClient, err := agent.Load(originalAgentState)
	if err != nil {
		t.Fatalf("load continuity agent identity: %v", err)
	}
	if _, err := continuityClient.Report(ctx, recoverySnapshot(now.Add(10*time.Second)), "systemd-user"); err != nil {
		t.Fatalf("restored trust state rejected the existing enrolled identity: %v", err)
	}
	originalDetail, err := restoredStore.DeviceDetail(ctx, originalConfig.DeviceID, now.Add(10*time.Second))
	if err != nil || originalDetail.Snapshot == nil {
		t.Fatalf("restored database did not preserve the original enrolled observation: %#v, %v", originalDetail, err)
	}

	cleanState := t.TempDir()
	cleanStore := openRecoveryStore(t, cleanState)
	defer cleanStore.Close()
	cleanPKI := ensureRecoveryPKI(t, cleanState, now.Add(20*time.Second))
	if string(cleanPKI.CACertificatePEM) == string(originalPKI.CACertificatePEM) {
		t.Fatal("clean initialization unexpectedly reused the previous trust root")
	}
	if _, err := authn.New(cleanStore, filepath.Join(cleanState, "auth.key"), "https://haven.example.invalid"); err != nil {
		t.Fatalf("initialize clean authentication key: %v", err)
	}
	assertBootstrapAvailable(t, ctx, cleanStore, now.Add(20*time.Second))
	devices, err := cleanStore.ListDevices(ctx, now.Add(20*time.Second))
	if err != nil {
		t.Fatalf("list clean device inventory: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("clean initialization inherited devices: %#v", devices)
	}
	cleanServer := startRecoveryAgentServer(t, cleanStore, cleanPKI)
	defer cleanServer.Close()
	cleanAgentState := t.TempDir()
	cleanConfig := enrollRecoveryAgent(t, ctx, cleanStore, cleanPKI, cleanServer.URL, cleanAgentState, "Reinitialized synthetic workstation", now.Add(20*time.Second))
	cleanClient, err := agent.Load(cleanAgentState)
	if err != nil {
		t.Fatalf("load clean synthetic agent: %v", err)
	}
	if _, err := cleanClient.Report(ctx, recoverySnapshot(now.Add(20*time.Second)), "systemd-user"); err != nil {
		t.Fatalf("submit clean synthetic observation: %v", err)
	}
	cleanDetail, err := cleanStore.DeviceDetail(ctx, cleanConfig.DeviceID, now.Add(20*time.Second))
	if err != nil || cleanDetail.Snapshot == nil || cleanDetail.Device.Status != "current" {
		t.Fatalf("clean re-enrollment did not produce a current device: %#v, %v", cleanDetail, err)
	}
}

func openRecoveryStore(t *testing.T, directory string) *storage.Store {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(directory, "haven.db"))
	if err != nil {
		t.Fatalf("open synthetic recovery store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func updateRecoveryAgentHubURL(t *testing.T, directory, hubURL string) {
	t.Helper()
	path := filepath.Join(directory, "config.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read synthetic agent configuration: %v", err)
	}
	var config agent.Config
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatalf("decode synthetic agent configuration: %v", err)
	}
	config.HubURL = hubURL
	payload, err = json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("encode synthetic agent configuration: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("update synthetic agent hub address: %v", err)
	}
}

func ensureRecoveryPKI(t *testing.T, directory string, now time.Time) *trust.HubPKI {
	t.Helper()
	pki, err := trust.EnsureHubPKI(filepath.Join(directory, "pki"), now)
	if err != nil {
		t.Fatalf("initialize synthetic recovery PKI: %v", err)
	}
	return pki
}

func startRecoveryAgentServer(t *testing.T, store *storage.Store, pki *trust.HubPKI) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewUnstartedServer(hub.NewAgentServer(store, pki, logger).Handler())
	server.TLS = trust.ServerTLSConfig(pki)
	server.StartTLS()
	return server
}

func enrollRecoveryAgent(t *testing.T, ctx context.Context, store *storage.Store, pki *trust.HubPKI, hubURL, agentState, label string, now time.Time) agent.Config {
	t.Helper()
	token, tokenHash, err := trust.NewEnrollmentToken()
	if err != nil {
		t.Fatalf("create synthetic enrollment token: %v", err)
	}
	if err := store.CreateEnrollmentToken(ctx, tokenHash, label, now.Add(10*time.Minute), now); err != nil {
		t.Fatalf("store synthetic enrollment token: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "agent-ca.crt")
	if err := os.WriteFile(caPath, pki.CACertificatePEM, 0o600); err != nil {
		t.Fatalf("write synthetic agent CA: %v", err)
	}
	config, err := agent.Enroll(ctx, agentState, hubURL, label, token, caPath)
	if err != nil {
		t.Fatalf("enroll synthetic agent: %v", err)
	}
	return config
}

func assertBootstrapAvailable(t *testing.T, ctx context.Context, store *storage.Store, now time.Time) {
	t.Helper()
	code, err := authn.CreateBootstrap(ctx, store, 10*time.Minute, now)
	if err != nil {
		t.Fatalf("create synthetic owner bootstrap: %v", err)
	}
	digest := sha256.Sum256([]byte(code))
	valid, err := store.BootstrapValid(ctx, digest[:], now)
	if err != nil || !valid {
		t.Fatalf("synthetic owner bootstrap was not valid: %v", err)
	}
}

func recoverySnapshot(collectedAt time.Time) model.SecuritySnapshot {
	return model.SecuritySnapshot{
		CollectedAt: collectedAt,
		Device: model.DeviceSummary{
			HostName:        "synthetic-host",
			OperatingSystem: "Synthetic Linux",
			Architecture:    "amd64",
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
}

func copyRecoveryTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		copyRecoveryFile(t, path, target)
		return nil
	})
	if err != nil {
		t.Fatalf("copy synthetic recovery tree: %v", err)
	}
}

func copyRecoveryFile(t *testing.T, source, destination string) {
	t.Helper()
	payload, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read synthetic recovery file: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatalf("create synthetic recovery directory: %v", err)
	}
	if err := os.WriteFile(destination, payload, 0o600); err != nil {
		t.Fatalf("write synthetic recovery file: %v", err)
	}
}
