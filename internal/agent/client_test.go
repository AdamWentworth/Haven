package agent_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/agent"
	"github.com/AdamWentworth/haven/internal/hub"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/AdamWentworth/haven/internal/trust"
)

func TestEnrollmentAndMutualTLSReporting(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(directory, "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pki, err := trust.EnsureHubPKI(filepath.Join(directory, "pki"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewUnstartedServer(hub.NewAgentServer(store, pki, logger).Handler())
	server.TLS = trust.ServerTLSConfig(pki)
	server.StartTLS()
	defer server.Close()

	token, tokenHash, err := trust.NewEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.CreateEnrollmentToken(ctx, tokenHash, "Test laptop", now.Add(10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "trusted-ca.crt")
	if err := os.WriteFile(caPath, pki.CACertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	agentDirectory := filepath.Join(directory, "agent")
	config, err := agent.Enroll(ctx, agentDirectory, server.URL, "Test laptop", token, caPath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.Load(agentDirectory)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.SecuritySnapshot{CollectedAt: time.Now().UTC(), Device: model.DeviceSummary{HostName: "test-laptop", OperatingSystem: "Test OS", Architecture: "amd64"}, FirewallProfiles: []model.FirewallProfileStatus{}, Connections: []model.NetworkConnection{}, Notices: []model.CollectorNotice{}}
	if _, err := client.Report(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	detail, err := store.DeviceDetail(ctx, config.DeviceID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if detail.Snapshot == nil || detail.Device.Status != "current" || detail.Snapshot.Device.DeviceID != config.DeviceID {
		t.Fatalf("unexpected enrolled device state: %#v", detail)
	}
	if err := store.RevokeDevice(ctx, config.DeviceID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Report(ctx, snapshot); err == nil {
		t.Fatal("expected a revoked certificate to be rejected")
	}
}
