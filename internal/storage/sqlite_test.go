package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

func TestStoreSavesLoadsAndExpiresSnapshots(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	collectedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	snapshot := model.SecuritySnapshot{
		CollectedAt: collectedAt,
		Device: model.DeviceSummary{
			DeviceID:        "test-device-id",
			HostName:        "test-device",
			OperatingSystem: "Test OS",
			Architecture:    "test-architecture",
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections: []model.NetworkConnection{{
			Protocol: "TCP",
			State:    "Established",
		}},
		Notices: []model.CollectorNotice{},
	}

	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LatestSnapshot(ctx, "test-device-id")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Device.HostName != "test-device" || !loaded.CollectedAt.Equal(collectedAt) {
		t.Fatalf("unexpected stored snapshot: %#v", loaded)
	}
	if len(loaded.Connections) != 0 {
		t.Fatal("connection metadata must remain live-only")
	}

	deleted, err := store.DeleteBefore(ctx, collectedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("expected one deleted observation, got %d", deleted)
	}
	_, err = store.LatestSnapshot(ctx, "test-device-id")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected the observation to be absent, got %v", err)
	}
}

func TestEnrollmentReplayRevocationAndBackup(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := Open(ctx, filepath.Join(directory, "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, time.September, 1, 15, 0, 0, 0, time.UTC)
	tokenHash := make([]byte, 32)
	tokenHash[0] = 1
	if err := store.CreateEnrollmentToken(ctx, tokenHash, "Test laptop", now.Add(10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	device := EnrollmentDevice{ID: "dev_test", DisplayName: "Test laptop", CertificateSerial: "abc123", CertificateExpiresAt: now.Add(90 * 24 * time.Hour)}
	if err := store.ConsumeEnrollmentToken(ctx, tokenHash, device, now); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeEnrollmentToken(ctx, tokenHash, device, now); !errors.Is(err, ErrEnrollmentInvalid) {
		t.Fatalf("expected one-time token rejection, got %v", err)
	}

	snapshot := model.SecuritySnapshot{CollectedAt: now, Device: model.DeviceSummary{HostName: "test-laptop", OperatingSystem: "Test OS", Architecture: "amd64"}, FirewallProfiles: []model.FirewallProfileStatus{}, Connections: []model.NetworkConnection{}, Notices: []model.CollectorNotice{}}
	envelope := model.ObservationEnvelope{ObservationID: "obs_test", DeviceID: device.ID, Sequence: 1, Snapshot: snapshot}
	if err := store.AcceptObservation(ctx, device.CertificateSerial, envelope, now); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptObservation(ctx, device.CertificateSerial, envelope, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	if err := store.RevokeDevice(ctx, device.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	envelope.Sequence = 2
	envelope.ObservationID = "obs_second"
	if err := store.AcceptObservation(ctx, device.CertificateSerial, envelope, now.Add(2*time.Minute)); !errors.Is(err, ErrRevokedDevice) {
		t.Fatalf("expected revoked device rejection, got %v", err)
	}

	backupPath := filepath.Join(directory, "backups", "haven.db")
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backup, err := Open(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	detail, err := backup.DeviceDetail(ctx, device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.Status != "revoked" || detail.Snapshot == nil {
		t.Fatalf("backup did not preserve device state: %#v", detail)
	}
}
