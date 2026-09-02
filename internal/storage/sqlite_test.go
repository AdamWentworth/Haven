package storage

import (
	"context"
	"database/sql"
	"encoding/json"
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
	if len(loaded.Connections) != 1 {
		t.Fatal("the current in-memory observation should retain live connection metadata")
	}
	var historicalPayloadJSON []byte
	if err := store.database.QueryRowContext(ctx, `SELECT payload_json FROM device_observations WHERE device_id = ? ORDER BY collected_at DESC LIMIT 1`, "test-device-id").Scan(&historicalPayloadJSON); err != nil {
		t.Fatal(err)
	}
	var historical model.SecuritySnapshot
	if err := json.Unmarshal(historicalPayloadJSON, &historical); err != nil {
		t.Fatal(err)
	}
	if len(historical.Connections) != 0 {
		t.Fatal("connection metadata must never be persisted")
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

func TestLocalSnapshotsTreatHostnameCaseAsOneDevice(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	firstCollectedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	first := model.SecuritySnapshot{
		CollectedAt: firstCollectedAt,
		Device: model.DeviceSummary{
			HostName:        "adam-pc",
			OperatingSystem: "windows",
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
	if err := store.SaveSnapshot(ctx, first); err != nil {
		t.Fatal(err)
	}

	second := first
	second.CollectedAt = firstCollectedAt.Add(time.Minute)
	second.Device.HostName = "ADAM-PC"
	second.Device.OperatingSystem = "Microsoft Windows 10 Pro"
	if err := store.SaveSnapshot(ctx, second); err != nil {
		t.Fatal(err)
	}

	devices, err := store.ListDevices(ctx, firstCollectedAt.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected one case-insensitive local device, got %#v", devices)
	}
	if devices[0].HostName != "ADAM-PC" || devices[0].OperatingSystem != "Microsoft Windows 10 Pro" {
		t.Fatalf("expected the latest device metadata, got %#v", devices[0])
	}
	if localDeviceID("adam-pc") != localDeviceID(" ADAM-PC ") {
		t.Fatal("local device identity must ignore hostname case and surrounding whitespace")
	}
}

func TestDeleteLocalDevicesPreservesEnrolledDevices(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	snapshot := model.SecuritySnapshot{
		CollectedAt:      now,
		Device:           model.DeviceSummary{HostName: "container-host", OperatingSystem: "linux"},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.ExecContext(ctx, `INSERT INTO devices (id, display_name, trust_state, enrolled_at) VALUES ('enrolled-test', 'Endpoint', 'enrolled', ?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	deleted, err := store.DeleteLocalDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("expected one local device deletion, got %d", deleted)
	}
	devices, err := store.ListDevices(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != "enrolled-test" {
		t.Fatalf("expected enrolled device to remain, got %#v", devices)
	}
}

func TestMigrationRemovesOlderCaseOnlyLocalDuplicate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "haven.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	older := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	newer := time.Date(2026, time.September, 1, 13, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	_, err = store.database.ExecContext(ctx,
		`INSERT INTO devices (
			id, display_name, host_name, operating_system, architecture,
			trust_state, enrolled_at, last_seen_at, last_collected_at
		 ) VALUES
			('local_old', 'adam-pc', 'adam-pc', 'windows', 'amd64', 'local', ?, ?, ?),
			('local_new', 'ADAM-PC', 'ADAM-PC', 'Microsoft Windows 10 Pro', 'amd64', 'local', ?, ?, ?)`,
		older, older, older,
		older, newer, newer,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.database.ExecContext(ctx,
		`INSERT INTO device_observations (
			observation_id, device_id, collected_at, received_at, payload_json
		 ) VALUES ('old_observation', 'local_old', ?, ?, '{}')`,
		older, older,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	devices, err := store.ListDevices(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != "local_new" {
		t.Fatalf("expected the newest local device to survive migration, got %#v", devices)
	}
	var staleObservations int
	if err := store.database.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM device_observations WHERE device_id = 'local_old'`,
	).Scan(&staleObservations); err != nil {
		t.Fatal(err)
	}
	if staleObservations != 0 {
		t.Fatalf("expected stale observations to be removed, got %d", staleObservations)
	}
}

func TestFindingEventsRecordOnlyOpenedAndResolvedTransitions(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	startedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	snapshot := model.SecuritySnapshot{
		CollectedAt: startedAt,
		Device: model.DeviceSummary{
			DeviceID:        "local_event_test",
			HostName:        "event-test",
			OperatingSystem: "Microsoft Windows 10 Pro",
		},
		Findings: []model.SecurityFinding{{
			ID:             "defender-disabled",
			Category:       "Protection",
			Title:          "Defender protection is incomplete",
			Severity:       "high",
			Summary:        "Real-time monitoring is disabled.",
			Recommendation: "Restore protection.",
		}},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}

	snapshot.CollectedAt = startedAt.Add(time.Minute)
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListSecurityEvents(ctx, snapshot.Device.DeviceID, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "opened" || events[0].Severity != "high" {
		t.Fatalf("expected one opened event, got %#v", events)
	}

	snapshot.CollectedAt = startedAt.Add(2 * time.Minute)
	snapshot.Findings = []model.SecurityFinding{}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	events, err = store.ListSecurityEvents(ctx, snapshot.Device.DeviceID, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Kind != "resolved" || events[1].Kind != "opened" {
		t.Fatalf("expected resolved and opened transitions, got %#v", events)
	}
}

func TestServiceInventoryGroupsListenersAndTracksExpectations(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	startedAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	snapshot := model.SecuritySnapshot{
		CollectedAt: startedAt,
		Device:      model.DeviceSummary{DeviceID: "service-test", HostName: "service-test", OperatingSystem: "Ubuntu"},
		Connections: []model.NetworkConnection{
			{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 443, State: "Listen"},
			{Protocol: "TCP", LocalAddress: "::", LocalPort: 443, State: "Listen"},
			{Protocol: "UDP", LocalAddress: "fc00::77", LocalPort: 51822, State: "Bound"},
			{Protocol: "TCP", LocalAddress: "192.0.2.77", LocalPort: 22, State: "Established"},
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Notices:          []model.CollectorNotice{},
	}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	listeners, err := store.ListObservedListeners(ctx, snapshot.Device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 2 || listeners[0].Port != 443 || listeners[0].BindScope != BindScopeWildcard || listeners[1].Port != 51822 || listeners[1].BindScope != BindScopePrivate {
		t.Fatalf("expected dual-stack sockets to form two privacy-bounded listeners, got %#v", listeners)
	}

	expected, err := store.UpsertExpectedService(ctx, ExpectedService{DeviceID: snapshot.Device.DeviceID, Label: "HTTPS proxy", Protocol: "tcp", Port: 443, BindScope: BindScopeWildcard, UpdatedAt: startedAt})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpsertExpectedService(ctx, ExpectedService{DeviceID: snapshot.Device.DeviceID, Label: "Web proxy", Protocol: "TCP", Port: 443, BindScope: BindScopeWildcard, UpdatedAt: startedAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != expected.ID || updated.Label != "Web proxy" {
		t.Fatalf("expected the same endpoint classification to update in place, got %#v", updated)
	}

	snapshot.CollectedAt = startedAt.Add(15 * time.Minute)
	snapshot.Connections = []model.NetworkConnection{}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	listeners, err = store.ListObservedListeners(ctx, snapshot.Device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if listeners[0].Present || listeners[1].Present {
		t.Fatalf("listeners missing from the latest report must not remain present: %#v", listeners)
	}

	snapshot.CollectedAt = startedAt.Add(30 * time.Minute)
	snapshot.Connections = []model.NetworkConnection{{Protocol: "TCP", LocalAddress: "::", LocalPort: 443, State: "Listen"}}
	if err := store.SaveSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	listeners, err = store.ListObservedListeners(ctx, snapshot.Device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !listeners[0].Present || !listeners[0].FirstSeen.Equal(startedAt) || !listeners[0].AppearedAt.Equal(snapshot.CollectedAt) {
		t.Fatalf("expected a reappearing listener to retain first seen and reset appearance time, got %#v", listeners[0])
	}

	if err := store.RemoveExpectedService(ctx, snapshot.Device.DeviceID, expected.ID); err != nil {
		t.Fatal(err)
	}
	services, err := store.ListExpectedServices(ctx, snapshot.Device.DeviceID)
	if err != nil || len(services) != 0 {
		t.Fatalf("expected the service classification to be removed, got %#v, %v", services, err)
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

	snapshot := model.SecuritySnapshot{CollectedAt: now, Device: model.DeviceSummary{HostName: "test-laptop", OperatingSystem: "Test OS", Architecture: "amd64"}, FirewallProfiles: []model.FirewallProfileStatus{}, Connections: []model.NetworkConnection{{Protocol: "TCP", State: "Listen", LocalPort: 443}}, Notices: []model.CollectorNotice{}}
	envelope := model.ObservationEnvelope{ObservationID: "obs_test", DeviceID: device.ID, Sequence: 1, Snapshot: snapshot}
	if err := store.AcceptObservation(ctx, device.CertificateSerial, envelope, now); err != nil {
		t.Fatal(err)
	}
	liveDetail, err := store.DeviceDetail(ctx, device.ID, now)
	if err != nil || liveDetail.Snapshot == nil || len(liveDetail.Snapshot.Connections) != 1 {
		t.Fatalf("expected the current remote observation to retain live connections in memory: %#v, %v", liveDetail, err)
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
	if len(detail.Snapshot.Connections) != 0 {
		t.Fatal("backup must not contain live connection metadata")
	}
}
