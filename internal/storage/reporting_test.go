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

func TestReportingStatusPreservesFreshnessAndBoundsReminders(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, expectation, want string
		age                     time.Duration
	}{
		{"current", "intermittent", "current", 34 * time.Minute},
		{"freshness boundary", "intermittent", "current", EnrolledDeviceStaleAfter},
		{"always on overdue", "always-on", "overdue", 36 * time.Minute},
		{"legacy defaults", "", "overdue", time.Hour},
		{"intermittent away", "intermittent", "away", 3 * 24 * time.Hour},
		{"reminder boundary", "intermittent", "away", IntermittentDeviceReminderAfter},
		{"reminder due", "intermittent", "check-in-due", IntermittentDeviceReminderAfter + time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			last := now.Add(-tc.age)
			device := model.DeviceRecord{TrustState: "enrolled", LastSeenAt: &last, ReportingExpectation: tc.expectation}
			device.Status = deviceStatus(device, now)
			if got := deviceReportingStatus(device, now); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if tc.age > EnrolledDeviceStaleAfter && device.Status != "stale" {
				t.Fatal("owner policy must not change raw evidence freshness")
			}
		})
	}
	for _, device := range []model.DeviceRecord{{Status: "revoked", ReportingExpectation: "intermittent"}, {Status: "awaiting-first-report", ReportingExpectation: "intermittent"}} {
		if deviceReportingStatus(device, now) != device.Status {
			t.Fatal("absence policy must not hide revocation or missing enrollment evidence")
		}
	}
}

func TestReportingExpectationMigrationPersistenceAndAudit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "haven.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err = store.database.ExecContext(ctx, `INSERT INTO devices (id,display_name,trust_state,enrolled_at,last_seen_at) VALUES ('test-device','Test laptop','enrolled',?,?)`, now.Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the previous schema, then exercise the actual migration.
	if _, err = store.database.ExecContext(ctx, `ALTER TABLE devices DROP COLUMN reporting_expectation`); err != nil {
		t.Fatal(err)
	}
	if _, err = store.database.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 17`); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := store.DeviceDetail(ctx, "test-device", now)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ReportingExpectation != "always-on" || detail.Device.ReportingStatus != "overdue" {
		t.Fatalf("unsafe migration default: %#v", detail.Device)
	}
	if err = store.SaveReportingExpectation(ctx, "test-device", "intermittent", now); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveReportingExpectation(ctx, "test-device", "other", now); !errors.Is(err, ErrInvalidReportingExpectation) {
		t.Fatalf("invalid enum accepted: %v", err)
	}
	if err = store.SaveReportingExpectation(ctx, "missing", "intermittent", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown identity accepted: %v", err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = store.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = Open(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	detail, err = store.DeviceDetail(ctx, "test-device", now)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ReportingExpectation != "intermittent" || detail.Device.ReportingStatus != "away" || !detail.Device.LastSeenAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("restore lost policy or rewrote contact: %#v", detail.Device)
	}
	events, err := store.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "device.reporting-expectation" {
		t.Fatalf("policy change must be audited exactly once: %#v", events)
	}
	if _, err = store.database.ExecContext(ctx, `CREATE TRIGGER fail_reporting_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveReportingExpectation(ctx, "test-device", "always-on", now); err == nil {
		t.Fatal("audit failure must roll back policy")
	}
	detail, err = store.DeviceDetail(ctx, "test-device", now)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Device.ReportingExpectation != "intermittent" {
		t.Fatal("unaudited policy change committed")
	}
	if _, err = store.database.ExecContext(ctx, `DROP TRIGGER fail_reporting_audit`); err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeDevice(ctx, "test-device", now); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveReportingExpectation(ctx, "test-device", "always-on", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("revoked identity policy changed")
	}
}
