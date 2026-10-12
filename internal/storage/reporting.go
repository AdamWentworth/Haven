package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const IntermittentDeviceReminderAfter = 7 * 24 * time.Hour

var ErrInvalidReportingExpectation = errors.New("reporting expectation must be always-on or intermittent")

func deviceReportingStatus(device model.DeviceRecord, now time.Time) string {
	if device.Status != "stale" {
		return device.Status
	}
	if device.ReportingExpectation != "intermittent" {
		return "overdue"
	}
	if device.LastSeenAt != nil && now.UTC().Sub(device.LastSeenAt.UTC()) > IntermittentDeviceReminderAfter {
		return "check-in-due"
	}
	return "away"
}

// SaveReportingExpectation changes only an active enrolled device's owner policy.
// Reporter observations cannot overwrite this decision. Its audit is atomic.
func (store *Store) SaveReportingExpectation(ctx context.Context, deviceID, expectation string, now time.Time) error {
	if expectation != "always-on" && expectation != "intermittent" {
		return ErrInvalidReportingExpectation
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE devices SET reporting_expectation = ?
	 WHERE id = ? AND trust_state = 'enrolled' AND revoked_at IS NULL`, expectation, deviceID)
	if err != nil {
		return fmt.Errorf("save reporting expectation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events (actor, action, target, outcome, detail, occurred_at)
	 VALUES ('owner', 'device.reporting-expectation', ?, 'succeeded', ?, ?)`, deviceID,
		"Reporting expectation: "+expectation+".", now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}
