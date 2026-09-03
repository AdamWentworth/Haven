package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const MaximumPushSubscriptions = 8

var ErrPushSubscriptionLimit = errors.New("push notification destination limit reached")

type PushSubscriptionRecord struct {
	ID                    string     `json:"id"`
	EncryptedSubscription []byte     `json:"-"`
	Label                 string     `json:"label"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
	LastSuccessAt         *time.Time `json:"lastSuccessAt"`
	LastFailureAt         *time.Time `json:"lastFailureAt"`
	FailureCount          int        `json:"failureCount"`
}

type PushDeliveryCandidate struct {
	Alert        model.Alert
	Subscription PushSubscriptionRecord
	AttemptCount int
}

type PushDeliveryStatus struct {
	SubscriptionCount int        `json:"subscriptionCount"`
	PendingCount      int        `json:"pendingCount"`
	FailedCount       int        `json:"failedCount"`
	LastSuccessAt     *time.Time `json:"lastSuccessAt"`
	LastFailureAt     *time.Time `json:"lastFailureAt"`
}

func (store *Store) UpsertPushSubscription(ctx context.Context, endpointHash, encrypted []byte, label string, now time.Time) (PushSubscriptionRecord, bool, error) {
	if len(endpointHash) != 32 || len(encrypted) < 32 {
		return PushSubscriptionRecord{}, false, errors.New("invalid encrypted push subscription")
	}
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 80 || strings.ContainsAny(label, "\r\n\t") {
		return PushSubscriptionRecord{}, false, errors.New("invalid push subscription label")
	}
	now = now.UTC()
	var existingID string
	err := store.database.QueryRowContext(ctx, `SELECT id FROM push_subscriptions WHERE endpoint_hash = ?`, endpointHash).Scan(&existingID)
	if err == nil {
		_, err = store.database.ExecContext(ctx,
			`UPDATE push_subscriptions SET encrypted_subscription = ?, label = ?, updated_at = ? WHERE id = ?`,
			encrypted, label, now.Format(time.RFC3339Nano), existingID)
		if err != nil {
			return PushSubscriptionRecord{}, false, fmt.Errorf("update push subscription: %w", err)
		}
		record, err := store.PushSubscription(ctx, existingID)
		return record, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PushSubscriptionRecord{}, false, fmt.Errorf("find push subscription: %w", err)
	}
	var count int
	if err := store.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_subscriptions`).Scan(&count); err != nil {
		return PushSubscriptionRecord{}, false, fmt.Errorf("count push subscriptions: %w", err)
	}
	if count >= MaximumPushSubscriptions {
		return PushSubscriptionRecord{}, false, ErrPushSubscriptionLimit
	}
	id, err := randomID("push_")
	if err != nil {
		return PushSubscriptionRecord{}, false, err
	}
	_, err = store.database.ExecContext(ctx,
		`INSERT INTO push_subscriptions (id, endpoint_hash, encrypted_subscription, label, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, endpointHash, encrypted, label, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return PushSubscriptionRecord{}, false, fmt.Errorf("create push subscription: %w", err)
	}
	record, err := store.PushSubscription(ctx, id)
	return record, true, err
}

func (store *Store) PushSubscription(ctx context.Context, id string) (PushSubscriptionRecord, error) {
	row := store.database.QueryRowContext(ctx,
		`SELECT id, encrypted_subscription, label, created_at, updated_at, last_success_at, last_failure_at, failure_count
		 FROM push_subscriptions WHERE id = ?`, id)
	return scanPushSubscription(row)
}

func (store *Store) ListPushSubscriptions(ctx context.Context) ([]PushSubscriptionRecord, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, encrypted_subscription, label, created_at, updated_at, last_success_at, last_failure_at, failure_count
		 FROM push_subscriptions ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []PushSubscriptionRecord{}
	for rows.Next() {
		record, err := scanPushSubscription(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *Store) DeletePushSubscription(ctx context.Context, endpointHash []byte) (bool, error) {
	result, err := store.database.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE endpoint_hash = ?`, endpointHash)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (store *Store) DeletePushSubscriptionByID(ctx context.Context, id string) error {
	_, err := store.database.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ?`, id)
	return err
}

// BaselinePushDeliveries records the alerts that already existed when a new
// destination was enabled. They remain visible in HAVEN but do not generate a
// surprising burst of historical notifications.
func (store *Store) BaselinePushDeliveries(ctx context.Context, subscriptionID string, alerts []model.Alert, now time.Time) error {
	nowText := now.UTC().Format(time.RFC3339Nano)
	for _, alert := range alerts {
		if alert.Severity != "high" && alert.Severity != "medium" {
			continue
		}
		_, err := store.database.ExecContext(ctx,
			`INSERT INTO push_deliveries (instance_id, alert_id, device_id, subscription_id, status, first_queued_at, next_attempt_at, last_result)
			 VALUES (?, ?, ?, ?, 'baseline', ?, ?, 'present-when-enabled')
			 ON CONFLICT(instance_id, subscription_id) DO NOTHING`,
			alert.InstanceID, alert.ID, alert.DeviceID, subscriptionID, nowText, nowText)
		if err != nil {
			return fmt.Errorf("baseline push delivery: %w", err)
		}
	}
	return nil
}

func (store *Store) PreparePushDeliveries(ctx context.Context, alerts []model.Alert, now time.Time) ([]PushDeliveryCandidate, error) {
	now = now.UTC()
	active := make(map[string]model.Alert)
	for _, alert := range alerts {
		if alert.Severity == "high" || alert.Severity == "medium" {
			active[alert.InstanceID] = alert
		}
	}
	rows, err := store.database.QueryContext(ctx, `SELECT instance_id, subscription_id FROM push_deliveries WHERE status IN ('pending', 'retry')`)
	if err != nil {
		return nil, fmt.Errorf("read active push deliveries: %w", err)
	}
	type deliveryKey struct{ instanceID, subscriptionID string }
	pending := []deliveryKey{}
	for rows.Next() {
		var key deliveryKey
		if err := rows.Scan(&key.instanceID, &key.subscriptionID); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, key)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, key := range pending {
		if _, exists := active[key.instanceID]; exists {
			continue
		}
		if _, err := store.database.ExecContext(ctx,
			`UPDATE push_deliveries SET status = 'expired', last_result = 'alert-no-longer-current' WHERE instance_id = ? AND subscription_id = ?`,
			key.instanceID, key.subscriptionID); err != nil {
			return nil, fmt.Errorf("expire inactive push delivery: %w", err)
		}
	}

	subscriptions, err := store.ListPushSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	nowText := now.Format(time.RFC3339Nano)
	for _, alert := range active {
		for _, subscription := range subscriptions {
			_, err := store.database.ExecContext(ctx,
				`INSERT INTO push_deliveries (instance_id, alert_id, device_id, subscription_id, status, first_queued_at, next_attempt_at)
				 VALUES (?, ?, ?, ?, 'pending', ?, ?)
				 ON CONFLICT(instance_id, subscription_id) DO NOTHING`,
				alert.InstanceID, alert.ID, alert.DeviceID, subscription.ID, nowText, nowText)
			if err != nil {
				return nil, fmt.Errorf("queue push delivery: %w", err)
			}
		}
	}
	_, _ = store.database.ExecContext(ctx,
		`DELETE FROM push_deliveries WHERE first_queued_at < ? AND status IN ('baseline', 'delivered', 'expired', 'failed')`,
		now.Add(-90*24*time.Hour).Format(time.RFC3339Nano))

	dueRows, err := store.database.QueryContext(ctx,
		`SELECT d.instance_id, d.attempt_count,
			s.id, s.encrypted_subscription, s.label, s.created_at, s.updated_at,
			s.last_success_at, s.last_failure_at, s.failure_count
		 FROM push_deliveries AS d
		 JOIN push_subscriptions AS s ON s.id = d.subscription_id
		 WHERE d.status IN ('pending', 'retry') AND d.next_attempt_at <= ?
		 ORDER BY d.first_queued_at, d.subscription_id LIMIT 64`, nowText)
	if err != nil {
		return nil, fmt.Errorf("list due push deliveries: %w", err)
	}
	defer dueRows.Close()
	candidates := []PushDeliveryCandidate{}
	for dueRows.Next() {
		var instanceID string
		var candidate PushDeliveryCandidate
		var created, updated string
		var success, failure sql.NullString
		if err := dueRows.Scan(&instanceID, &candidate.AttemptCount,
			&candidate.Subscription.ID, &candidate.Subscription.EncryptedSubscription, &candidate.Subscription.Label,
			&created, &updated, &success, &failure, &candidate.Subscription.FailureCount); err != nil {
			return nil, err
		}
		alert, exists := active[instanceID]
		if !exists {
			continue
		}
		candidate.Alert = alert
		if candidate.Subscription.CreatedAt, err = parseDatabaseTime(created); err != nil {
			return nil, err
		}
		if candidate.Subscription.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
			return nil, err
		}
		if candidate.Subscription.LastSuccessAt, err = optionalDatabaseTime(success); err != nil {
			return nil, err
		}
		if candidate.Subscription.LastFailureAt, err = optionalDatabaseTime(failure); err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, dueRows.Err()
}

func (store *Store) RecordPushDelivery(ctx context.Context, instanceID, subscriptionID, status, result string, attemptedAt, nextAttemptAt time.Time) error {
	if status != "delivered" && status != "retry" && status != "failed" {
		return errors.New("invalid push delivery status")
	}
	attempted := attemptedAt.UTC().Format(time.RFC3339Nano)
	next := nextAttemptAt.UTC().Format(time.RFC3339Nano)
	delivered := any(nil)
	if status == "delivered" {
		delivered = attempted
		next = attempted
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	resultUpdate, err := tx.ExecContext(ctx,
		`UPDATE push_deliveries SET status = ?, attempt_count = attempt_count + 1, last_attempt_at = ?, next_attempt_at = ?, delivered_at = ?, last_result = ?
		 WHERE instance_id = ? AND subscription_id = ?`,
		status, attempted, next, delivered, result, instanceID, subscriptionID)
	if err != nil {
		return err
	}
	if rows, _ := resultUpdate.RowsAffected(); rows != 1 {
		return sql.ErrNoRows
	}
	if status == "delivered" {
		_, err = tx.ExecContext(ctx, `UPDATE push_subscriptions SET last_success_at = ?, failure_count = 0 WHERE id = ?`, attempted, subscriptionID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE push_subscriptions SET last_failure_at = ?, failure_count = failure_count + 1 WHERE id = ?`, attempted, subscriptionID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) PushDeliveryStatus(ctx context.Context) (PushDeliveryStatus, error) {
	var status PushDeliveryStatus
	var lastSuccess, lastFailure sql.NullString
	err := store.database.QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(last_success_at), MAX(last_failure_at) FROM push_subscriptions`).
		Scan(&status.SubscriptionCount, &lastSuccess, &lastFailure)
	if err != nil {
		return status, err
	}
	if status.LastSuccessAt, err = optionalDatabaseTime(lastSuccess); err != nil {
		return status, err
	}
	if status.LastFailureAt, err = optionalDatabaseTime(lastFailure); err != nil {
		return status, err
	}
	if err := store.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_deliveries WHERE status IN ('pending', 'retry')`).Scan(&status.PendingCount); err != nil {
		return status, err
	}
	if err := store.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM push_deliveries WHERE status = 'failed'`).Scan(&status.FailedCount); err != nil {
		return status, err
	}
	return status, nil
}

type pushRow interface{ Scan(...any) error }

func scanPushSubscription(row pushRow) (PushSubscriptionRecord, error) {
	var record PushSubscriptionRecord
	var created, updated string
	var success, failure sql.NullString
	if err := row.Scan(&record.ID, &record.EncryptedSubscription, &record.Label, &created, &updated, &success, &failure, &record.FailureCount); err != nil {
		return record, err
	}
	var err error
	if record.CreatedAt, err = parseDatabaseTime(created); err != nil {
		return record, err
	}
	if record.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
		return record, err
	}
	if record.LastSuccessAt, err = optionalDatabaseTime(success); err != nil {
		return record, err
	}
	if record.LastFailureAt, err = optionalDatabaseTime(failure); err != nil {
		return record, err
	}
	return record, nil
}
