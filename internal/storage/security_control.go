package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrBootstrapInvalid = errors.New("bootstrap code is invalid, expired, or already used")

type AuthUserRecord struct {
	ID          string
	WebAuthnID  []byte
	Name        string
	DisplayName string
}

type AuthCredentialRecord struct {
	ID                  []byte
	EncryptedCredential []byte
}

type FindingReview struct {
	DeviceID     string     `json:"deviceId"`
	FindingID    string     `json:"findingId"`
	State        string     `json:"state"`
	Note         string     `json:"note"`
	SnoozedUntil *time.Time `json:"snoozedUntil"`
	ReviewedAt   time.Time  `json:"reviewedAt"`
}

type AuditEvent struct {
	ID         int64     `json:"id"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	Outcome    string    `json:"outcome"`
	Detail     string    `json:"detail"`
	OccurredAt time.Time `json:"occurredAt"`
}

type SecurityAction struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requestedAt"`
	StartedAt   *time.Time `json:"startedAt"`
	CompletedAt *time.Time `json:"completedAt"`
	Message     string     `json:"message"`
}

func (store *Store) AuthConfigured(ctx context.Context) (bool, error) {
	var count int
	err := store.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_credentials`).Scan(&count)
	return count > 0, err
}

func (store *Store) EnsureAuthUser(ctx context.Context, now time.Time) (AuthUserRecord, error) {
	user, err := store.LoadAuthUser(ctx)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthUserRecord{}, err
	}
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return AuthUserRecord{}, fmt.Errorf("generate passkey user identity: %w", err)
	}
	_, err = store.database.ExecContext(ctx,
		`INSERT INTO auth_users (id, webauthn_user_id, name, display_name, created_at) VALUES ('owner', ?, 'owner', 'HAVEN owner', ?)`,
		userID, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return AuthUserRecord{}, fmt.Errorf("create passkey owner: %w", err)
	}
	return AuthUserRecord{ID: "owner", WebAuthnID: userID, Name: "owner", DisplayName: "HAVEN owner"}, nil
}

func (store *Store) LoadAuthUser(ctx context.Context) (AuthUserRecord, error) {
	var user AuthUserRecord
	err := store.database.QueryRowContext(ctx,
		`SELECT id, webauthn_user_id, name, display_name FROM auth_users WHERE id = 'owner'`).
		Scan(&user.ID, &user.WebAuthnID, &user.Name, &user.DisplayName)
	return user, err
}

func (store *Store) AuthCredentials(ctx context.Context) ([]AuthCredentialRecord, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT credential_id, encrypted_credential FROM auth_credentials WHERE user_id = 'owner' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []AuthCredentialRecord{}
	for rows.Next() {
		var record AuthCredentialRecord
		if err := rows.Scan(&record.ID, &record.EncryptedCredential); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *Store) CreateAuthBootstrap(ctx context.Context, tokenHash []byte, expiresAt, now time.Time) error {
	if _, err := store.database.ExecContext(ctx, `DELETE FROM auth_bootstrap_tokens WHERE used_at IS NULL`); err != nil {
		return err
	}
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO auth_bootstrap_tokens (token_hash, expires_at, created_at) VALUES (?, ?, ?)`,
		tokenHash, expiresAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	return err
}

func (store *Store) BootstrapValid(ctx context.Context, tokenHash []byte, now time.Time) (bool, error) {
	var count int
	err := store.database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM auth_bootstrap_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		tokenHash, now.UTC().Format(time.RFC3339Nano)).Scan(&count)
	return count == 1, err
}

func (store *Store) CompleteAuthBootstrap(ctx context.Context, tokenHash, credentialID, encryptedCredential []byte, now time.Time) error {
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE auth_bootstrap_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now.UTC().Format(time.RFC3339Nano), tokenHash, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrBootstrapInvalid
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_credentials (credential_id, user_id, encrypted_credential, created_at) VALUES (?, 'owner', ?, ?)`,
		credentialID, encryptedCredential, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) UpdateAuthCredential(ctx context.Context, credentialID, encryptedCredential []byte, now time.Time) error {
	result, err := store.database.ExecContext(ctx,
		`UPDATE auth_credentials SET encrypted_credential = ?, last_used_at = ? WHERE credential_id = ?`,
		encryptedCredential, now.UTC().Format(time.RFC3339Nano), credentialID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (store *Store) CreateAuthSession(ctx context.Context, sessionHash, csrfHash []byte, expiresAt, now time.Time) error {
	_, _ = store.database.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= ?`, now.UTC().Format(time.RFC3339Nano))
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO auth_sessions (session_hash, csrf_hash, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?)`,
		sessionHash, csrfHash, now.UTC().Format(time.RFC3339Nano), expiresAt.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	return err
}

func (store *Store) ValidateAuthSession(ctx context.Context, sessionHash, csrfHash []byte, now time.Time) (bool, error) {
	var storedCSRF []byte
	err := store.database.QueryRowContext(ctx,
		`SELECT csrf_hash FROM auth_sessions WHERE session_hash = ? AND expires_at > ?`,
		sessionHash, now.UTC().Format(time.RFC3339Nano)).Scan(&storedCSRF)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(csrfHash) > 0 && !equalBytes(storedCSRF, csrfHash) {
		return false, nil
	}
	_, _ = store.database.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at = ? WHERE session_hash = ?`, now.UTC().Format(time.RFC3339Nano), sessionHash)
	return true, nil
}

func (store *Store) DeleteAuthSession(ctx context.Context, sessionHash []byte) error {
	_, err := store.database.ExecContext(ctx, `DELETE FROM auth_sessions WHERE session_hash = ?`, sessionHash)
	return err
}

func (store *Store) UpsertFindingReview(ctx context.Context, review FindingReview) error {
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO finding_reviews (device_id, finding_id, state, note, snoozed_until, reviewed_at) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, finding_id) DO UPDATE SET state=excluded.state, note=excluded.note, snoozed_until=excluded.snoozed_until, reviewed_at=excluded.reviewed_at`,
		review.DeviceID, review.FindingID, review.State, review.Note, optionalTimeString(review.SnoozedUntil), review.ReviewedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (store *Store) ListFindingReviews(ctx context.Context, deviceID string) ([]FindingReview, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT device_id, finding_id, state, note, snoozed_until, reviewed_at FROM finding_reviews WHERE device_id = ? ORDER BY reviewed_at DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reviews := []FindingReview{}
	for rows.Next() {
		var review FindingReview
		var snooze sql.NullString
		var reviewed string
		if err := rows.Scan(&review.DeviceID, &review.FindingID, &review.State, &review.Note, &snooze, &reviewed); err != nil {
			return nil, err
		}
		var err error
		if review.ReviewedAt, err = parseDatabaseTime(reviewed); err != nil {
			return nil, err
		}
		if review.SnoozedUntil, err = optionalDatabaseTime(snooze); err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}
	return reviews, rows.Err()
}

func (store *Store) AppendAudit(ctx context.Context, event AuditEvent) error {
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO audit_events (actor, action, target, outcome, detail, occurred_at) VALUES (?, ?, ?, ?, ?, ?)`,
		event.Actor, event.Action, event.Target, event.Outcome, event.Detail, event.OccurredAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (store *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, actor, action, target, outcome, detail, occurred_at FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var event AuditEvent
		var occurred string
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.Target, &event.Outcome, &event.Detail, &occurred); err != nil {
			return nil, err
		}
		var err error
		if event.OccurredAt, err = parseDatabaseTime(occurred); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (store *Store) CreateSecurityAction(ctx context.Context, action SecurityAction) error {
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO security_actions (id, kind, status, requested_at, message) VALUES (?, ?, ?, ?, ?)`,
		action.ID, action.Kind, action.Status, action.RequestedAt.UTC().Format(time.RFC3339Nano), action.Message)
	return err
}

func (store *Store) SecurityActionActive(ctx context.Context, kind string) (bool, error) {
	var count int
	err := store.database.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_actions WHERE kind = ? AND status IN ('queued', 'running')`, kind).Scan(&count)
	return count > 0, err
}

func (store *Store) UpdateSecurityAction(ctx context.Context, id, status, message string, at time.Time) error {
	column := "started_at"
	if status == "succeeded" || status == "failed" {
		column = "completed_at"
	}
	query := `UPDATE security_actions SET status = ?, message = ?, ` + column + ` = ? WHERE id = ?`
	_, err := store.database.ExecContext(ctx, query, status, message, at.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (store *Store) ListSecurityActions(ctx context.Context, limit int) ([]SecurityAction, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, kind, status, requested_at, started_at, completed_at, message FROM security_actions ORDER BY requested_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	actions := []SecurityAction{}
	for rows.Next() {
		var action SecurityAction
		var requested string
		var started, completed sql.NullString
		if err := rows.Scan(&action.ID, &action.Kind, &action.Status, &requested, &started, &completed, &action.Message); err != nil {
			return nil, err
		}
		var err error
		if action.RequestedAt, err = parseDatabaseTime(requested); err != nil {
			return nil, err
		}
		if action.StartedAt, err = optionalDatabaseTime(started); err != nil {
			return nil, err
		}
		if action.CompletedAt, err = optionalDatabaseTime(completed); err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, rows.Err()
}

func optionalTimeString(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var result byte
	for index := range left {
		result |= left[index] ^ right[index]
	}
	return result == 0
}
