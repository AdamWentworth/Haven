package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// EncryptedAccountProfile is the only account-notebook representation the
// storage layer understands. Provider names, identifiers, posture choices,
// and notes stay inside the authenticated encryption envelope.
type EncryptedAccountProfile struct {
	ID         string
	Ciphertext []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (store *Store) ListEncryptedAccountProfiles(ctx context.Context) ([]EncryptedAccountProfile, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, encrypted_profile, created_at, updated_at
		   FROM account_profiles
		  ORDER BY updated_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("list encrypted account profiles: %w", err)
	}
	defer rows.Close()

	profiles := []EncryptedAccountProfile{}
	for rows.Next() {
		var profile EncryptedAccountProfile
		var createdAt, updatedAt string
		if err := rows.Scan(&profile.ID, &profile.Ciphertext, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan encrypted account profile: %w", err)
		}
		if profile.CreatedAt, err = parseDatabaseTime(createdAt); err != nil {
			return nil, err
		}
		if profile.UpdatedAt, err = parseDatabaseTime(updatedAt); err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func (store *Store) EncryptedAccountProfile(ctx context.Context, id string) (EncryptedAccountProfile, error) {
	var profile EncryptedAccountProfile
	var createdAt, updatedAt string
	err := store.database.QueryRowContext(ctx,
		`SELECT id, encrypted_profile, created_at, updated_at
		   FROM account_profiles WHERE id = ?`, id).
		Scan(&profile.ID, &profile.Ciphertext, &createdAt, &updatedAt)
	if err != nil {
		return profile, err
	}
	if profile.CreatedAt, err = parseDatabaseTime(createdAt); err != nil {
		return profile, err
	}
	if profile.UpdatedAt, err = parseDatabaseTime(updatedAt); err != nil {
		return profile, err
	}
	return profile, nil
}

func (store *Store) SaveEncryptedAccountProfile(ctx context.Context, profile EncryptedAccountProfile) error {
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO account_profiles (id, encrypted_profile, created_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			encrypted_profile = excluded.encrypted_profile,
			updated_at = excluded.updated_at`,
		profile.ID, profile.Ciphertext,
		profile.CreatedAt.UTC().Format(time.RFC3339Nano),
		profile.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save encrypted account profile: %w", err)
	}
	return nil
}

func (store *Store) DeleteAccountProfile(ctx context.Context, id string) error {
	result, err := store.database.ExecContext(ctx, `DELETE FROM account_profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete account profile: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}
