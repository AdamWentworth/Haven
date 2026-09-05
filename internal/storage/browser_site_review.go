package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// EncryptedBrowserSiteReview is the only browser-site classification the
// storage layer understands. Browser profile identifiers, domains, and owner
// decisions remain inside an authenticated encryption envelope.
type EncryptedBrowserSiteReview struct {
	ID         string
	DeviceID   string
	Ciphertext []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (store *Store) ListEncryptedBrowserSiteReviews(ctx context.Context, deviceID string) ([]EncryptedBrowserSiteReview, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, device_id, encrypted_review, created_at, updated_at
		   FROM browser_site_reviews
		  WHERE device_id = ?
		  ORDER BY updated_at DESC, id`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list encrypted browser site reviews: %w", err)
	}
	defer rows.Close()

	reviews := []EncryptedBrowserSiteReview{}
	for rows.Next() {
		var review EncryptedBrowserSiteReview
		var createdAt, updatedAt string
		if err := rows.Scan(&review.ID, &review.DeviceID, &review.Ciphertext, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan encrypted browser site review: %w", err)
		}
		if review.CreatedAt, err = parseDatabaseTime(createdAt); err != nil {
			return nil, err
		}
		if review.UpdatedAt, err = parseDatabaseTime(updatedAt); err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}
	return reviews, rows.Err()
}

func (store *Store) EncryptedBrowserSiteReview(ctx context.Context, deviceID, id string) (EncryptedBrowserSiteReview, error) {
	var review EncryptedBrowserSiteReview
	var createdAt, updatedAt string
	err := store.database.QueryRowContext(ctx,
		`SELECT id, device_id, encrypted_review, created_at, updated_at
		   FROM browser_site_reviews
		  WHERE device_id = ? AND id = ?`, deviceID, id).
		Scan(&review.ID, &review.DeviceID, &review.Ciphertext, &createdAt, &updatedAt)
	if err != nil {
		return review, err
	}
	if review.CreatedAt, err = parseDatabaseTime(createdAt); err != nil {
		return review, err
	}
	if review.UpdatedAt, err = parseDatabaseTime(updatedAt); err != nil {
		return review, err
	}
	return review, nil
}

func (store *Store) SaveEncryptedBrowserSiteReview(ctx context.Context, review EncryptedBrowserSiteReview) error {
	_, err := store.database.ExecContext(ctx,
		`INSERT INTO browser_site_reviews (id, device_id, encrypted_review, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			encrypted_review = excluded.encrypted_review,
			updated_at = excluded.updated_at`,
		review.ID, review.DeviceID, review.Ciphertext,
		review.CreatedAt.UTC().Format(time.RFC3339Nano),
		review.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save encrypted browser site review: %w", err)
	}
	return nil
}

func (store *Store) DeleteBrowserSiteReview(ctx context.Context, deviceID, id string) error {
	result, err := store.database.ExecContext(ctx, `DELETE FROM browser_site_reviews WHERE device_id = ? AND id = ?`, deviceID, id)
	if err != nil {
		return fmt.Errorf("delete browser site review: %w", err)
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
