package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	_ "modernc.org/sqlite"
)

var (
	ErrEnrollmentInvalid = errors.New("enrollment token is invalid, expired, or already used")
	ErrUnknownDevice     = errors.New("client certificate is not enrolled")
	ErrRevokedDevice     = errors.New("device has been revoked")
	ErrAlreadyAccepted   = errors.New("observation was already accepted")
	ErrReplay            = errors.New("observation sequence has already been accepted")
)

type Store struct {
	database         *sql.DB
	liveMutex        sync.RWMutex
	liveObservations map[string]model.SecuritySnapshot
}

type EnrollmentDevice struct {
	ID                   string
	DisplayName          string
	CertificateSerial    string
	CertificateExpiresAt time.Time
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create HAVEN data directory: %w", err)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open HAVEN database: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	store := &Store{database: database, liveObservations: make(map[string]model.SecuritySnapshot)}
	if err := store.initialize(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) initialize(ctx context.Context) error {
	pragmas := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA synchronous = NORMAL`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`,
	}
	for _, statement := range pragmas {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize HAVEN database: %w", err)
		}
	}

	for _, item := range migrations {
		var applied int
		err := store.database.QueryRowContext(
			ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
			item.version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("read schema migration state: %w", err)
		}
		if applied > 0 {
			continue
		}

		transaction, err := store.database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin schema migration: %w", err)
		}
		for _, statement := range item.statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				_ = transaction.Rollback()
				return fmt.Errorf("apply schema migration %d: %w", item.version, err)
			}
		}
		if _, err := transaction.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			item.version,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("record schema migration %d: %w", item.version, err)
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit schema migration %d: %w", item.version, err)
		}
	}
	return nil
}

func (store *Store) Close() error {
	return store.database.Close()
}

// Ping verifies that the persistence layer required by every useful hub
// operation is responsive. It is intentionally small enough for readiness
// probes and does not mutate state.
func (store *Store) Ping(ctx context.Context) error {
	return store.database.PingContext(ctx)
}

func (store *Store) Backup(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("backup destination is required")
	}
	if _, err := os.Stat(destination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	if _, err := store.database.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return fmt.Errorf("protect SQLite backup: %w", err)
	}
	return nil
}

func (store *Store) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin observation retention: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(
		ctx,
		`DELETE FROM security_events WHERE occurred_at < ?`,
		cutoff.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return 0, fmt.Errorf("expire security events: %w", err)
	}
	result, err := transaction.ExecContext(
		ctx,
		`DELETE FROM device_observations WHERE collected_at < ?`,
		cutoff.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, fmt.Errorf("expire device observations: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read expired observation count: %w", err)
	}
	if _, err := transaction.ExecContext(
		ctx,
		`DELETE FROM observations WHERE collected_at < ?`,
		cutoff.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return 0, fmt.Errorf("expire legacy observations: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit observation retention: %w", err)
	}
	store.liveMutex.Lock()
	for deviceID, snapshot := range store.liveObservations {
		if snapshot.CollectedAt.Before(cutoff.UTC()) {
			delete(store.liveObservations, deviceID)
		}
	}
	store.liveMutex.Unlock()
	return deleted, nil
}

func (store *Store) LatestSnapshot(ctx context.Context, deviceID string) (model.SecuritySnapshot, error) {
	detail, err := store.DeviceDetail(ctx, deviceID, time.Now().UTC())
	if err != nil {
		return model.SecuritySnapshot{}, err
	}
	if detail.Snapshot == nil {
		return model.SecuritySnapshot{}, sql.ErrNoRows
	}
	return *detail.Snapshot, nil
}

func DefaultPath() (string, error) {
	if configured := os.Getenv("HAVEN_DATA_PATH"); configured != "" {
		return configured, nil
	}
	stateDirectory, err := DefaultStateDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDirectory, "haven.db"), nil
}

func DefaultStateDirectory() (string, error) {
	if configured := os.Getenv("HAVEN_STATE_DIRECTORY"); configured != "" {
		return configured, nil
	}
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "HAVEN"), nil
		}
	}
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		return filepath.Join(dataHome, "haven"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user data directory: %w", err)
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "HAVEN"), nil
	}
	return filepath.Join(home, ".local", "share", "haven"), nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanDevice(row rowScanner, now time.Time) (model.DeviceRecord, error) {
	var device model.DeviceRecord
	var enrolledAt string
	var lastSeenAt, lastCollectedAt, certificateExpiresAt, revokedAt sql.NullString
	var agentSchemaVersion, agentCollectionNotices sql.NullInt64
	var agentVersion, agentRevision, agentPlatform, agentInstallation sql.NullString
	var agentCapabilities []byte
	err := row.Scan(
		&device.ID,
		&device.DisplayName,
		&device.HostName,
		&device.OperatingSystem,
		&device.Architecture,
		&device.TrustState,
		&enrolledAt,
		&lastSeenAt,
		&lastCollectedAt,
		&certificateExpiresAt,
		&revokedAt,
		&agentSchemaVersion,
		&agentVersion,
		&agentRevision,
		&agentPlatform,
		&agentInstallation,
		&agentCapabilities,
		&agentCollectionNotices,
	)
	if err != nil {
		return model.DeviceRecord{}, fmt.Errorf("read device: %w", err)
	}
	device.EnrolledAt, err = parseDatabaseTime(enrolledAt)
	if err != nil {
		return model.DeviceRecord{}, err
	}
	if device.LastSeenAt, err = optionalDatabaseTime(lastSeenAt); err != nil {
		return model.DeviceRecord{}, err
	}
	if device.LastCollectedAt, err = optionalDatabaseTime(lastCollectedAt); err != nil {
		return model.DeviceRecord{}, err
	}
	if device.CertificateExpiresAt, err = optionalDatabaseTime(certificateExpiresAt); err != nil {
		return model.DeviceRecord{}, err
	}
	if device.RevokedAt, err = optionalDatabaseTime(revokedAt); err != nil {
		return model.DeviceRecord{}, err
	}
	if agentSchemaVersion.Valid {
		metadata := model.AgentMetadata{
			SchemaVersion:     int(agentSchemaVersion.Int64),
			Version:           agentVersion.String,
			Revision:          agentRevision.String,
			Platform:          agentPlatform.String,
			Installation:      agentInstallation.String,
			CollectionNotices: int(agentCollectionNotices.Int64),
			Capabilities:      []string{},
		}
		if len(agentCapabilities) > 0 {
			if err := json.Unmarshal(agentCapabilities, &metadata.Capabilities); err != nil {
				return model.DeviceRecord{}, fmt.Errorf("decode device agent capabilities: %w", err)
			}
		}
		device.Agent = &metadata
	}
	device.Status = deviceStatus(device, now)
	return device, nil
}

func storedAgentMetadata(metadata *model.AgentMetadata) (schemaVersion any, version any, revision any, platform any, installation any, capabilities any, collectionNotices any, err error) {
	if metadata == nil {
		return nil, nil, nil, nil, nil, nil, nil, nil
	}
	payload, err := json.Marshal(metadata.Capabilities)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("encode device agent capabilities: %w", err)
	}
	return metadata.SchemaVersion, metadata.Version, metadata.Revision, metadata.Platform, metadata.Installation, payload, metadata.CollectionNotices, nil
}

// EnrolledDeviceStaleAfter is the server-owned freshness allowance used when
// classifying an enrolled endpoint. Clients receive this value from the
// authenticated runtime endpoint instead of duplicating the threshold.
const EnrolledDeviceStaleAfter = 35 * time.Minute

func deviceStatus(device model.DeviceRecord, now time.Time) string {
	if device.RevokedAt != nil || device.TrustState == "revoked" {
		return "revoked"
	}
	if device.LastSeenAt == nil {
		return "awaiting-first-report"
	}
	if now.UTC().Sub(device.LastSeenAt.UTC()) > EnrolledDeviceStaleAfter {
		return "stale"
	}
	return "current"
}

func optionalDatabaseTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseDatabaseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseDatabaseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp: %w", err)
	}
	return parsed, nil
}

func normalizeDisplayName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Unnamed device"
	}
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func localDeviceID(hostName string) string {
	canonicalHostName := strings.ToLower(strings.TrimSpace(hostName))
	digest := sha256.Sum256([]byte("HAVEN local device\x00" + canonicalHostName))
	return "local_" + hex.EncodeToString(digest[:8])
}

func (store *Store) resolveLocalDeviceID(ctx context.Context, hostName string) (string, error) {
	var deviceID string
	err := store.database.QueryRowContext(
		ctx,
		`SELECT id
		   FROM devices
		  WHERE trust_state = 'local'
		    AND trim(host_name) <> ''
		    AND lower(trim(host_name)) = lower(trim(?))
		  ORDER BY COALESCE(last_collected_at, last_seen_at, enrolled_at) DESC, id
		  LIMIT 1`,
		hostName,
	).Scan(&deviceID)
	if err == nil {
		return deviceID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("resolve local device identity: %w", err)
	}
	return localDeviceID(hostName), nil
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate observation identity: %w", err)
	}
	return prefix + hex.EncodeToString(value), nil
}

func isUniqueConstraint(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed"))
}

func nullableSequence(sequence *int64) any {
	if sequence == nil {
		return nil
	}
	return *sequence
}
