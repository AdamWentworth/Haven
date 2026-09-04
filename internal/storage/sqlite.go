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

type migration struct {
	version    int
	statements []string
}

var migrations = []migration{
	{
		version: 1,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS observations (
				id INTEGER PRIMARY KEY,
				device_key TEXT NOT NULL,
				collected_at TEXT NOT NULL,
				payload_json BLOB NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS observations_device_collected
				ON observations (device_key, collected_at DESC)`,
		},
	},
	{
		version: 2,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS devices (
				id TEXT PRIMARY KEY,
				display_name TEXT NOT NULL,
				host_name TEXT NOT NULL DEFAULT '',
				operating_system TEXT NOT NULL DEFAULT '',
				architecture TEXT NOT NULL DEFAULT '',
				trust_state TEXT NOT NULL,
				certificate_serial TEXT UNIQUE,
				certificate_not_after TEXT,
				enrolled_at TEXT NOT NULL,
				last_seen_at TEXT,
				last_collected_at TEXT,
				last_sequence INTEGER NOT NULL DEFAULT 0,
				revoked_at TEXT
			)`,
			`CREATE TABLE IF NOT EXISTS enrollment_tokens (
				token_hash BLOB PRIMARY KEY,
				display_name TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				created_at TEXT NOT NULL,
				used_at TEXT
			)`,
			`CREATE TABLE IF NOT EXISTS device_observations (
				id INTEGER PRIMARY KEY,
				observation_id TEXT NOT NULL UNIQUE,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				sequence INTEGER,
				collected_at TEXT NOT NULL,
				received_at TEXT NOT NULL,
				payload_json BLOB NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS device_observations_device_collected
				ON device_observations (device_id, collected_at DESC)`,
		},
	},
	{
		version: 3,
		statements: []string{
			`DELETE FROM devices
			 WHERE trust_state = 'local'
			   AND trim(host_name) <> ''
			   AND EXISTS (
				SELECT 1
				  FROM devices AS keeper
				 WHERE keeper.trust_state = 'local'
				   AND lower(trim(keeper.host_name)) = lower(trim(devices.host_name))
				   AND (
					COALESCE(keeper.last_collected_at, keeper.last_seen_at, keeper.enrolled_at) >
						COALESCE(devices.last_collected_at, devices.last_seen_at, devices.enrolled_at)
					OR (
						COALESCE(keeper.last_collected_at, keeper.last_seen_at, keeper.enrolled_at) =
							COALESCE(devices.last_collected_at, devices.last_seen_at, devices.enrolled_at)
						AND keeper.id < devices.id
					)
				   )
			   )`,
		},
	},
	{
		version: 4,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS finding_states (
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				finding_id TEXT NOT NULL,
				category TEXT NOT NULL,
				title TEXT NOT NULL,
				severity TEXT NOT NULL,
				summary TEXT NOT NULL,
				recommendation TEXT NOT NULL,
				active INTEGER NOT NULL,
				first_seen_at TEXT NOT NULL,
				last_seen_at TEXT NOT NULL,
				resolved_at TEXT,
				PRIMARY KEY (device_id, finding_id)
			)`,
			`CREATE TABLE IF NOT EXISTS security_events (
				id INTEGER PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				finding_id TEXT NOT NULL,
				kind TEXT NOT NULL,
				category TEXT NOT NULL,
				title TEXT NOT NULL,
				severity TEXT NOT NULL,
				summary TEXT NOT NULL,
				occurred_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS security_events_device_occurred
				ON security_events (device_id, occurred_at DESC, id DESC)`,
			`CREATE INDEX IF NOT EXISTS security_events_occurred
				ON security_events (occurred_at DESC, id DESC)`,
		},
	},
	{
		version: 5,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS auth_users (
				id TEXT PRIMARY KEY,
				webauthn_user_id BLOB NOT NULL UNIQUE,
				name TEXT NOT NULL,
				display_name TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS auth_credentials (
				credential_id BLOB PRIMARY KEY,
				user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
				encrypted_credential BLOB NOT NULL,
				created_at TEXT NOT NULL,
				last_used_at TEXT
			)`,
			`CREATE TABLE IF NOT EXISTS auth_bootstrap_tokens (
				token_hash BLOB PRIMARY KEY,
				expires_at TEXT NOT NULL,
				created_at TEXT NOT NULL,
				used_at TEXT
			)`,
			`CREATE TABLE IF NOT EXISTS auth_sessions (
				session_hash BLOB PRIMARY KEY,
				csrf_hash BLOB NOT NULL,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				last_seen_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS auth_sessions_expires ON auth_sessions (expires_at)`,
			`CREATE TABLE IF NOT EXISTS finding_reviews (
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				finding_id TEXT NOT NULL,
				state TEXT NOT NULL,
				note TEXT NOT NULL DEFAULT '',
				snoozed_until TEXT,
				reviewed_at TEXT NOT NULL,
				PRIMARY KEY (device_id, finding_id)
			)`,
			`CREATE TABLE IF NOT EXISTS audit_events (
				id INTEGER PRIMARY KEY,
				actor TEXT NOT NULL,
				action TEXT NOT NULL,
				target TEXT NOT NULL,
				outcome TEXT NOT NULL,
				detail TEXT NOT NULL DEFAULT '',
				occurred_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS audit_events_occurred ON audit_events (occurred_at DESC, id DESC)`,
			`CREATE TABLE IF NOT EXISTS security_actions (
				id TEXT PRIMARY KEY,
				kind TEXT NOT NULL,
				status TEXT NOT NULL,
				requested_at TEXT NOT NULL,
				started_at TEXT,
				completed_at TEXT,
				message TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS security_actions_requested ON security_actions (requested_at DESC)`,
		},
	},
	{
		version: 6,
		statements: []string{
			`ALTER TABLE auth_credentials ADD COLUMN label TEXT NOT NULL DEFAULT 'Passkey'`,
		},
	},
	{
		version: 7,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS expected_services (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				label TEXT NOT NULL,
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				bind_scope TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE (device_id, protocol, port, bind_scope)
			)`,
			`CREATE INDEX IF NOT EXISTS expected_services_device
				ON expected_services (device_id, protocol, port)`,
			`CREATE TABLE IF NOT EXISTS observed_listeners (
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				bind_scope TEXT NOT NULL,
				first_seen_at TEXT NOT NULL,
				appeared_at TEXT NOT NULL,
				last_seen_at TEXT NOT NULL,
				present INTEGER NOT NULL,
				PRIMARY KEY (device_id, protocol, port, bind_scope)
			)`,
			`CREATE INDEX IF NOT EXISTS observed_listeners_device_present
				ON observed_listeners (device_id, present, protocol, port)`,
		},
	},
	{
		version: 8,
		statements: []string{
			`CREATE TABLE expected_services_v2 (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				label TEXT NOT NULL,
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				port_end INTEGER NOT NULL,
				bind_scope TEXT NOT NULL,
				process_names TEXT NOT NULL DEFAULT '[]',
				workload_names TEXT NOT NULL DEFAULT '[]',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE (device_id, protocol, port, port_end, bind_scope, process_names, workload_names)
			)`,
			`INSERT INTO expected_services_v2 (
				id, device_id, label, protocol, port, port_end, bind_scope,
				process_names, workload_names, created_at, updated_at
			 )
			 SELECT id, device_id, label, protocol, port, port, bind_scope,
				'[]', '[]', created_at, updated_at
			 FROM expected_services`,
			`DROP TABLE expected_services`,
			`ALTER TABLE expected_services_v2 RENAME TO expected_services`,
			`CREATE INDEX expected_services_device
				ON expected_services (device_id, protocol, port, port_end)`,
		},
	},
	{
		version: 9,
		statements: []string{
			`CREATE TABLE expected_services_v3 (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				label TEXT NOT NULL,
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				port_end INTEGER NOT NULL,
				bind_scope TEXT NOT NULL,
				process_names TEXT NOT NULL DEFAULT '[]',
				workload_names TEXT NOT NULL DEFAULT '[]',
				systemd_units TEXT NOT NULL DEFAULT '[]',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE (device_id, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units)
			)`,
			`INSERT INTO expected_services_v3 (
				id, device_id, label, protocol, port, port_end, bind_scope,
				process_names, workload_names, systemd_units, created_at, updated_at
			 )
			 SELECT id, device_id, label, protocol, port, port_end, bind_scope,
				process_names, workload_names, '[]', created_at, updated_at
			 FROM expected_services`,
			`DROP TABLE expected_services`,
			`ALTER TABLE expected_services_v3 RENAME TO expected_services`,
			`CREATE INDEX expected_services_device
				ON expected_services (device_id, protocol, port, port_end)`,
		},
	},
	{
		version: 10,
		statements: []string{
			`CREATE TABLE push_subscriptions (
				id TEXT PRIMARY KEY,
				endpoint_hash BLOB NOT NULL UNIQUE,
				encrypted_subscription BLOB NOT NULL,
				label TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				last_success_at TEXT,
				last_failure_at TEXT,
				failure_count INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE TABLE push_deliveries (
				instance_id TEXT NOT NULL,
				alert_id TEXT NOT NULL,
				device_id TEXT NOT NULL,
				subscription_id TEXT NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
				status TEXT NOT NULL,
				attempt_count INTEGER NOT NULL DEFAULT 0,
				first_queued_at TEXT NOT NULL,
				last_attempt_at TEXT,
				next_attempt_at TEXT NOT NULL,
				delivered_at TEXT,
				last_result TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (instance_id, subscription_id)
			)`,
			`CREATE INDEX push_deliveries_due ON push_deliveries (status, next_attempt_at)`,
			`CREATE INDEX push_deliveries_subscription ON push_deliveries (subscription_id, first_queued_at DESC)`,
		},
	},
	{
		version: 11,
		statements: []string{
			`ALTER TABLE expected_services ADD COLUMN expires_at TEXT`,
			`CREATE INDEX expected_services_expiration ON expected_services (device_id, expires_at)`,
		},
	},
	{
		version: 12,
		statements: []string{
			`CREATE TABLE managed_appliances (
				id TEXT PRIMARY KEY,
				display_name TEXT NOT NULL,
				kind TEXT NOT NULL,
				address TEXT NOT NULL,
				configured_at TEXT NOT NULL
			)`,
			`CREATE TABLE managed_appliance_services (
				appliance_id TEXT NOT NULL REFERENCES managed_appliances(id) ON DELETE CASCADE,
				service_id TEXT NOT NULL,
				name TEXT NOT NULL,
				protocol TEXT NOT NULL,
				port INTEGER NOT NULL,
				tls INTEGER NOT NULL,
				required INTEGER NOT NULL,
				reachable INTEGER,
				consecutive_failures INTEGER NOT NULL DEFAULT 0,
				first_checked_at TEXT,
				last_checked_at TEXT,
				last_changed_at TEXT,
				error_class TEXT NOT NULL DEFAULT '',
				certificate_subject TEXT,
				certificate_issuer TEXT,
				certificate_fingerprint TEXT,
				certificate_not_before TEXT,
				certificate_not_after TEXT,
				certificate_system_trust INTEGER,
				certificate_name_valid INTEGER,
				PRIMARY KEY (appliance_id, service_id)
			)`,
			`CREATE INDEX managed_appliance_services_checked
				ON managed_appliance_services (appliance_id, last_checked_at)`,
		},
	},
	{
		version: 13,
		statements: []string{
			`ALTER TABLE managed_appliances ADD COLUMN health_provider TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE managed_appliances ADD COLUMN health_payload_json BLOB`,
			`ALTER TABLE managed_appliances ADD COLUMN health_last_checked_at TEXT`,
			`ALTER TABLE managed_appliances ADD COLUMN health_consecutive_failures INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE managed_appliances ADD COLUMN health_error_class TEXT NOT NULL DEFAULT ''`,
		},
	},
	{
		version: 14,
		statements: []string{
			`ALTER TABLE devices ADD COLUMN agent_schema_version INTEGER`,
			`ALTER TABLE devices ADD COLUMN agent_version TEXT`,
			`ALTER TABLE devices ADD COLUMN agent_revision TEXT`,
			`ALTER TABLE devices ADD COLUMN agent_platform TEXT`,
			`ALTER TABLE devices ADD COLUMN agent_installation TEXT`,
			`ALTER TABLE devices ADD COLUMN agent_capabilities_json BLOB`,
			`ALTER TABLE devices ADD COLUMN agent_collection_notices INTEGER`,
		},
	},
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

func (store *Store) SaveSnapshot(ctx context.Context, snapshot model.SecuritySnapshot) error {
	deviceID := snapshot.Device.DeviceID
	if deviceID == "" {
		resolvedDeviceID, err := store.resolveLocalDeviceID(ctx, snapshot.Device.HostName)
		if err != nil {
			return err
		}
		deviceID = resolvedDeviceID
	}
	snapshot.Device.DeviceID = deviceID
	payload, err := historicalPayload(snapshot)
	if err != nil {
		return err
	}
	observationID, err := randomID("local_")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	collectedAt := snapshot.CollectedAt.UTC()
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local observation: %w", err)
	}
	defer transaction.Rollback()

	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO devices (
			id, display_name, host_name, operating_system, architecture,
			trust_state, enrolled_at, last_seen_at, last_collected_at
		) VALUES (?, ?, ?, ?, ?, 'local', ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			display_name = excluded.display_name,
			host_name = excluded.host_name,
			operating_system = excluded.operating_system,
			architecture = excluded.architecture,
			last_seen_at = excluded.last_seen_at,
			last_collected_at = excluded.last_collected_at`,
		deviceID,
		snapshot.Device.HostName,
		snapshot.Device.HostName,
		snapshot.Device.OperatingSystem,
		snapshot.Device.Architecture,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		collectedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save local device: %w", err)
	}
	if err := insertObservation(ctx, transaction, observationID, deviceID, nil, collectedAt, now, payload); err != nil {
		return err
	}
	if err := reconcileFindingEvents(ctx, transaction, deviceID, snapshot, collectedAt); err != nil {
		return err
	}
	if err := reconcileListenerObservations(ctx, transaction, deviceID, snapshot.Connections, collectedAt); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit local observation: %w", err)
	}
	store.rememberLiveSnapshot(deviceID, snapshot)
	return nil
}

func (store *Store) CreateEnrollmentToken(
	ctx context.Context,
	tokenHash []byte,
	displayName string,
	expiresAt time.Time,
	now time.Time,
) error {
	if len(tokenHash) != sha256.Size {
		return errors.New("enrollment token hash is invalid")
	}
	displayName = normalizeDisplayName(displayName)
	_, err := store.database.ExecContext(
		ctx,
		`INSERT INTO enrollment_tokens (token_hash, display_name, expires_at, created_at)
		 VALUES (?, ?, ?, ?)`,
		tokenHash,
		displayName,
		expiresAt.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

func (store *Store) ConsumeEnrollmentToken(
	ctx context.Context,
	tokenHash []byte,
	device EnrollmentDevice,
	now time.Time,
) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin device enrollment: %w", err)
	}
	defer transaction.Rollback()

	var tokenName, expiresAtValue string
	var usedAt sql.NullString
	err = transaction.QueryRowContext(
		ctx,
		`SELECT display_name, expires_at, used_at
		 FROM enrollment_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&tokenName, &expiresAtValue, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEnrollmentInvalid
	}
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	expiresAt, err := parseDatabaseTime(expiresAtValue)
	if err != nil {
		return err
	}
	if usedAt.Valid || !now.UTC().Before(expiresAt) {
		return ErrEnrollmentInvalid
	}
	if device.DisplayName == "" {
		device.DisplayName = tokenName
	}

	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO devices (
			id, display_name, trust_state, certificate_serial,
			certificate_not_after, enrolled_at
		) VALUES (?, ?, 'enrolled', ?, ?, ?)`,
		device.ID,
		normalizeDisplayName(device.DisplayName),
		device.CertificateSerial,
		device.CertificateExpiresAt.UTC().Format(time.RFC3339Nano),
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("create enrolled device: %w", err)
	}
	result, err := transaction.ExecContext(
		ctx,
		`UPDATE enrollment_tokens SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL`,
		now.UTC().Format(time.RFC3339Nano),
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrEnrollmentInvalid
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit device enrollment: %w", err)
	}
	return nil
}

func (store *Store) AcceptObservation(
	ctx context.Context,
	certificateSerial string,
	envelope model.ObservationEnvelope,
	receivedAt time.Time,
) error {
	if envelope.Sequence < 1 {
		return ErrReplay
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin agent observation: %w", err)
	}
	defer transaction.Rollback()

	var deviceID string
	var lastSequence int64
	var revokedAt sql.NullString
	err = transaction.QueryRowContext(
		ctx,
		`SELECT id, last_sequence, revoked_at
		 FROM devices WHERE certificate_serial = ?`,
		certificateSerial,
	).Scan(&deviceID, &lastSequence, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownDevice
	}
	if err != nil {
		return fmt.Errorf("read enrolled device: %w", err)
	}
	if revokedAt.Valid {
		return ErrRevokedDevice
	}
	if envelope.DeviceID != deviceID {
		return ErrUnknownDevice
	}
	var acceptedDeviceID, acceptedCollectedAt string
	var acceptedSequence sql.NullInt64
	err = transaction.QueryRowContext(
		ctx,
		`SELECT device_id, sequence, collected_at
		 FROM device_observations WHERE observation_id = ?`,
		envelope.ObservationID,
	).Scan(&acceptedDeviceID, &acceptedSequence, &acceptedCollectedAt)
	if err == nil {
		collectedAt, parseErr := parseDatabaseTime(acceptedCollectedAt)
		if parseErr != nil {
			return fmt.Errorf("read accepted observation timestamp: %w", parseErr)
		}
		if acceptedDeviceID == deviceID && acceptedSequence.Valid && acceptedSequence.Int64 == envelope.Sequence && collectedAt.Equal(envelope.Snapshot.CollectedAt.UTC()) {
			return ErrAlreadyAccepted
		}
		return ErrReplay
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check observation idempotency key: %w", err)
	}
	if envelope.Sequence <= lastSequence {
		return ErrReplay
	}

	envelope.Snapshot.Device.DeviceID = deviceID
	agentSchemaVersion, agentVersion, agentRevision, agentPlatform, agentInstallation, agentCapabilities, agentCollectionNotices, err := storedAgentMetadata(envelope.Agent)
	if err != nil {
		return err
	}
	payload, err := historicalPayload(envelope.Snapshot)
	if err != nil {
		return err
	}
	if err := insertObservation(
		ctx,
		transaction,
		envelope.ObservationID,
		deviceID,
		&envelope.Sequence,
		envelope.Snapshot.CollectedAt.UTC(),
		receivedAt.UTC(),
		payload,
	); err != nil {
		if isUniqueConstraint(err) {
			return ErrReplay
		}
		return err
	}
	if err := reconcileFindingEvents(ctx, transaction, deviceID, envelope.Snapshot, envelope.Snapshot.CollectedAt.UTC()); err != nil {
		return err
	}
	if err := reconcileListenerObservations(ctx, transaction, deviceID, envelope.Snapshot.Connections, envelope.Snapshot.CollectedAt.UTC()); err != nil {
		return err
	}
	_, err = transaction.ExecContext(
		ctx,
		`UPDATE devices SET
			host_name = ?, operating_system = ?, architecture = ?,
			last_seen_at = ?, last_collected_at = ?, last_sequence = ?,
			agent_schema_version = ?, agent_version = ?, agent_revision = ?,
			agent_platform = ?, agent_installation = ?,
			agent_capabilities_json = ?, agent_collection_notices = ?
		 WHERE id = ?`,
		envelope.Snapshot.Device.HostName,
		envelope.Snapshot.Device.OperatingSystem,
		envelope.Snapshot.Device.Architecture,
		receivedAt.UTC().Format(time.RFC3339Nano),
		envelope.Snapshot.CollectedAt.UTC().Format(time.RFC3339Nano),
		envelope.Sequence,
		agentSchemaVersion,
		agentVersion,
		agentRevision,
		agentPlatform,
		agentInstallation,
		agentCapabilities,
		agentCollectionNotices,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("update enrolled device: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit agent observation: %w", err)
	}
	store.rememberLiveSnapshot(deviceID, envelope.Snapshot)
	return nil
}

func (store *Store) ListDevices(ctx context.Context, now time.Time) ([]model.DeviceRecord, error) {
	rows, err := store.database.QueryContext(
		ctx,
		`SELECT id, display_name, host_name, operating_system, architecture,
			trust_state, enrolled_at, last_seen_at, last_collected_at,
			certificate_not_after, revoked_at, agent_schema_version,
			agent_version, agent_revision, agent_platform, agent_installation,
			agent_capabilities_json, agent_collection_notices
		 FROM devices
		 ORDER BY display_name COLLATE NOCASE, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	devices := []model.DeviceRecord{}
	for rows.Next() {
		device, err := scanDevice(rows, now)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return devices, nil
}

// DeleteLocalDevices removes development-mode collector records and their
// cascading observations. Enrolled devices, authentication, audit history,
// and hub identity material are not affected.
func (store *Store) DeleteLocalDevices(ctx context.Context) (int64, error) {
	result, err := store.database.ExecContext(ctx, `DELETE FROM devices WHERE trust_state = 'local'`)
	if err != nil {
		return 0, fmt.Errorf("delete local collector devices: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted local collector devices: %w", err)
	}
	return deleted, nil
}

func (store *Store) ListSecurityEvents(ctx context.Context, deviceID string, limit int, demoMode bool) ([]model.SecurityEvent, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("security event limit must be from 1 through 100")
	}
	trustFilter := `devices.trust_state <> 'synthetic'`
	if demoMode {
		trustFilter = `devices.trust_state = 'synthetic'`
	}
	query := `SELECT security_events.id, security_events.device_id, devices.display_name,
			security_events.finding_id, security_events.kind, security_events.category,
			security_events.title, security_events.severity, security_events.summary,
			security_events.occurred_at
		 FROM security_events
		 JOIN devices ON devices.id = security_events.device_id
		 WHERE ` + trustFilter
	arguments := []any{}
	if deviceID != "" {
		query += ` AND security_events.device_id = ?`
		arguments = append(arguments, deviceID)
	}
	query += ` ORDER BY security_events.occurred_at DESC, security_events.id DESC LIMIT ?`
	arguments = append(arguments, limit)

	rows, err := store.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list security events: %w", err)
	}
	defer rows.Close()
	events := []model.SecurityEvent{}
	for rows.Next() {
		var event model.SecurityEvent
		var occurredAt string
		if err := rows.Scan(
			&event.ID,
			&event.DeviceID,
			&event.DeviceName,
			&event.FindingID,
			&event.Kind,
			&event.Category,
			&event.Title,
			&event.Severity,
			&event.Summary,
			&occurredAt,
		); err != nil {
			return nil, fmt.Errorf("read security event: %w", err)
		}
		event.OccurredAt, err = parseDatabaseTime(occurredAt)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list security events: %w", err)
	}
	return events, nil
}

func (store *Store) DeviceDetail(ctx context.Context, deviceID string, now time.Time) (model.DeviceDetail, error) {
	row := store.database.QueryRowContext(
		ctx,
		`SELECT id, display_name, host_name, operating_system, architecture,
			trust_state, enrolled_at, last_seen_at, last_collected_at,
			certificate_not_after, revoked_at, agent_schema_version,
			agent_version, agent_revision, agent_platform, agent_installation,
			agent_capabilities_json, agent_collection_notices
		 FROM devices WHERE id = ?`,
		deviceID,
	)
	device, err := scanDevice(row, now)
	if err != nil {
		return model.DeviceDetail{}, err
	}
	if snapshot, ok := store.liveSnapshot(deviceID); ok {
		return model.DeviceDetail{Device: device, Snapshot: &snapshot}, nil
	}

	var payload []byte
	err = store.database.QueryRowContext(
		ctx,
		`SELECT payload_json FROM device_observations
		 WHERE device_id = ? ORDER BY collected_at DESC LIMIT 1`,
		deviceID,
	).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeviceDetail{Device: device}, nil
	}
	if err != nil {
		return model.DeviceDetail{}, fmt.Errorf("load device observation: %w", err)
	}
	var snapshot model.SecuritySnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return model.DeviceDetail{}, fmt.Errorf("decode device observation: %w", err)
	}
	return model.DeviceDetail{Device: device, Snapshot: &snapshot}, nil
}

func (store *Store) RevokeDevice(ctx context.Context, deviceID string, now time.Time) error {
	result, err := store.database.ExecContext(
		ctx,
		`UPDATE devices SET revoked_at = ?, trust_state = 'revoked'
		 WHERE id = ? AND trust_state = 'enrolled' AND revoked_at IS NULL`,
		now.UTC().Format(time.RFC3339Nano),
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked device count: %w", err)
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	store.forgetLiveSnapshot(deviceID)
	return nil
}

func (store *Store) rememberLiveSnapshot(deviceID string, snapshot model.SecuritySnapshot) {
	store.liveMutex.Lock()
	defer store.liveMutex.Unlock()
	store.liveObservations[deviceID] = snapshot
}

func (store *Store) liveSnapshot(deviceID string) (model.SecuritySnapshot, bool) {
	store.liveMutex.RLock()
	defer store.liveMutex.RUnlock()
	snapshot, ok := store.liveObservations[deviceID]
	return snapshot, ok
}

func (store *Store) forgetLiveSnapshot(deviceID string) {
	store.liveMutex.Lock()
	defer store.liveMutex.Unlock()
	delete(store.liveObservations, deviceID)
}

func (store *Store) SeedSyntheticDevices(ctx context.Context, count int, now time.Time) error {
	if count < 1 || count > 25 {
		return errors.New("synthetic device count must be from 1 through 25")
	}
	platforms := []struct {
		name, host, operatingSystem, architecture string
	}{
		{"Demo Windows workstation", "demo-windows", "Windows 11 Pro", "amd64"},
		{"Demo Ubuntu server", "demo-server", "Ubuntu Server", "amd64"},
		{"Demo Linux laptop", "demo-linux-laptop", "Ubuntu Desktop", "amd64"},
		{"Demo macOS laptop", "demo-macbook", "macOS", "arm64"},
		{"Demo macOS workstation", "demo-mac", "macOS", "arm64"},
	}
	for index := 0; index < count; index++ {
		platform := platforms[index%len(platforms)]
		deviceID := fmt.Sprintf("demo-%02d", index+1)
		collectedAt := now.UTC().Add(-time.Duration(index*4) * time.Minute)
		enabled := index%4 != 3
		snapshot := model.SecuritySnapshot{
			CollectedAt: collectedAt,
			Device: model.DeviceSummary{
				DeviceID:        deviceID,
				HostName:        platform.host,
				OperatingSystem: platform.operatingSystem,
				Architecture:    platform.architecture,
			},
			FirewallProfiles: []model.FirewallProfileStatus{{Name: "Default", Enabled: &enabled}},
			Connections:      []model.NetworkConnection{},
			Notices:          []model.CollectorNotice{},
		}
		if strings.Contains(platform.operatingSystem, "Windows") {
			healthy := true
			disabled := false
			administratorCount := 2
			enabledAdministratorCount := 2
			threatCount := 0
			encryptionPercentage := 100.0
			lastUpdate := collectedAt.Add(-9 * 24 * time.Hour)
			signatureUpdate := collectedAt.Add(-4 * time.Hour)
			snapshot.Defender = &model.DefenderStatus{
				AntivirusEnabled:          &healthy,
				RealTimeProtectionEnabled: &healthy,
				BehaviorMonitorEnabled:    &healthy,
				DownloadProtectionEnabled: &healthy,
				TamperProtected:           &healthy,
				SignatureVersion:          "1.0.demo.0",
				SignatureUpdatedAt:        &signatureUpdate,
			}
			snapshot.WindowsBaseline = &model.WindowsBaseline{
				Update:           &model.WindowsUpdateStatus{LastInstalledAt: &lastUpdate, PendingReboot: &disabled, RebootReasons: []string{}},
				SystemEncryption: &model.DiskEncryptionStatus{SystemDrive: "C:", VolumeStatus: "FullyEncrypted", ProtectionStatus: "On", EncryptionPercentage: &encryptionPercentage},
				PlatformSecurity: &model.PlatformSecurityStatus{SecureBootEnabled: &healthy, TPMPresent: &healthy, TPMReady: &healthy},
				RemoteAccess:     &model.RemoteAccessStatus{RemoteDesktopEnabled: &disabled, NetworkLevelAuthRequired: &healthy, RemoteAssistanceEnabled: &disabled, SMB1Enabled: &disabled, OpenSSHServerRunning: &disabled},
				LocalAccounts:    &model.LocalAccountStatus{AdministratorCount: &administratorCount, EnabledAdministratorCount: &enabledAdministratorCount},
				Threats:          &model.DefenderThreatStatus{ActiveThreatCount: &threatCount, RecentDetectionCount: &threatCount},
			}
			snapshot.Connections = []model.NetworkConnection{
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 135, State: "Listen", ProcessID: 1120, ProcessName: "svchost"},
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 445, State: "Listen", ProcessID: 4, ProcessName: "System"},
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 3389, State: "Listen", ProcessID: 1312, ProcessName: "svchost"},
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 49664, State: "Listen", ProcessID: 852, ProcessName: "lsass"},
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 49674, State: "Listen", ProcessID: 6200, ProcessName: "ControlServer"},
				{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 54306, State: "Listen", ProcessID: 14820, ProcessName: "Spotify"},
				{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 5080, State: "Listen", ProcessID: 19440, ProcessName: "haven-hub"},
			}
		} else if strings.Contains(platform.operatingSystem, "Ubuntu") {
			pendingPackages := index % 3
			pendingSecurityPackages := 0
			pendingReboot := false
			failedUnits := 0
			storageUsed := 42.0 + float64(index)
			active := true
			snapshot.LinuxBaseline = &model.LinuxBaseline{
				Updates:          &model.LinuxUpdateStatus{PendingPackageCount: &pendingPackages, PendingSecurityPackageCount: &pendingSecurityPackages, PendingReboot: &pendingReboot},
				Firewall:         &model.LinuxFirewallStatus{Provider: "ufw", Active: &enabled, DefaultInboundAction: "Block", DefaultOutboundAction: "Allow"},
				SSH:              &model.LinuxSSHStatus{ServerRunning: &active, PasswordAuthentication: "no", KeyboardInteractiveAuthentication: "no", PermitRootLogin: "prohibit-password", PublicKeyAuthentication: "yes"},
				Services:         &model.LinuxServiceStatus{FailedUnitCount: &failedUnits},
				AutomaticUpdates: &model.LinuxAutomaticUpdateStatus{Enabled: &active, Active: &active},
				AppArmor:         &model.LinuxAppArmorStatus{Enabled: &active},
				TimeSync:         &model.LinuxTimeSyncStatus{Synchronized: &active},
				Storage:          &model.LinuxStorageStatus{MountPoint: "/", UsedPercentage: &storageUsed},
			}
			if strings.Contains(platform.operatingSystem, "Server") {
				snapshot.Connections = []model.NetworkConnection{
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 22, State: "Listen", ProcessID: 992, ProcessName: "sshd", SystemdUnit: "ssh.service"},
					{Protocol: "TCP", LocalAddress: "127.0.0.53", LocalPort: 53, State: "Listen", SystemdUnit: "systemd-resolved.service"},
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 8081, State: "Listen", ProcessID: 0, ProcessName: ""},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 8081, State: "Listen", SystemdUnit: "binderledger-localhost-proxy@8081.service"},
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 8443, State: "Listen", ProcessID: 0, ProcessName: ""},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 5432, State: "Listen", ProcessID: 1440, ProcessName: "postgres"},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 33509, State: "Listen", SystemdUnit: "containerd.service"},
					{Protocol: "UDP", LocalAddress: "127.0.0.53", LocalPort: 53, State: "Bound", SystemdUnit: "systemd-resolved.service"},
					{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 5353, State: "Bound", ProcessID: 847, ProcessName: "avahi-daemon", SystemdUnit: "avahi-daemon.service"},
					{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 51822, State: "Bound", ProcessID: 0, ProcessName: ""},
				}
				snapshot.LinuxBaseline.Workloads = &model.WorkloadInventory{
					Runtime:     "docker",
					CollectedAt: collectedAt,
					Workloads: []model.ContainerWorkload{
						{Name: "binderledger_web", Image: "ghcr.io/example/binderledger-web:demo", Project: "binderledger", Service: "web", State: "running", Health: "healthy", Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 8080, Published: true, HostAddress: "0.0.0.0", HostPort: 8081}}},
						{Name: "haven_proxy", Image: "caddy:demo", Project: "haven", Service: "proxy", State: "running", Health: "healthy", Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 8443, Published: true, HostAddress: "0.0.0.0", HostPort: 8443}}},
						{Name: "demo_database", Image: "postgres:demo", Project: "demo", Service: "database", State: "running", Health: "healthy", Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 5432, Published: false}}},
					},
				}
			}
		}
		if !enabled {
			snapshot.Notices = append(snapshot.Notices, model.CollectorNotice{
				Source: "Synthetic firewall", Severity: "warning", Message: "A demo protection signal needs attention.",
			})
		}
		if err := store.saveSyntheticSnapshot(ctx, platform.name, snapshot, now.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) saveSyntheticSnapshot(
	ctx context.Context,
	displayName string,
	snapshot model.SecuritySnapshot,
	now time.Time,
) error {
	// Synthetic fixtures intentionally keep their invented live-only fields so
	// demo mode can exercise listener and workload review after a hub restart.
	// Real observations continue through historicalPayload and never persist
	// connection or container-runtime metadata.
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	observationID, err := randomID("demo_")
	if err != nil {
		return err
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO devices (
			id, display_name, host_name, operating_system, architecture,
			trust_state, enrolled_at, last_seen_at, last_collected_at
		) VALUES (?, ?, ?, ?, ?, 'synthetic', ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			display_name = excluded.display_name,
			host_name = excluded.host_name,
			operating_system = excluded.operating_system,
			architecture = excluded.architecture,
			last_seen_at = excluded.last_seen_at,
			last_collected_at = excluded.last_collected_at`,
		snapshot.Device.DeviceID,
		displayName,
		snapshot.Device.HostName,
		snapshot.Device.OperatingSystem,
		snapshot.Device.Architecture,
		now.Format(time.RFC3339Nano),
		snapshot.CollectedAt.UTC().Format(time.RFC3339Nano),
		snapshot.CollectedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save synthetic device: %w", err)
	}
	if err := insertObservation(
		ctx,
		transaction,
		observationID,
		snapshot.Device.DeviceID,
		nil,
		snapshot.CollectedAt,
		now,
		payload,
	); err != nil {
		return err
	}
	if err := reconcileFindingEvents(ctx, transaction, snapshot.Device.DeviceID, snapshot, snapshot.CollectedAt.UTC()); err != nil {
		return err
	}
	if err := reconcileListenerObservations(ctx, transaction, snapshot.Device.DeviceID, snapshot.Connections, snapshot.CollectedAt.UTC()); err != nil {
		return err
	}
	return transaction.Commit()
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

func insertObservation(
	ctx context.Context,
	transaction *sql.Tx,
	observationID, deviceID string,
	sequence *int64,
	collectedAt, receivedAt time.Time,
	payload []byte,
) error {
	_, err := transaction.ExecContext(
		ctx,
		`INSERT INTO device_observations (
			observation_id, device_id, sequence, collected_at, received_at, payload_json
		) VALUES (?, ?, ?, ?, ?, ?)`,
		observationID,
		deviceID,
		nullableSequence(sequence),
		collectedAt.UTC().Format(time.RFC3339Nano),
		receivedAt.UTC().Format(time.RFC3339Nano),
		payload,
	)
	if err != nil {
		return fmt.Errorf("save device observation: %w", err)
	}
	return nil
}

type storedFindingState struct {
	finding model.SecurityFinding
	active  bool
}

func reconcileFindingEvents(
	ctx context.Context,
	transaction *sql.Tx,
	deviceID string,
	snapshot model.SecuritySnapshot,
	occurredAt time.Time,
) error {
	rows, err := transaction.QueryContext(
		ctx,
		`SELECT finding_id, category, title, severity, summary, recommendation, active
		   FROM finding_states WHERE device_id = ?`,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("read finding states: %w", err)
	}
	states := make(map[string]storedFindingState)
	for rows.Next() {
		var state storedFindingState
		var active int
		if err := rows.Scan(
			&state.finding.ID,
			&state.finding.Category,
			&state.finding.Title,
			&state.finding.Severity,
			&state.finding.Summary,
			&state.finding.Recommendation,
			&active,
		); err != nil {
			rows.Close()
			return fmt.Errorf("read finding state: %w", err)
		}
		state.active = active != 0
		states[state.finding.ID] = state
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close finding states: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate finding states: %w", err)
	}

	timestamp := occurredAt.UTC().Format(time.RFC3339Nano)
	current := make(map[string]model.SecurityFinding, len(snapshot.Findings))
	for _, finding := range snapshot.Findings {
		current[finding.ID] = finding
		state, existed := states[finding.ID]
		if !existed || !state.active {
			if err := insertSecurityEvent(ctx, transaction, deviceID, finding, "opened", timestamp); err != nil {
				return err
			}
		}
		_, err := transaction.ExecContext(
			ctx,
			`INSERT INTO finding_states (
				device_id, finding_id, category, title, severity, summary, recommendation,
				active, first_seen_at, last_seen_at, resolved_at
			 ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)
			 ON CONFLICT(device_id, finding_id) DO UPDATE SET
				category = excluded.category,
				title = excluded.title,
				severity = excluded.severity,
				summary = excluded.summary,
				recommendation = excluded.recommendation,
				active = 1,
				first_seen_at = CASE WHEN finding_states.active = 0 THEN excluded.first_seen_at ELSE finding_states.first_seen_at END,
				last_seen_at = excluded.last_seen_at,
				resolved_at = NULL`,
			deviceID,
			finding.ID,
			finding.Category,
			finding.Title,
			finding.Severity,
			finding.Summary,
			finding.Recommendation,
			timestamp,
			timestamp,
		)
		if err != nil {
			return fmt.Errorf("save finding state: %w", err)
		}
	}

	for findingID, state := range states {
		if !state.active {
			continue
		}
		if _, stillActive := current[findingID]; stillActive {
			continue
		}
		if err := insertSecurityEvent(ctx, transaction, deviceID, state.finding, "resolved", timestamp); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(
			ctx,
			`UPDATE finding_states
			    SET active = 0, last_seen_at = ?, resolved_at = ?
			  WHERE device_id = ? AND finding_id = ?`,
			timestamp,
			timestamp,
			deviceID,
			findingID,
		); err != nil {
			return fmt.Errorf("resolve finding state: %w", err)
		}
	}
	return nil
}

func insertSecurityEvent(
	ctx context.Context,
	transaction *sql.Tx,
	deviceID string,
	finding model.SecurityFinding,
	kind, occurredAt string,
) error {
	_, err := transaction.ExecContext(
		ctx,
		`INSERT INTO security_events (
			device_id, finding_id, kind, category, title, severity, summary, occurred_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID,
		finding.ID,
		kind,
		finding.Category,
		finding.Title,
		finding.Severity,
		finding.Summary,
		occurredAt,
	)
	if err != nil {
		return fmt.Errorf("save security event: %w", err)
	}
	return nil
}

func historicalPayload(snapshot model.SecuritySnapshot) ([]byte, error) {
	// Connection and workload metadata are intentionally live-only. Persisting
	// either would create an unnecessary household activity/deployment trail.
	persisted := snapshot
	persisted.Connections = []model.NetworkConnection{}
	if persisted.LinuxBaseline != nil {
		linux := *persisted.LinuxBaseline
		linux.Workloads = nil
		persisted.LinuxBaseline = &linux
	}
	payload, err := json.Marshal(persisted)
	if err != nil {
		return nil, fmt.Errorf("encode security observation: %w", err)
	}
	return payload, nil
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
