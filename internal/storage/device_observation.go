package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

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
	// Connection, workload, and browser-extension metadata are intentionally
	// live-only. Persisting them would create an unnecessary household activity,
	// deployment, or software-interest trail. The current authenticated report
	// remains available in memory until the hub restarts or a newer report arrives.
	persisted := snapshot
	persisted.Connections = []model.NetworkConnection{}
	persisted.BrowserSecurity = nil
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
