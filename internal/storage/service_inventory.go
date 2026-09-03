package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const (
	BindScopeAny      = "any"
	BindScopeLocal    = "local"
	BindScopePrivate  = "private"
	BindScopeWildcard = "wildcard"
	BindScopeSpecific = "specific"

	MaximumExpectedServiceLifetime = 30 * 24 * time.Hour
)

type ExpectedService struct {
	ID            string     `json:"id"`
	DeviceID      string     `json:"deviceId"`
	Label         string     `json:"label"`
	Protocol      string     `json:"protocol"`
	Port          int        `json:"port"`
	PortEnd       int        `json:"portEnd"`
	BindScope     string     `json:"bindScope"`
	ProcessNames  []string   `json:"processNames"`
	WorkloadNames []string   `json:"workloadNames"`
	SystemdUnits  []string   `json:"systemdUnits"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type ObservedListener struct {
	DeviceID   string    `json:"deviceId"`
	Protocol   string    `json:"protocol"`
	Port       int       `json:"port"`
	BindScope  string    `json:"bindScope"`
	FirstSeen  time.Time `json:"firstSeenAt"`
	AppearedAt time.Time `json:"appearedAt"`
	LastSeen   time.Time `json:"lastSeenAt"`
	Present    bool      `json:"present"`
}

type listenerKey struct {
	protocol string
	port     int
	scope    string
}

func reconcileListenerObservations(ctx context.Context, tx *sql.Tx, deviceID string, connections []model.NetworkConnection, collectedAt time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE observed_listeners SET present = 2 WHERE device_id = ? AND present = 1`, deviceID); err != nil {
		return fmt.Errorf("prepare listener inventory: %w", err)
	}
	keys := map[listenerKey]struct{}{}
	for _, connection := range connections {
		state := strings.ToLower(strings.TrimSpace(connection.State))
		if state != "listen" && state != "open" && state != "bound" {
			continue
		}
		protocol := strings.ToUpper(strings.TrimSpace(connection.Protocol))
		if (protocol != "TCP" && protocol != "UDP") || connection.LocalPort < 1 || connection.LocalPort > 65535 {
			continue
		}
		keys[listenerKey{protocol: protocol, port: connection.LocalPort, scope: listenerBindScope(connection.LocalAddress)}] = struct{}{}
	}
	ordered := make([]listenerKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].protocol != ordered[right].protocol {
			return ordered[left].protocol < ordered[right].protocol
		}
		if ordered[left].port != ordered[right].port {
			return ordered[left].port < ordered[right].port
		}
		return ordered[left].scope < ordered[right].scope
	})
	at := collectedAt.UTC().Format(time.RFC3339Nano)
	for _, key := range ordered {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO observed_listeners (
				device_id, protocol, port, bind_scope, first_seen_at, appeared_at, last_seen_at, present
			 ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
			 ON CONFLICT(device_id, protocol, port, bind_scope) DO UPDATE SET
				appeared_at = CASE WHEN observed_listeners.present = 0 THEN excluded.appeared_at ELSE observed_listeners.appeared_at END,
				last_seen_at = excluded.last_seen_at,
				present = 1`,
			deviceID, key.protocol, key.port, key.scope, at, at, at)
		if err != nil {
			return fmt.Errorf("record listener inventory: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE observed_listeners SET present = 0 WHERE device_id = ? AND present = 2`, deviceID); err != nil {
		return fmt.Errorf("finish listener inventory: %w", err)
	}
	return nil
}

func listenerBindScope(value string) string {
	address := normalizeListenerAddress(value)
	if address == "" || address == "*" || address == "0.0.0.0" || address == "::" {
		return BindScopeWildcard
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return BindScopeSpecific
	}
	parsed = parsed.Unmap()
	if parsed.IsLoopback() {
		return BindScopeLocal
	}
	if parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return BindScopePrivate
	}
	return BindScopeSpecific
}

func normalizeListenerAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if separator := strings.LastIndex(value, "%"); separator >= 0 {
		value = value[:separator]
	}
	if parsed, err := netip.ParseAddr(value); err == nil {
		return parsed.Unmap().String()
	}
	return strings.ToLower(value)
}

func validExpectedBindScope(value string) bool {
	return value == BindScopeAny || value == BindScopeLocal || value == BindScopePrivate || value == BindScopeWildcard || value == BindScopeSpecific
}

func normalizeExpectedService(service ExpectedService) (ExpectedService, error) {
	service.Label = strings.TrimSpace(service.Label)
	service.Protocol = strings.ToUpper(strings.TrimSpace(service.Protocol))
	service.BindScope = strings.ToLower(strings.TrimSpace(service.BindScope))
	if service.PortEnd == 0 {
		service.PortEnd = service.Port
	}
	referenceTime := service.UpdatedAt.UTC()
	if referenceTime.IsZero() {
		referenceTime = time.Now().UTC()
	}
	if service.ExpiresAt != nil {
		expiresAt := service.ExpiresAt.UTC()
		if !expiresAt.After(referenceTime) || expiresAt.After(referenceTime.Add(MaximumExpectedServiceLifetime)) {
			return ExpectedService{}, errors.New("invalid expected service expiration")
		}
		service.ExpiresAt = &expiresAt
	}
	canonicalNames := func(values []string, trimExecutable bool) ([]string, error) {
		canonical := make(map[string]struct{}, len(values))
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if trimExecutable {
				value = strings.TrimSuffix(value, ".exe")
			}
			if value == "" || len(value) > 80 || strings.ContainsAny(value, "\r\n\t") {
				return nil, errors.New("invalid expected service owner")
			}
			canonical[value] = struct{}{}
		}
		result := make([]string, 0, len(canonical))
		for value := range canonical {
			result = append(result, value)
		}
		sort.Strings(result)
		return result, nil
	}
	var err error
	service.ProcessNames, err = canonicalNames(service.ProcessNames, true)
	if err != nil {
		return ExpectedService{}, err
	}
	service.WorkloadNames, err = canonicalNames(service.WorkloadNames, false)
	if err != nil {
		return ExpectedService{}, err
	}
	service.SystemdUnits, err = canonicalNames(service.SystemdUnits, false)
	if err != nil {
		return ExpectedService{}, err
	}
	if service.DeviceID == "" || service.Label == "" || len(service.Label) > 80 || strings.ContainsAny(service.Label, "\r\n\t") || (service.Protocol != "TCP" && service.Protocol != "UDP") || service.Port < 1 || service.Port > 65535 || service.PortEnd < service.Port || service.PortEnd > 65535 || len(service.ProcessNames) > 16 || len(service.WorkloadNames) > 16 || len(service.SystemdUnits) > 16 || !validExpectedBindScope(service.BindScope) {
		return ExpectedService{}, errors.New("invalid expected service")
	}
	return service, nil
}

func expectedOwnerJSON(values []string) (string, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode expected service owners: %w", err)
	}
	return string(encoded), nil
}

func (store *Store) UpsertExpectedService(ctx context.Context, service ExpectedService) (ExpectedService, error) {
	service, err := normalizeExpectedService(service)
	if err != nil {
		return ExpectedService{}, err
	}
	if service.ID == "" {
		id, err := randomID("svc_")
		if err != nil {
			return ExpectedService{}, err
		}
		service.ID = id
	}
	now := service.UpdatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	created := service.CreatedAt.UTC()
	if created.IsZero() {
		created = now
	}
	processNames, err := expectedOwnerJSON(service.ProcessNames)
	if err != nil {
		return ExpectedService{}, err
	}
	workloadNames, err := expectedOwnerJSON(service.WorkloadNames)
	if err != nil {
		return ExpectedService{}, err
	}
	systemdUnits, err := expectedOwnerJSON(service.SystemdUnits)
	if err != nil {
		return ExpectedService{}, err
	}
	var id string
	err = store.database.QueryRowContext(ctx,
		`INSERT INTO expected_services (id, device_id, label, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units) DO UPDATE SET
			label = excluded.label,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at
		 RETURNING id`,
		service.ID, service.DeviceID, service.Label, service.Protocol, service.Port, service.PortEnd, service.BindScope, processNames, workloadNames, systemdUnits,
		databaseTimeValue(service.ExpiresAt), created.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Scan(&id)
	if err != nil {
		return ExpectedService{}, fmt.Errorf("save expected service: %w", err)
	}
	return store.expectedService(ctx, id)
}

func (store *Store) UpsertExpectedServices(ctx context.Context, services []ExpectedService) ([]ExpectedService, error) {
	if len(services) == 0 || len(services) > 64 {
		return nil, errors.New("expected service batch must contain from 1 through 64 services")
	}
	normalized := make([]ExpectedService, 0, len(services))
	deviceID := ""
	for _, service := range services {
		item, err := normalizeExpectedService(service)
		if err != nil {
			return nil, err
		}
		if deviceID == "" {
			deviceID = item.DeviceID
		} else if item.DeviceID != deviceID {
			return nil, errors.New("expected service batch must target one device")
		}
		if item.ID == "" {
			item.ID, err = randomID("svc_")
			if err != nil {
				return nil, err
			}
		}
		now := item.UpdatedAt.UTC()
		if now.IsZero() {
			now = time.Now().UTC()
		}
		item.UpdatedAt = now
		if item.CreatedAt.IsZero() {
			item.CreatedAt = now
		}
		normalized = append(normalized, item)
	}

	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin expected service batch: %w", err)
	}
	defer transaction.Rollback()
	for _, service := range normalized {
		processNames, err := expectedOwnerJSON(service.ProcessNames)
		if err != nil {
			return nil, err
		}
		workloadNames, err := expectedOwnerJSON(service.WorkloadNames)
		if err != nil {
			return nil, err
		}
		systemdUnits, err := expectedOwnerJSON(service.SystemdUnits)
		if err != nil {
			return nil, err
		}
		_, err = transaction.ExecContext(ctx,
			`INSERT INTO expected_services (id, device_id, label, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units, expires_at, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(device_id, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units) DO UPDATE SET
				label = excluded.label,
				expires_at = excluded.expires_at,
				updated_at = excluded.updated_at`,
			service.ID, service.DeviceID, service.Label, service.Protocol, service.Port, service.PortEnd,
			service.BindScope, processNames, workloadNames, systemdUnits, databaseTimeValue(service.ExpiresAt), service.CreatedAt.UTC().Format(time.RFC3339Nano), service.UpdatedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return nil, fmt.Errorf("save expected service batch: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit expected service batch: %w", err)
	}
	return store.ListExpectedServices(ctx, deviceID)
}

func (store *Store) expectedService(ctx context.Context, id string) (ExpectedService, error) {
	var service ExpectedService
	var processNames, workloadNames, systemdUnits, created, updated string
	var expiresAt sql.NullString
	err := store.database.QueryRowContext(ctx,
		`SELECT id, device_id, label, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units, expires_at, created_at, updated_at
		 FROM expected_services WHERE id = ?`, id).
		Scan(&service.ID, &service.DeviceID, &service.Label, &service.Protocol, &service.Port, &service.PortEnd, &service.BindScope, &processNames, &workloadNames, &systemdUnits, &expiresAt, &created, &updated)
	if err != nil {
		return ExpectedService{}, err
	}
	if service.CreatedAt, err = parseDatabaseTime(created); err != nil {
		return ExpectedService{}, err
	}
	if service.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
		return ExpectedService{}, err
	}
	if service.ExpiresAt, err = optionalDatabaseTime(expiresAt); err != nil {
		return ExpectedService{}, err
	}
	if err := json.Unmarshal([]byte(processNames), &service.ProcessNames); err != nil {
		return ExpectedService{}, fmt.Errorf("decode expected service processes: %w", err)
	}
	if err := json.Unmarshal([]byte(workloadNames), &service.WorkloadNames); err != nil {
		return ExpectedService{}, fmt.Errorf("decode expected service workloads: %w", err)
	}
	if err := json.Unmarshal([]byte(systemdUnits), &service.SystemdUnits); err != nil {
		return ExpectedService{}, fmt.Errorf("decode expected service systemd units: %w", err)
	}
	return service, nil
}

func (store *Store) ListExpectedServices(ctx context.Context, deviceID string) ([]ExpectedService, error) {
	return store.listExpectedServices(ctx, deviceID, false)
}

// ListExpectedServicesIncludingExpired is reserved for server-side projections
// that need expiration evidence to create a new review lifecycle. User-facing
// APIs should use ListExpectedServices so expired trust never appears active.
func (store *Store) ListExpectedServicesIncludingExpired(ctx context.Context, deviceID string) ([]ExpectedService, error) {
	return store.listExpectedServices(ctx, deviceID, true)
}

func (store *Store) listExpectedServices(ctx context.Context, deviceID string, includeExpired bool) ([]ExpectedService, error) {
	now := time.Now().UTC()
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, device_id, label, protocol, port, port_end, bind_scope, process_names, workload_names, systemd_units, expires_at, created_at, updated_at
		 FROM expected_services WHERE device_id = ? ORDER BY protocol, port, port_end, bind_scope`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	services := []ExpectedService{}
	for rows.Next() {
		var service ExpectedService
		var processNames, workloadNames, systemdUnits, created, updated string
		var expiresAt sql.NullString
		if err := rows.Scan(&service.ID, &service.DeviceID, &service.Label, &service.Protocol, &service.Port, &service.PortEnd, &service.BindScope, &processNames, &workloadNames, &systemdUnits, &expiresAt, &created, &updated); err != nil {
			return nil, err
		}
		if service.CreatedAt, err = parseDatabaseTime(created); err != nil {
			return nil, err
		}
		if service.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
			return nil, err
		}
		if service.ExpiresAt, err = optionalDatabaseTime(expiresAt); err != nil {
			return nil, err
		}
		if !includeExpired && service.ExpiresAt != nil && !service.ExpiresAt.After(now) {
			continue
		}
		if err := json.Unmarshal([]byte(processNames), &service.ProcessNames); err != nil {
			return nil, fmt.Errorf("decode expected service processes: %w", err)
		}
		if err := json.Unmarshal([]byte(workloadNames), &service.WorkloadNames); err != nil {
			return nil, fmt.Errorf("decode expected service workloads: %w", err)
		}
		if err := json.Unmarshal([]byte(systemdUnits), &service.SystemdUnits); err != nil {
			return nil, fmt.Errorf("decode expected service systemd units: %w", err)
		}
		services = append(services, service)
	}
	return services, rows.Err()
}

func databaseTimeValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (store *Store) RemoveExpectedService(ctx context.Context, deviceID, id string) error {
	result, err := store.database.ExecContext(ctx, `DELETE FROM expected_services WHERE device_id = ? AND id = ?`, deviceID, id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (store *Store) ListObservedListeners(ctx context.Context, deviceID string) ([]ObservedListener, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT device_id, protocol, port, bind_scope, first_seen_at, appeared_at, last_seen_at, present
		 FROM observed_listeners WHERE device_id = ? ORDER BY present DESC, protocol, port, bind_scope`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	listeners := []ObservedListener{}
	for rows.Next() {
		var item ObservedListener
		var firstSeen, appearedAt, lastSeen string
		var present int
		if err := rows.Scan(&item.DeviceID, &item.Protocol, &item.Port, &item.BindScope, &firstSeen, &appearedAt, &lastSeen, &present); err != nil {
			return nil, err
		}
		if item.FirstSeen, err = parseDatabaseTime(firstSeen); err != nil {
			return nil, err
		}
		if item.AppearedAt, err = parseDatabaseTime(appearedAt); err != nil {
			return nil, err
		}
		if item.LastSeen, err = parseDatabaseTime(lastSeen); err != nil {
			return nil, err
		}
		item.Present = present == 1
		listeners = append(listeners, item)
	}
	return listeners, rows.Err()
}
