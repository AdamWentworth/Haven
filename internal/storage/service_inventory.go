package storage

import (
	"context"
	"database/sql"
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
)

type ExpectedService struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"deviceId"`
	Label     string    `json:"label"`
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port"`
	BindScope string    `json:"bindScope"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
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

func (store *Store) UpsertExpectedService(ctx context.Context, service ExpectedService) (ExpectedService, error) {
	service.Label = strings.TrimSpace(service.Label)
	service.Protocol = strings.ToUpper(strings.TrimSpace(service.Protocol))
	service.BindScope = strings.ToLower(strings.TrimSpace(service.BindScope))
	if service.DeviceID == "" || service.Label == "" || len(service.Label) > 80 || (service.Protocol != "TCP" && service.Protocol != "UDP") || service.Port < 1 || service.Port > 65535 || !validExpectedBindScope(service.BindScope) {
		return ExpectedService{}, errors.New("invalid expected service")
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
	var id string
	err := store.database.QueryRowContext(ctx,
		`INSERT INTO expected_services (id, device_id, label, protocol, port, bind_scope, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id, protocol, port, bind_scope) DO UPDATE SET
			label = excluded.label,
			updated_at = excluded.updated_at
		 RETURNING id`,
		service.ID, service.DeviceID, service.Label, service.Protocol, service.Port, service.BindScope,
		created.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Scan(&id)
	if err != nil {
		return ExpectedService{}, fmt.Errorf("save expected service: %w", err)
	}
	return store.expectedService(ctx, id)
}

func (store *Store) expectedService(ctx context.Context, id string) (ExpectedService, error) {
	var service ExpectedService
	var created, updated string
	err := store.database.QueryRowContext(ctx,
		`SELECT id, device_id, label, protocol, port, bind_scope, created_at, updated_at
		 FROM expected_services WHERE id = ?`, id).
		Scan(&service.ID, &service.DeviceID, &service.Label, &service.Protocol, &service.Port, &service.BindScope, &created, &updated)
	if err != nil {
		return ExpectedService{}, err
	}
	if service.CreatedAt, err = parseDatabaseTime(created); err != nil {
		return ExpectedService{}, err
	}
	if service.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
		return ExpectedService{}, err
	}
	return service, nil
}

func (store *Store) ListExpectedServices(ctx context.Context, deviceID string) ([]ExpectedService, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, device_id, label, protocol, port, bind_scope, created_at, updated_at
		 FROM expected_services WHERE device_id = ? ORDER BY protocol, port, bind_scope`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	services := []ExpectedService{}
	for rows.Next() {
		var service ExpectedService
		var created, updated string
		if err := rows.Scan(&service.ID, &service.DeviceID, &service.Label, &service.Protocol, &service.Port, &service.BindScope, &created, &updated); err != nil {
			return nil, err
		}
		if service.CreatedAt, err = parseDatabaseTime(created); err != nil {
			return nil, err
		}
		if service.UpdatedAt, err = parseDatabaseTime(updated); err != nil {
			return nil, err
		}
		services = append(services, service)
	}
	return services, rows.Err()
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
