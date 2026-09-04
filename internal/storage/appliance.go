package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

func (store *Store) SyncManagedAppliances(ctx context.Context, definitions []model.ManagedApplianceDefinition, configuredAt time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin managed-appliance synchronization: %w", err)
	}
	defer transaction.Rollback()

	configuredAppliances := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		configuredAppliances[definition.ID] = struct{}{}
		var previousAddress, previousHealthProvider string
		addressErr := transaction.QueryRowContext(ctx, `SELECT address, health_provider FROM managed_appliances WHERE id = ?`, definition.ID).Scan(&previousAddress, &previousHealthProvider)
		if addressErr != nil && !errors.Is(addressErr, sql.ErrNoRows) {
			return fmt.Errorf("read managed appliance %q address: %w", definition.ID, addressErr)
		}
		healthProvider := ""
		if definition.Health != nil {
			healthProvider = definition.Health.Provider
		}
		addressChanged := addressErr == nil && previousAddress != definition.Address
		healthChanged := addressErr == nil && previousHealthProvider != healthProvider
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO managed_appliances (id, display_name, kind, address, configured_at, health_provider)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
				display_name = excluded.display_name,
				kind = excluded.kind,
				address = excluded.address,
				health_provider = excluded.health_provider`,
			definition.ID, definition.DisplayName, definition.Kind, definition.Address, configuredAt.UTC().Format(time.RFC3339Nano), healthProvider,
		); err != nil {
			return fmt.Errorf("save managed appliance %q: %w", definition.ID, err)
		}
		if addressChanged || healthChanged {
			if _, err := transaction.ExecContext(ctx,
				`UPDATE managed_appliances
				    SET health_payload_json = NULL, health_last_checked_at = NULL,
				        health_consecutive_failures = 0, health_error_class = ''
				  WHERE id = ?`, definition.ID); err != nil {
				return fmt.Errorf("reset managed appliance %q health status: %w", definition.ID, err)
			}
		}

		configuredServices := make(map[string]struct{}, len(definition.Services))
		for _, service := range definition.Services {
			configuredServices[service.ID] = struct{}{}
			var previousProtocol string
			var previousPort, previousTLS int
			serviceErr := transaction.QueryRowContext(ctx,
				`SELECT protocol, port, tls FROM managed_appliance_services WHERE appliance_id = ? AND service_id = ?`,
				definition.ID, service.ID,
			).Scan(&previousProtocol, &previousPort, &previousTLS)
			if serviceErr != nil && !errors.Is(serviceErr, sql.ErrNoRows) {
				return fmt.Errorf("read managed appliance %q service %q definition: %w", definition.ID, service.ID, serviceErr)
			}
			endpointChanged := serviceErr == nil && (previousProtocol != service.Protocol || previousPort != service.Port || previousTLS != boolInt(service.TLS))
			if _, err := transaction.ExecContext(ctx,
				`INSERT INTO managed_appliance_services (
					appliance_id, service_id, name, protocol, port, tls, required
				 ) VALUES (?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(appliance_id, service_id) DO UPDATE SET
					name = excluded.name,
					protocol = excluded.protocol,
					port = excluded.port,
					tls = excluded.tls,
					required = excluded.required`,
				definition.ID, service.ID, service.Name, service.Protocol, service.Port, boolInt(service.TLS), boolInt(service.Required),
			); err != nil {
				return fmt.Errorf("save managed appliance %q service %q: %w", definition.ID, service.ID, err)
			}
			if addressChanged || endpointChanged {
				if err := resetManagedServiceStatus(ctx, transaction, definition.ID, service.ID); err != nil {
					return err
				}
			}
		}
		if err := deleteUnconfiguredServices(ctx, transaction, definition.ID, configuredServices); err != nil {
			return err
		}
	}
	if err := deleteUnconfiguredAppliances(ctx, transaction, configuredAppliances); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit managed-appliance synchronization: %w", err)
	}
	return nil
}

func (store *Store) RecordManagedApplianceHealth(ctx context.Context, applianceID string, health model.ManagedHealthStatus, checkedAt time.Time) error {
	var previousPayload []byte
	if err := store.database.QueryRowContext(ctx, `SELECT health_payload_json FROM managed_appliances WHERE id = ?`, applianceID).Scan(&previousPayload); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read managed appliance %q previous health: %w", applianceID, err)
	}
	var previous model.ManagedHealthStatus
	if len(previousPayload) > 0 {
		if err := json.Unmarshal(previousPayload, &previous); err != nil {
			return fmt.Errorf("decode managed appliance %q previous health: %w", applianceID, err)
		}
	}
	preserveHealthTransitions(&health, previous, checkedAt.UTC())
	health.LastCheckedAt = nil
	health.ConsecutiveFailures = 0
	payload, err := json.Marshal(health)
	if err != nil {
		return fmt.Errorf("encode managed appliance %q health: %w", applianceID, err)
	}
	failed := health.Status == "unavailable"
	result, err := store.database.ExecContext(ctx,
		`UPDATE managed_appliances
		    SET health_payload_json = ?, health_last_checked_at = ?,
		        health_consecutive_failures = CASE WHEN ? = 1 THEN health_consecutive_failures + 1 ELSE 0 END,
		        health_error_class = ?
		  WHERE id = ? AND health_provider <> ''`,
		payload, checkedAt.UTC().Format(time.RFC3339Nano), boolInt(failed), health.ErrorClass, applianceID,
	)
	if err != nil {
		return fmt.Errorf("record managed appliance %q health: %w", applianceID, err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count managed appliance %q health update: %w", applianceID, err)
	}
	if updated != 1 {
		return fmt.Errorf("managed appliance %q health provider is not configured", applianceID)
	}
	return nil
}

func preserveHealthTransitions(current *model.ManagedHealthStatus, previous model.ManagedHealthStatus, checkedAt time.Time) {
	current.LastChangedAt = transitionTime(current.Status, previous.Status, previous.LastChangedAt, checkedAt)
	previousDisks := make(map[string]model.ManagedDiskHealth, len(previous.Disks))
	for _, item := range previous.Disks {
		previousDisks[item.Name] = item
	}
	for index := range current.Disks {
		prior := previousDisks[current.Disks[index].Name]
		current.Disks[index].LastChangedAt = transitionTime(current.Disks[index].State+"|"+current.Disks[index].SMART, prior.State+"|"+prior.SMART, prior.LastChangedAt, checkedAt)
	}
	previousPools := make(map[string]model.ManagedPoolHealth, len(previous.Pools))
	for _, item := range previous.Pools {
		previousPools[item.Name] = item
	}
	for index := range current.Pools {
		prior := previousPools[current.Pools[index].Name]
		current.Pools[index].LastChangedAt = transitionTime(current.Pools[index].State, prior.State, prior.LastChangedAt, checkedAt)
	}
	previousVolumes := make(map[string]model.ManagedVolumeHealth, len(previous.Volumes))
	for _, item := range previous.Volumes {
		previousVolumes[item.Name] = item
	}
	for index := range current.Volumes {
		prior := previousVolumes[current.Volumes[index].Name]
		current.Volumes[index].LastChangedAt = transitionTime(current.Volumes[index].State, prior.State, prior.LastChangedAt, checkedAt)
	}
	previousTemperatures := make(map[string]model.ManagedTemperature, len(previous.Temperatures))
	for _, item := range previous.Temperatures {
		previousTemperatures[item.Name] = item
	}
	for index := range current.Temperatures {
		prior := previousTemperatures[current.Temperatures[index].Name]
		current.Temperatures[index].LastChangedAt = transitionTime(current.Temperatures[index].State, prior.State, prior.LastChangedAt, checkedAt)
	}
}

func transitionTime(current, previous string, previousChanged *time.Time, checkedAt time.Time) *time.Time {
	if current == previous && previousChanged != nil {
		value := previousChanged.UTC()
		return &value
	}
	value := checkedAt.UTC()
	return &value
}

func resetManagedServiceStatus(ctx context.Context, transaction *sql.Tx, applianceID, serviceID string) error {
	_, err := transaction.ExecContext(ctx,
		`UPDATE managed_appliance_services
		    SET reachable = NULL, consecutive_failures = 0,
		        first_checked_at = NULL, last_checked_at = NULL, last_changed_at = NULL,
		        error_class = '', certificate_subject = NULL, certificate_issuer = NULL,
		        certificate_fingerprint = NULL, certificate_not_before = NULL,
		        certificate_not_after = NULL, certificate_system_trust = NULL,
		        certificate_name_valid = NULL
		  WHERE appliance_id = ? AND service_id = ?`, applianceID, serviceID)
	if err != nil {
		return fmt.Errorf("reset managed appliance %q service %q status: %w", applianceID, serviceID, err)
	}
	return nil
}

func deleteUnconfiguredServices(ctx context.Context, transaction *sql.Tx, applianceID string, configured map[string]struct{}) error {
	rows, err := transaction.QueryContext(ctx, `SELECT service_id FROM managed_appliance_services WHERE appliance_id = ?`, applianceID)
	if err != nil {
		return fmt.Errorf("list managed appliance %q services: %w", applianceID, err)
	}
	var stale []string
	for rows.Next() {
		var serviceID string
		if err := rows.Scan(&serviceID); err != nil {
			rows.Close()
			return fmt.Errorf("read managed appliance service id: %w", err)
		}
		if _, exists := configured[serviceID]; !exists {
			stale = append(stale, serviceID)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close managed appliance service rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate managed appliance services: %w", err)
	}
	for _, serviceID := range stale {
		if _, err := transaction.ExecContext(ctx, `DELETE FROM managed_appliance_services WHERE appliance_id = ? AND service_id = ?`, applianceID, serviceID); err != nil {
			return fmt.Errorf("remove managed appliance %q service %q: %w", applianceID, serviceID, err)
		}
	}
	return nil
}

func deleteUnconfiguredAppliances(ctx context.Context, transaction *sql.Tx, configured map[string]struct{}) error {
	rows, err := transaction.QueryContext(ctx, `SELECT id FROM managed_appliances`)
	if err != nil {
		return fmt.Errorf("list managed appliances: %w", err)
	}
	var stale []string
	for rows.Next() {
		var applianceID string
		if err := rows.Scan(&applianceID); err != nil {
			rows.Close()
			return fmt.Errorf("read managed appliance id: %w", err)
		}
		if _, exists := configured[applianceID]; !exists {
			stale = append(stale, applianceID)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close managed appliance rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate managed appliances: %w", err)
	}
	for _, applianceID := range stale {
		if _, err := transaction.ExecContext(ctx, `DELETE FROM managed_appliances WHERE id = ?`, applianceID); err != nil {
			return fmt.Errorf("remove managed appliance %q: %w", applianceID, err)
		}
	}
	return nil
}

func (store *Store) RecordManagedApplianceProbe(ctx context.Context, applianceID string, services []model.ManagedServiceStatus, checkedAt time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin managed-appliance probe: %w", err)
	}
	defer transaction.Rollback()
	timestamp := checkedAt.UTC().Format(time.RFC3339Nano)
	for _, service := range services {
		var subject, issuer, fingerprint, notBefore, notAfter any
		var systemTrust, nameValid any
		if service.Certificate != nil {
			subject = service.Certificate.Subject
			issuer = service.Certificate.Issuer
			fingerprint = service.Certificate.Fingerprint
			notBefore = service.Certificate.NotBefore.UTC().Format(time.RFC3339Nano)
			notAfter = service.Certificate.NotAfter.UTC().Format(time.RFC3339Nano)
			systemTrust = boolInt(service.Certificate.SystemTrust)
			nameValid = boolInt(service.Certificate.NameValid)
		}
		result, err := transaction.ExecContext(ctx,
			`UPDATE managed_appliance_services
			    SET reachable = ?,
			        consecutive_failures = CASE WHEN ? = 1 THEN 0 ELSE consecutive_failures + 1 END,
			        first_checked_at = COALESCE(first_checked_at, ?),
			        last_checked_at = ?,
			        last_changed_at = CASE
			          WHEN reachable IS NULL OR reachable <> ? THEN ?
			          ELSE last_changed_at
			        END,
			        error_class = ?,
			        certificate_subject = ?,
			        certificate_issuer = ?,
			        certificate_fingerprint = ?,
			        certificate_not_before = ?,
			        certificate_not_after = ?,
			        certificate_system_trust = ?,
			        certificate_name_valid = ?
			  WHERE appliance_id = ? AND service_id = ?`,
			boolInt(service.Reachable), boolInt(service.Reachable), timestamp, timestamp,
			boolInt(service.Reachable), timestamp, service.ErrorClass,
			subject, issuer, fingerprint, notBefore, notAfter, systemTrust, nameValid,
			applianceID, service.ID,
		)
		if err != nil {
			return fmt.Errorf("record managed appliance %q service %q: %w", applianceID, service.ID, err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count managed appliance %q service %q update: %w", applianceID, service.ID, err)
		}
		if updated != 1 {
			return fmt.Errorf("managed appliance %q service %q is not configured", applianceID, service.ID)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit managed-appliance probe: %w", err)
	}
	return nil
}

func (store *Store) ListManagedAppliances(ctx context.Context) ([]model.ManagedApplianceStatus, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT id, display_name, kind, address, configured_at,
		        health_provider, health_payload_json, health_last_checked_at,
		        health_consecutive_failures, health_error_class
		   FROM managed_appliances ORDER BY lower(display_name), id`)
	if err != nil {
		return nil, fmt.Errorf("list managed appliances: %w", err)
	}
	var appliances []model.ManagedApplianceStatus
	for rows.Next() {
		var appliance model.ManagedApplianceStatus
		var configuredAt string
		var healthProvider, healthErrorClass string
		var healthPayload []byte
		var healthChecked sql.NullString
		var healthFailures int
		if err := rows.Scan(
			&appliance.ID, &appliance.DisplayName, &appliance.Kind, &appliance.Address, &configuredAt,
			&healthProvider, &healthPayload, &healthChecked, &healthFailures, &healthErrorClass,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("read managed appliance: %w", err)
		}
		appliance.ConfiguredAt, err = parseDatabaseTime(configuredAt)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if healthProvider != "" {
			health := model.ManagedHealthStatus{Provider: healthProvider, Status: "pending", Coverage: model.ManagedHealthCoverage{Disks: "unavailable", RAID: "unavailable", Temperature: "unavailable", Capacity: "unavailable", Firmware: "unavailable"}}
			if len(healthPayload) > 0 {
				if err := json.Unmarshal(healthPayload, &health); err != nil {
					rows.Close()
					return nil, fmt.Errorf("decode managed appliance %q health: %w", appliance.ID, err)
				}
			}
			health.Provider = healthProvider
			health.ConsecutiveFailures = healthFailures
			health.ErrorClass = healthErrorClass
			if health.LastCheckedAt, err = optionalDatabaseTime(healthChecked); err != nil {
				rows.Close()
				return nil, err
			}
			appliance.Health = &health
		}
		appliances = append(appliances, appliance)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close managed appliance rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed appliances: %w", err)
	}

	for index := range appliances {
		services, err := store.listManagedApplianceServices(ctx, appliances[index].ID)
		if err != nil {
			return nil, err
		}
		appliances[index].Services = services
		for _, service := range services {
			if service.LastCheckedAt != nil && (appliances[index].LastCheckedAt == nil || service.LastCheckedAt.After(*appliances[index].LastCheckedAt)) {
				checked := service.LastCheckedAt.UTC()
				appliances[index].LastCheckedAt = &checked
			}
		}
		if health := appliances[index].Health; health != nil && health.LastCheckedAt != nil && (appliances[index].LastCheckedAt == nil || health.LastCheckedAt.After(*appliances[index].LastCheckedAt)) {
			checked := health.LastCheckedAt.UTC()
			appliances[index].LastCheckedAt = &checked
		}
		appliances[index].Status = managedApplianceStatus(services, appliances[index].Health)
	}
	return appliances, nil
}

func (store *Store) listManagedApplianceServices(ctx context.Context, applianceID string) ([]model.ManagedServiceStatus, error) {
	rows, err := store.database.QueryContext(ctx,
		`SELECT service_id, name, protocol, port, tls, required, reachable, consecutive_failures,
		        first_checked_at, last_checked_at, last_changed_at, error_class,
		        certificate_subject, certificate_issuer, certificate_fingerprint,
		        certificate_not_before, certificate_not_after,
		        certificate_system_trust, certificate_name_valid
		   FROM managed_appliance_services
		  WHERE appliance_id = ?
		  ORDER BY required DESC, port, service_id`, applianceID)
	if err != nil {
		return nil, fmt.Errorf("list managed appliance %q services: %w", applianceID, err)
	}
	defer rows.Close()
	services := make([]model.ManagedServiceStatus, 0)
	for rows.Next() {
		var service model.ManagedServiceStatus
		var tlsEnabled, required int
		var reachable, systemTrust, nameValid sql.NullInt64
		var firstChecked, lastChecked, lastChanged sql.NullString
		var subject, issuer, fingerprint, notBefore, notAfter sql.NullString
		if err := rows.Scan(
			&service.ID, &service.Name, &service.Protocol, &service.Port, &tlsEnabled, &required,
			&reachable, &service.ConsecutiveFailures, &firstChecked, &lastChecked, &lastChanged, &service.ErrorClass,
			&subject, &issuer, &fingerprint, &notBefore, &notAfter, &systemTrust, &nameValid,
		); err != nil {
			return nil, fmt.Errorf("read managed appliance %q service: %w", applianceID, err)
		}
		service.TLS = tlsEnabled != 0
		service.Required = required != 0
		service.Reachable = reachable.Valid && reachable.Int64 != 0
		var err error
		if service.FirstCheckedAt, err = optionalDatabaseTime(firstChecked); err != nil {
			return nil, err
		}
		if service.LastCheckedAt, err = optionalDatabaseTime(lastChecked); err != nil {
			return nil, err
		}
		if service.LastChangedAt, err = optionalDatabaseTime(lastChanged); err != nil {
			return nil, err
		}
		if fingerprint.Valid {
			certificate := &model.ManagedCertificateStatus{Subject: subject.String, Issuer: issuer.String, Fingerprint: fingerprint.String, SystemTrust: systemTrust.Valid && systemTrust.Int64 != 0, NameValid: nameValid.Valid && nameValid.Int64 != 0}
			certificate.NotBefore, err = parseDatabaseTime(notBefore.String)
			if err != nil {
				return nil, err
			}
			certificate.NotAfter, err = parseDatabaseTime(notAfter.String)
			if err != nil {
				return nil, err
			}
			service.Certificate = certificate
		}
		services = append(services, service)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed appliance %q services: %w", applianceID, err)
	}
	return services, nil
}

func managedApplianceStatus(services []model.ManagedServiceStatus, health *model.ManagedHealthStatus) string {
	requiredCount := 0
	rechecking := false
	for _, service := range services {
		if !service.Required {
			continue
		}
		requiredCount++
		if service.LastCheckedAt == nil {
			return "pending"
		}
		if service.Reachable {
			continue
		}
		if service.ConsecutiveFailures >= 2 {
			return "attention"
		}
		rechecking = true
	}
	if rechecking {
		return "rechecking"
	}
	if health != nil {
		if health.LastCheckedAt == nil {
			return "pending"
		}
		if health.Status == "attention" || (health.Status == "unavailable" && health.ConsecutiveFailures >= 2) {
			return "attention"
		}
		if health.Status == "unavailable" || health.Status == "partial" {
			return "observed"
		}
	}
	if requiredCount == 0 {
		return "observed"
	}
	return "healthy"
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
