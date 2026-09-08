package storage

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
	{
		version: 15,
		statements: []string{
			`CREATE TABLE account_profiles (
				id TEXT PRIMARY KEY,
				encrypted_profile BLOB NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX account_profiles_updated
				ON account_profiles (updated_at DESC, id)`,
		},
	},
	{
		version: 16,
		statements: []string{
			`CREATE TABLE browser_site_reviews (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
				encrypted_review BLOB NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE INDEX browser_site_reviews_device
				ON browser_site_reviews (device_id, updated_at DESC, id)`,
		},
	},
}
