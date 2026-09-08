package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

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
			recentCookieUse := collectedAt.Add(-2 * time.Hour)
			dormantCookieUse := collectedAt.Add(-120 * 24 * time.Hour)
			cookieExpiry := collectedAt.Add(60 * 24 * time.Hour)
			snapshot.Defender = &model.DefenderStatus{
				AntivirusEnabled:          &healthy,
				RealTimeProtectionEnabled: &healthy,
				BehaviorMonitorEnabled:    &healthy,
				DownloadProtectionEnabled: &healthy,
				TamperProtected:           &healthy,
				SignatureVersion:          "1.0.demo.0",
				SignatureUpdatedAt:        &signatureUpdate,
			}
			snapshot.BrowserSecurity = &model.BrowserSecurityStatus{
				Coverage: "observed",
				Browsers: []model.BrowserInstallation{{
					ID: "chrome", Name: "Google Chrome", Version: "140.0.demo", ProfileCount: 1,
					Extensions: []model.BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Demo password manager", Version: "1.0", State: "installed", ProfileCount: 1, SiteAccess: "all-sites", OptionalSiteAccess: "none-declared", SensitivePermissions: []string{"cookies"}, OptionalSensitivePermissions: []string{}}},
					Profiles: []model.BrowserProfile{{Fingerprint: "abcdef0123456789abcdef01", Name: "Personal", CookieStatus: "observed", CookieCount: 8, Sites: []model.BrowserCookieSite{
						{Domain: "accounts.example.com", CookieCount: 5, SessionCookieCount: 2, PersistentCookieCount: 3, SecureCookieCount: 5, HTTPOnlyCookieCount: 4, LastAccessedAt: &recentCookieUse, LatestExpiryAt: &cookieExpiry},
						{Domain: "unused.example.com", CookieCount: 3, SessionCookieCount: 0, PersistentCookieCount: 3, SecureCookieCount: 2, HTTPOnlyCookieCount: 1, LastAccessedAt: &dormantCookieUse, LatestExpiryAt: &cookieExpiry},
					}}},
				}},
				Protections: []model.BrowserProtectionStatus{
					{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "enabled", Source: "Synthetic Defender preferences"},
					{ID: "defender-network", Name: "Defender Network Protection", State: "audit", Source: "Synthetic Defender preferences"},
					{ID: "windows-smartscreen", Name: "Microsoft Defender SmartScreen", State: "enabled", Source: "Synthetic Windows configuration"},
				},
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
			snapshot.BrowserSecurity = &model.BrowserSecurityStatus{
				Coverage:    "observed",
				Browsers:    []model.BrowserInstallation{{ID: "firefox", Name: "Mozilla Firefox", Version: "139.0.demo", ProfileCount: 1, Extensions: []model.BrowserExtension{}}},
				Protections: []model.BrowserProtectionStatus{},
			}
			if strings.Contains(platform.operatingSystem, "Server") {
				snapshot.Connections = []model.NetworkConnection{
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 22, State: "Listen", ProcessID: 992, ProcessName: "sshd", SystemdUnit: "ssh.service"},
					{Protocol: "TCP", LocalAddress: "127.0.0.53", LocalPort: 53, State: "Listen", SystemdUnit: "systemd-resolved.service"},
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 8081, State: "Listen", ProcessID: 0, ProcessName: ""},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 8081, State: "Listen", SystemdUnit: "sample-localhost-proxy@8081.service"},
					{Protocol: "TCP", LocalAddress: "0.0.0.0", LocalPort: 8443, State: "Listen", ProcessID: 0, ProcessName: ""},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 5432, State: "Listen", ProcessID: 1440, ProcessName: "postgres"},
					{Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 33509, State: "Listen", SystemdUnit: "containerd.service"},
					{Protocol: "UDP", LocalAddress: "127.0.0.53", LocalPort: 53, State: "Bound", SystemdUnit: "systemd-resolved.service"},
					{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 5353, State: "Bound", ProcessID: 847, ProcessName: "avahi-daemon", SystemdUnit: "avahi-daemon.service"},
					{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 51820, State: "Bound", ProcessID: 0, ProcessName: "wireguard"},
				}
				snapshot.LinuxBaseline.Workloads = &model.WorkloadInventory{
					Runtime:     "docker",
					CollectedAt: collectedAt,
					Workloads: []model.ContainerWorkload{
						{Name: "sample_web", Image: "ghcr.io/example/sample-web:demo", Project: "sample", Service: "web", State: "running", Health: "healthy", Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 8080, Published: true, HostAddress: "0.0.0.0", HostPort: 8081}}},
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
