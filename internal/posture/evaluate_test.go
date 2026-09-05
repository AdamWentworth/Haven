package posture

import (
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

func TestEvaluateHealthyWindowsBaseline(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-10 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.Defender.SignatureUpdatedAt = timePointer(now.Add(-time.Hour))
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update:           &model.WindowsUpdateStatus{LastInstalledAt: &lastUpdate, PendingReboot: boolPointer(false)},
		SystemEncryption: &model.DiskEncryptionStatus{SystemDrive: "C:", VolumeStatus: "FullyEncrypted", ProtectionStatus: "On"},
		PlatformSecurity: &model.PlatformSecurityStatus{SecureBootEnabled: boolPointer(true), TPMPresent: boolPointer(true), TPMReady: boolPointer(true)},
		RemoteAccess:     &model.RemoteAccessStatus{RemoteDesktopEnabled: boolPointer(false), NetworkLevelAuthRequired: boolPointer(true), RemoteAssistanceEnabled: boolPointer(false), SMB1Enabled: boolPointer(false), OpenSSHServerRunning: boolPointer(false)},
		LocalAccounts:    &model.LocalAccountStatus{AdministratorCount: intPointer(3), EnabledAdministratorCount: intPointer(2)},
		Threats:          &model.DefenderThreatStatus{ActiveThreatCount: intPointer(0), RecentDetectionCount: intPointer(0)},
	}

	evaluated := Evaluate(snapshot, now)
	if len(evaluated.BaselineChecks) != 9 {
		t.Fatalf("expected 9 baseline checks, got %d", len(evaluated.BaselineChecks))
	}
	if len(evaluated.Findings) != 0 {
		t.Fatalf("expected no findings, got %#v", evaluated.Findings)
	}
	for _, check := range evaluated.BaselineChecks {
		if check.Status != "pass" {
			t.Fatalf("expected passing check, got %#v", check)
		}
	}
}

func TestEvaluatePrioritizesActionableWindowsFindings(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-90 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.Defender.RealTimeProtectionEnabled = boolPointer(false)
	snapshot.FirewallProfiles[0].Enabled = boolPointer(false)
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update:           &model.WindowsUpdateStatus{LastInstalledAt: &lastUpdate, PendingReboot: boolPointer(false)},
		SystemEncryption: &model.DiskEncryptionStatus{SystemDrive: "C:", VolumeStatus: "FullyDecrypted", ProtectionStatus: "Off"},
		PlatformSecurity: &model.PlatformSecurityStatus{SecureBootEnabled: boolPointer(false), TPMPresent: boolPointer(true), TPMReady: boolPointer(false)},
		RemoteAccess:     &model.RemoteAccessStatus{RemoteDesktopEnabled: boolPointer(true), NetworkLevelAuthRequired: boolPointer(false), RemoteAssistanceEnabled: boolPointer(false), SMB1Enabled: boolPointer(false), OpenSSHServerRunning: boolPointer(false)},
		LocalAccounts:    &model.LocalAccountStatus{AdministratorCount: intPointer(4), EnabledAdministratorCount: intPointer(4)},
		Threats:          &model.DefenderThreatStatus{ActiveThreatCount: intPointer(1), RecentDetectionCount: intPointer(1)},
	}

	evaluated := Evaluate(snapshot, now)
	if len(evaluated.Findings) < 7 {
		t.Fatalf("expected multiple findings, got %#v", evaluated.Findings)
	}
	assertFinding(t, evaluated.Findings, "defender-disabled", "high")
	assertFinding(t, evaluated.Findings, "firewall-disabled", "high")
	assertFinding(t, evaluated.Findings, "rdp-nla", "high")
	assertFinding(t, evaluated.Findings, "active-threats", "high")
	for _, finding := range evaluated.Findings {
		if finding.ID == "drive-encryption" {
			t.Fatalf("BitLocker state is physical-loss posture and must not become a network or malware alert: %#v", finding)
		}
	}
}

func TestEvaluateTreatsDisabledBitLockerAsDataAtRestInventory(t *testing.T) {
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		SystemEncryption: &model.DiskEncryptionStatus{SystemDrive: "C:", VolumeStatus: "FullyDecrypted", ProtectionStatus: "Off"},
	}

	evaluated := Evaluate(snapshot, time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC))
	check := findCheck(t, evaluated.BaselineChecks, "encryption")
	if check.Status != "configured" || !strings.Contains(check.Summary, "physical loss") {
		t.Fatalf("expected neutral physical-loss inventory, got %#v", check)
	}
	for _, finding := range evaluated.Findings {
		if finding.ID == "drive-encryption" {
			t.Fatalf("disabled BitLocker must not create an actionable finding: %#v", finding)
		}
	}
}

func TestEvaluateTreatsRunningWindowsOpenSSHAsConfiguredService(t *testing.T) {
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		RemoteAccess: &model.RemoteAccessStatus{
			RemoteDesktopEnabled:     boolPointer(false),
			NetworkLevelAuthRequired: boolPointer(true),
			RemoteAssistanceEnabled:  boolPointer(false),
			SMB1Enabled:              boolPointer(false),
			OpenSSHServerRunning:     boolPointer(true),
		},
	}

	evaluated := Evaluate(snapshot, time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC))
	check := findCheck(t, evaluated.BaselineChecks, "remote-access")
	if check.Status != "configured" {
		t.Fatalf("expected running OpenSSH to be configured, got %#v", check)
	}
	for _, finding := range evaluated.Findings {
		if finding.ID == "openssh-running" {
			t.Fatalf("running OpenSSH alone must not create an actionable finding: %#v", finding)
		}
	}
}

func TestEvaluateTreatsPendingApplicationFileReplacementAsInformational(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-10 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update: &model.WindowsUpdateStatus{
			LastInstalledAt:        &lastUpdate,
			PendingReboot:          boolPointer(false),
			PendingFileReplacement: boolPointer(true),
		},
	}

	evaluated := Evaluate(snapshot, now)
	check := findCheck(t, evaluated.BaselineChecks, "updates")
	if check.Status != "configured" || !strings.Contains(check.Summary, "do not require a restart") {
		t.Fatalf("expected informational application cleanup state, got %#v", check)
	}
	for _, finding := range evaluated.Findings {
		if finding.ID == "pending-reboot" {
			t.Fatalf("generic application file cleanup must not create a restart finding: %#v", finding)
		}
	}
}

func TestEvaluateTreatsLegacyFileReplacementOnlyPayloadAsInformational(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-10 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update: &model.WindowsUpdateStatus{
			LastInstalledAt: &lastUpdate,
			PendingReboot:   boolPointer(true),
			RebootReasons:   []string{"Pending file replacement"},
		},
	}

	evaluated := Evaluate(snapshot, now)
	check := findCheck(t, evaluated.BaselineChecks, "updates")
	if check.Status != "configured" || !strings.Contains(check.Summary, "do not require a restart") {
		t.Fatalf("expected legacy file cleanup payload to be informational, got %#v", check)
	}
	for _, finding := range evaluated.Findings {
		if finding.ID == "pending-reboot" {
			t.Fatalf("legacy file-cleanup-only payload must not create a restart finding: %#v", finding)
		}
	}
}

func TestEvaluateFlagsAuthoritativeWindowsRestartRequirement(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-10 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update: &model.WindowsUpdateStatus{
			LastInstalledAt:        &lastUpdate,
			PendingReboot:          boolPointer(true),
			RebootReasons:          []string{"Windows Update"},
			PendingFileReplacement: boolPointer(true),
		},
	}

	evaluated := Evaluate(snapshot, now)
	assertFinding(t, evaluated.Findings, "pending-reboot", "low")
	check := findCheck(t, evaluated.BaselineChecks, "updates")
	if check.Status != "attention" || check.Evidence != "Windows Update" {
		t.Fatalf("expected authoritative restart requirement to remain actionable, got %#v", check)
	}
}

func TestEvaluateDoesNotTreatDisabledBuiltInAdministratorAsEnabled(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	lastUpdate := now.Add(-10 * 24 * time.Hour)
	snapshot := windowsSnapshot()
	snapshot.Defender.SignatureUpdatedAt = timePointer(now.Add(-time.Hour))
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		Update:           &model.WindowsUpdateStatus{LastInstalledAt: &lastUpdate, PendingReboot: boolPointer(false)},
		SystemEncryption: &model.DiskEncryptionStatus{SystemDrive: "C:", VolumeStatus: "FullyEncrypted", ProtectionStatus: "On"},
		PlatformSecurity: &model.PlatformSecurityStatus{SecureBootEnabled: boolPointer(true), TPMPresent: boolPointer(true), TPMReady: boolPointer(true)},
		RemoteAccess:     &model.RemoteAccessStatus{RemoteDesktopEnabled: boolPointer(false), NetworkLevelAuthRequired: boolPointer(true), RemoteAssistanceEnabled: boolPointer(false), SMB1Enabled: boolPointer(false), OpenSSHServerRunning: boolPointer(false)},
		LocalAccounts:    &model.LocalAccountStatus{AdministratorCount: intPointer(3), EnabledAdministratorCount: intPointer(2)},
		Threats:          &model.DefenderThreatStatus{ActiveThreatCount: intPointer(0), RecentDetectionCount: intPointer(0)},
	}

	evaluated := Evaluate(snapshot, now)
	for _, finding := range evaluated.Findings {
		if finding.ID == "local-admins" {
			t.Fatalf("disabled administrator account must not trigger an enabled-account finding: %#v", finding)
		}
	}
}

func TestEvaluateTreatsRestrictedRDPAsConfigured(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		RemoteAccess: &model.RemoteAccessStatus{
			RemoteDesktopEnabled:     boolPointer(true),
			NetworkLevelAuthRequired: boolPointer(true),
			RDPFirewallScope:         "restricted",
			RDPFirewallRuleCount:     intPointer(2),
			RemoteAssistanceEnabled:  boolPointer(false),
			SMB1Enabled:              boolPointer(false),
			OpenSSHServerRunning:     boolPointer(false),
		},
	}

	evaluated := Evaluate(snapshot, now)
	check := findCheck(t, evaluated.BaselineChecks, "remote-access")
	if check.Status != "configured" {
		t.Fatalf("expected restricted RDP to be configured, got %#v", check)
	}
	for _, finding := range evaluated.Findings {
		if strings.HasPrefix(finding.ID, "rdp-") {
			t.Fatalf("restricted RDP must not create an actionable finding: %#v", finding)
		}
	}
}

func TestEvaluateFlagsUnrestrictedRDPFirewallScope(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	snapshot := windowsSnapshot()
	snapshot.WindowsBaseline = &model.WindowsBaseline{
		RemoteAccess: &model.RemoteAccessStatus{
			RemoteDesktopEnabled:     boolPointer(true),
			NetworkLevelAuthRequired: boolPointer(true),
			RDPFirewallScope:         "unrestricted",
			RDPFirewallRuleCount:     intPointer(1),
			RemoteAssistanceEnabled:  boolPointer(false),
			SMB1Enabled:              boolPointer(false),
			OpenSSHServerRunning:     boolPointer(false),
		},
	}

	evaluated := Evaluate(snapshot, now)
	assertFinding(t, evaluated.Findings, "rdp-firewall-scope", "medium")
}

func TestEvaluateDoesNotCreatePlatformClaimsForUnsupportedPlatforms(t *testing.T) {
	snapshot := model.SecuritySnapshot{Device: model.DeviceSummary{OperatingSystem: "macOS"}}
	evaluated := Evaluate(snapshot, time.Now())
	if len(evaluated.BaselineChecks) != 0 || len(evaluated.Findings) != 0 {
		t.Fatal("unsupported observations must not receive platform findings")
	}
}

func TestEvaluateHealthyLinuxBaseline(t *testing.T) {
	snapshot := healthyLinuxSnapshot()
	evaluated := Evaluate(snapshot, time.Now())
	if len(evaluated.BaselineChecks) != 9 {
		t.Fatalf("expected 9 Linux checks, got %d", len(evaluated.BaselineChecks))
	}
	if len(evaluated.Findings) != 0 {
		t.Fatalf("expected no Linux findings, got %#v", evaluated.Findings)
	}
	for _, check := range evaluated.BaselineChecks {
		if check.Status != "pass" && check.Status != "configured" {
			t.Fatalf("expected healthy or configured Linux check, got %#v", check)
		}
	}
}

func TestEvaluateActionableLinuxBaseline(t *testing.T) {
	snapshot := healthyLinuxSnapshot()
	snapshot.LinuxBaseline.Updates.PendingSecurityPackageCount = intPointer(2)
	snapshot.LinuxBaseline.Updates.PendingPackageCount = intPointer(6)
	snapshot.LinuxBaseline.Updates.PendingReboot = boolPointer(true)
	snapshot.LinuxBaseline.Firewall.Active = boolPointer(false)
	snapshot.LinuxBaseline.SSH.PasswordAuthentication = "yes"
	snapshot.LinuxBaseline.AutomaticUpdates.Enabled = boolPointer(false)
	snapshot.LinuxBaseline.Services.FailedUnitCount = intPointer(1)
	snapshot.LinuxBaseline.Services.FailedUnits = []string{"certbot.service"}
	snapshot.LinuxBaseline.Storage.UsedPercentage = floatPointer(91)

	evaluated := Evaluate(snapshot, time.Now())
	assertFinding(t, evaluated.Findings, "linux-security-updates", "medium")
	assertFinding(t, evaluated.Findings, "linux-pending-reboot", "low")
	assertFinding(t, evaluated.Findings, "linux-firewall-disabled", "medium")
	assertFinding(t, evaluated.Findings, "linux-ssh-passwords", "medium")
	assertFinding(t, evaluated.Findings, "linux-automatic-updates", "medium")
	assertFinding(t, evaluated.Findings, "linux-failed-services", "low")
	serviceCheck := findCheck(t, evaluated.BaselineChecks, "linux-services")
	if !strings.Contains(serviceCheck.Evidence, "certbot.service") {
		t.Fatalf("failed unit name missing from evidence: %#v", serviceCheck)
	}
	assertFinding(t, evaluated.Findings, "linux-storage-low", "medium")
}

func TestEvaluateLinuxFlagsKeyboardInteractiveAuthentication(t *testing.T) {
	snapshot := healthyLinuxSnapshot()
	snapshot.LinuxBaseline.SSH.PasswordAuthentication = "no"
	snapshot.LinuxBaseline.SSH.KeyboardInteractiveAuthentication = "yes"

	evaluated := Evaluate(snapshot, time.Now())
	assertFinding(t, evaluated.Findings, "linux-ssh-passwords", "medium")
}

func TestEvaluateSummarizesPrivacyBoundedBrowserExposure(t *testing.T) {
	snapshot := healthyLinuxSnapshot()
	snapshot.BrowserSecurity = &model.BrowserSecurityStatus{
		Coverage: "observed",
		Browsers: []model.BrowserInstallation{{
			ID: "firefox", Name: "Mozilla Firefox", ProfileCount: 2,
			Extensions: []model.BrowserExtension{
				{Fingerprint: "0123456789abcdef01234567", Name: "Scoped", State: "active", ProfileCount: 1, SiteAccess: "specific-sites", OptionalSiteAccess: "none-declared"},
				{Fingerprint: "abcdef0123456789abcdef01", Name: "Broad", State: "active", ProfileCount: 1, SiteAccess: "all-sites", OptionalSiteAccess: "none-declared"},
			},
		}},
	}

	evaluated := Evaluate(snapshot, time.Now())
	check := findCheck(t, evaluated.BaselineChecks, "browser-inventory")
	if check.Status != "pass" || !strings.Contains(check.Summary, "2 profile(s)") || !strings.Contains(check.Evidence, "1 extension(s)") {
		t.Fatalf("browser exposure was not summarized accurately: %#v", check)
	}
}

func TestEvaluateShowsDisabledWebProtectionWithoutInventingFinding(t *testing.T) {
	snapshot := windowsSnapshot()
	snapshot.BrowserSecurity = &model.BrowserSecurityStatus{
		Coverage: "partial",
		Protections: []model.BrowserProtectionStatus{
			{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "disabled", Source: "Microsoft Defender preferences"},
			{ID: "defender-network", Name: "Defender Network Protection", State: "audit", Source: "Microsoft Defender preferences"},
		},
	}

	evaluated := Evaluate(snapshot, time.Now())
	if findCheck(t, evaluated.BaselineChecks, "browser-inventory").Status != "configured" {
		t.Fatal("partial browser coverage must be presented without a false failure")
	}
	if findCheck(t, evaluated.BaselineChecks, "web-protection-defender-pua").Status != "attention" {
		t.Fatal("disabled protection must remain visible for owner review")
	}
	if findCheck(t, evaluated.BaselineChecks, "web-protection-defender-network").Status != "configured" {
		t.Fatal("audit mode must be represented as configured")
	}
	for _, finding := range evaluated.Findings {
		if strings.HasPrefix(finding.ID, "browser-") || strings.HasPrefix(finding.ID, "web-protection-") {
			t.Fatalf("first-slice browser evidence must not create an unreviewed alert: %#v", finding)
		}
	}
}

func TestEvaluateFlagsSessionDefenseFailuresAndMeaningfulExtensionChanges(t *testing.T) {
	eventCount := 2
	snapshot := windowsSnapshot()
	snapshot.BrowserSecurity = &model.BrowserSecurityStatus{
		Coverage: "observed",
		Browsers: []model.BrowserInstallation{{
			ID: "chrome", Name: "Google Chrome", ProfileCount: 1,
			Extensions: []model.BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Password Helper", State: "active", ProfileCount: 1, SiteAccess: "all-sites", OptionalSiteAccess: "none-declared", SensitivePermissions: []string{"cookies"}}},
		}},
		Protections: []model.BrowserProtectionStatus{
			{ID: "chrome-app-bound-encryption", Name: "Chrome App-Bound Encryption policy", State: "disabled", Source: "Chrome policy"},
			{ID: "chrome-cookie-verification-events", Name: "Chrome cookie-protection verification", State: "attention", Source: "Windows Application event log", EventCount: &eventCount},
		},
		Changes: []model.BrowserExtensionChange{{ID: "abcdef0123456789abcdef01", BrowserID: "chrome", Fingerprint: "0123456789abcdef01234567", ExtensionName: "Password Helper", Kind: "permissions-expanded", SiteAccess: "all-sites", AddedPermissions: []string{"cookies"}}},
	}

	evaluated := Evaluate(snapshot, time.Now())
	assertFinding(t, evaluated.Findings, "browser-protection-chrome-app-bound-encryption", "medium")
	assertFinding(t, evaluated.Findings, "browser-cookie-verification-events", "medium")
	assertFinding(t, evaluated.Findings, "browser-change-abcdef0123456789abcdef01", "medium")
	finding := findFinding(t, evaluated.Findings, "browser-cookie-verification-events")
	if !strings.Contains(strings.ToLower(finding.Summary), "not proof of malware") {
		t.Fatalf("cookie verification finding overstated its evidence: %#v", finding)
	}
}

func healthyLinuxSnapshot() model.SecuritySnapshot {
	return model.SecuritySnapshot{
		Device: model.DeviceSummary{OperatingSystem: "Ubuntu 24.04 LTS"},
		LinuxBaseline: &model.LinuxBaseline{
			Updates:          &model.LinuxUpdateStatus{PendingPackageCount: intPointer(0), PendingSecurityPackageCount: intPointer(0), PendingReboot: boolPointer(false)},
			Firewall:         &model.LinuxFirewallStatus{Provider: "ufw", Active: boolPointer(true), DefaultInboundAction: "Block"},
			SSH:              &model.LinuxSSHStatus{ServerRunning: boolPointer(true), PasswordAuthentication: "no", KeyboardInteractiveAuthentication: "no", PermitRootLogin: "prohibit-password", PublicKeyAuthentication: "yes"},
			Services:         &model.LinuxServiceStatus{FailedUnitCount: intPointer(0)},
			AutomaticUpdates: &model.LinuxAutomaticUpdateStatus{Enabled: boolPointer(true), Active: boolPointer(true)},
			AppArmor:         &model.LinuxAppArmorStatus{Enabled: boolPointer(true)},
			TimeSync:         &model.LinuxTimeSyncStatus{Synchronized: boolPointer(true)},
			Storage:          &model.LinuxStorageStatus{MountPoint: "/", UsedPercentage: floatPointer(45)},
		},
	}
}

func windowsSnapshot() model.SecuritySnapshot {
	return model.SecuritySnapshot{
		Device:           model.DeviceSummary{OperatingSystem: "Microsoft Windows 10 Pro"},
		Defender:         &model.DefenderStatus{AntivirusEnabled: boolPointer(true), RealTimeProtectionEnabled: boolPointer(true), TamperProtected: boolPointer(true)},
		FirewallProfiles: []model.FirewallProfileStatus{{Name: "Private", Enabled: boolPointer(true)}},
	}
}

func assertFinding(t *testing.T, findings []model.SecurityFinding, id, severity string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			if finding.Severity != severity {
				t.Fatalf("expected %s severity %s, got %s", id, severity, finding.Severity)
			}
			return
		}
	}
	t.Fatalf("finding %s was missing", id)
}

func findFinding(t *testing.T, findings []model.SecurityFinding, id string) model.SecurityFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			return finding
		}
	}
	t.Fatalf("finding %s was missing", id)
	return model.SecurityFinding{}
}

func findCheck(t *testing.T, checks []model.BaselineCheck, id string) model.BaselineCheck {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("check %s was missing", id)
	return model.BaselineCheck{}
}

func boolPointer(value bool) *bool           { return &value }
func intPointer(value int) *int              { return &value }
func timePointer(value time.Time) *time.Time { return &value }
func floatPointer(value float64) *float64    { return &value }
