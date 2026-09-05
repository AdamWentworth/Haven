package posture

import (
	"fmt"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const updateFreshnessWindow = 45 * 24 * time.Hour

// Evaluate derives explainable checks and findings from raw observations. It
// never treats an unavailable signal as healthy and never includes account
// names, threat resource paths, or other raw private identifiers.
func Evaluate(snapshot model.SecuritySnapshot, now time.Time) model.SecuritySnapshot {
	snapshot.BaselineChecks = []model.BaselineCheck{}
	snapshot.Findings = []model.SecurityFinding{}
	evaluateBrowserSecurity(&snapshot)
	operatingSystem := strings.ToLower(snapshot.Device.OperatingSystem)
	if snapshot.LinuxBaseline != nil || strings.Contains(operatingSystem, "linux") || strings.Contains(operatingSystem, "ubuntu") {
		evaluateLinux(&snapshot)
		return snapshot
	}
	if !strings.Contains(operatingSystem, "windows") {
		return snapshot
	}

	evaluateDefender(&snapshot, now.UTC())
	evaluateFirewall(&snapshot)
	evaluateUpdate(&snapshot, now.UTC())
	evaluateEncryption(&snapshot)
	evaluatePlatform(&snapshot)
	evaluateRemoteAccess(&snapshot)
	evaluateLocalAccounts(&snapshot)
	evaluateThreats(&snapshot)
	return snapshot
}

func evaluateBrowserSecurity(snapshot *model.SecuritySnapshot) {
	status := snapshot.BrowserSecurity
	if status == nil {
		return
	}
	if status.Coverage == "unavailable" {
		addCheck(snapshot, "browser-inventory", "Browser", "Browser exposure inventory", "unknown", "Supported browser metadata could not be verified for this user session.", "No cookies, history, passwords, page contents, or raw extension identifiers are collected")
	} else {
		profiles := 0
		extensions := 0
		broadAccess := 0
		for _, browser := range status.Browsers {
			profiles += browser.ProfileCount
			extensions += len(browser.Extensions)
			for _, extension := range browser.Extensions {
				if extension.SiteAccess == "all-sites" || extension.OptionalSiteAccess == "all-sites" {
					broadAccess++
				}
			}
		}
		checkStatus := "pass"
		summary := fmt.Sprintf("Observed %d supported browser installation(s), %d profile(s), and %d extension(s).", len(status.Browsers), profiles, extensions)
		if status.Coverage == "partial" {
			checkStatus = "configured"
			summary = "Browser inventory is partial; HAVEN retained only the bounded facts it could verify."
		}
		evidence := fmt.Sprintf("%d extension(s) declare or optionally request all-site access", broadAccess)
		addCheck(snapshot, "browser-inventory", "Browser", "Browser exposure inventory", checkStatus, summary, evidence)
	}

	for _, protection := range status.Protections {
		checkStatus := "unknown"
		summary := protection.Name + " could not be verified."
		switch protection.State {
		case "enabled":
			checkStatus = "pass"
			summary = protection.Name + " is enabled."
		case "audit":
			checkStatus = "configured"
			summary = protection.Name + " is in audit mode."
		case "disabled":
			checkStatus = "attention"
			summary = protection.Name + " is disabled; review whether that matches your intended browser-protection policy."
		case "default":
			checkStatus = "configured"
			if protection.ID == "chrome-app-bound-encryption" {
				summary = protection.Name + " has no disabling override; Chrome enables it by default whenever the platform supports it."
			} else {
				summary = protection.Name + " follows Chrome's gradual default rollout; HAVEN cannot claim that every Google session is device-bound."
			}
		case "clear":
			checkStatus = "pass"
			summary = protection.Name + " reported no recent verification failures."
		case "attention":
			checkStatus = "attention"
			if protection.EventCount != nil {
				summary = fmt.Sprintf("%s recorded %d verification failure event(s) in the last seven days.", protection.Name, *protection.EventCount)
			} else {
				summary = protection.Name + " needs review."
			}
		}
		addCheck(snapshot, "web-protection-"+protection.ID, "Browser protection", protection.Name, checkStatus, summary, protection.Source)
		if protection.State == "disabled" && (protection.ID == "chrome-app-bound-encryption" || protection.ID == "chrome-device-bound-sessions") {
			addFinding(snapshot, "browser-protection-"+protection.ID, "Browser", protection.Name+" is explicitly disabled", "medium", "A managed Chrome policy explicitly disables this session-theft mitigation.", "Confirm that the policy is intentional. If it is not, remove the disabling policy or enable the feature, restart Chrome, and verify the effective policy in chrome://policy.")
		}
		if protection.ID == "chrome-cookie-verification-events" && protection.State == "attention" && protection.EventCount != nil {
			addFinding(snapshot, "browser-cookie-verification-events", "Browser", "Review Chrome cookie-protection failures", "medium", fmt.Sprintf("Chrome recorded %d App-Bound Encryption verification failure event(s) in the last seven days. A failure may indicate incompatible software or an attempted bypass; it is not proof of malware.", *protection.EventCount), "Review Windows Application log events from source Chrome with ID 257, confirm Chrome and security software are current, and investigate the named process before changing browser protection settings.")
		}
	}

	for _, change := range status.Changes {
		title := "Review browser extension change"
		summary := change.ExtensionName + " changed on " + browserDisplayName(change.BrowserID) + "."
		switch change.Kind {
		case "installed":
			title = "Review newly installed browser extension"
			summary = change.ExtensionName + " was newly observed on " + browserDisplayName(change.BrowserID) + "."
		case "enabled":
			title = "Review re-enabled browser extension"
			summary = change.ExtensionName + " changed from disabled to enabled on " + browserDisplayName(change.BrowserID) + "."
		case "permissions-expanded":
			title = "Review expanded browser extension access"
			summary = change.ExtensionName + " gained broader declared access on " + browserDisplayName(change.BrowserID) + "."
		}
		if change.SiteAccess == "all-sites" {
			summary += " Its declared or optional access now includes all sites."
		}
		if len(change.AddedPermissions) > 0 {
			summary += " Added sensitive capabilities: " + strings.Join(change.AddedPermissions, ", ") + "."
		}
		addFinding(snapshot, "browser-change-"+change.ID, "Browser", title, browserChangeSeverity(change), summary, "Open the browser's extension manager, confirm the extension and its access are expected, and remove or restrict it if you do not recognize or need it. HAVEN never reads the extension's data or your cookies.")
	}
}

func browserChangeSeverity(change model.BrowserExtensionChange) string {
	if change.SiteAccess == "all-sites" {
		return "medium"
	}
	for _, permission := range change.AddedPermissions {
		switch permission {
		case "cookies", "debugger", "nativemessaging", "proxy", "webauthenticationproxy", "browsingdata":
			return "medium"
		}
	}
	return "low"
}

func browserDisplayName(id string) string {
	switch id {
	case "chrome":
		return "Google Chrome"
	case "edge":
		return "Microsoft Edge"
	case "brave":
		return "Brave"
	case "chromium", "chromium-snap":
		return "Chromium"
	case "firefox", "firefox-snap":
		return "Mozilla Firefox"
	default:
		return "a supported browser"
	}
}

func evaluateLinux(snapshot *model.SecuritySnapshot) {
	evaluateLinuxUpdates(snapshot)
	evaluateLinuxFirewall(snapshot)
	evaluateLinuxSSH(snapshot)
	evaluateLinuxAutomaticUpdates(snapshot)
	evaluateLinuxAppArmor(snapshot)
	evaluateLinuxTimeSync(snapshot)
	evaluateLinuxServices(snapshot)
	evaluateLinuxStorage(snapshot)
}

func evaluateLinuxUpdates(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.Updates == nil {
		addCheck(snapshot, "linux-updates", "Maintenance", "Ubuntu updates", "unknown", "Available package updates could not be verified.", "")
		addCheck(snapshot, "linux-reboot", "Maintenance", "Restart state", "unknown", "Pending-restart state could not be verified.", "")
		return
	}
	updates := snapshot.LinuxBaseline.Updates
	if updates.PendingSecurityPackageCount == nil || updates.PendingPackageCount == nil {
		addCheck(snapshot, "linux-updates", "Maintenance", "Ubuntu updates", "unknown", "Available package updates could not be counted.", "")
	} else if *updates.PendingSecurityPackageCount > 0 {
		count := *updates.PendingSecurityPackageCount
		addCheck(snapshot, "linux-updates", "Maintenance", "Ubuntu updates", "attention", fmt.Sprintf("%d security update(s) are available.", count), fmt.Sprintf("%d total package update(s); package names are intentionally not collected", *updates.PendingPackageCount))
		addFinding(snapshot, "linux-security-updates", "Maintenance", "Ubuntu security updates are available", "medium", fmt.Sprintf("Ubuntu reports %d pending security update(s).", count), "Review and apply security updates through the server's normal maintenance process, then confirm that HAVEN reports no pending security packages.")
	} else if *updates.PendingPackageCount > 0 {
		count := *updates.PendingPackageCount
		addCheck(snapshot, "linux-updates", "Maintenance", "Ubuntu updates", "configured", fmt.Sprintf("%d routine package update(s) are available and none are classified as security updates.", count), "Package names are intentionally not collected")
	} else {
		addCheck(snapshot, "linux-updates", "Maintenance", "Ubuntu updates", "pass", "Ubuntu reports no pending package updates.", "apt update-notifier")
	}

	if updates.PendingReboot == nil {
		addCheck(snapshot, "linux-reboot", "Maintenance", "Restart state", "unknown", "Pending-restart state could not be verified.", "")
	} else if *updates.PendingReboot {
		addCheck(snapshot, "linux-reboot", "Maintenance", "Restart state", "attention", "Ubuntu reports that a restart is required to finish maintenance.", "/var/run/reboot-required is present")
		addFinding(snapshot, "linux-pending-reboot", "Maintenance", "The Ubuntu server needs a restart", "low", "Ubuntu reports a pending restart after package maintenance.", "Restart the server during a planned maintenance window after confirming that its hosted applications can be interrupted safely.")
	} else {
		addCheck(snapshot, "linux-reboot", "Maintenance", "Restart state", "pass", "Ubuntu does not report a pending restart.", "No reboot-required marker")
	}
}

func evaluateLinuxFirewall(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.Firewall == nil || snapshot.LinuxBaseline.Firewall.Active == nil {
		addCheck(snapshot, "linux-firewall", "Network", "Host firewall", "unknown", "The Linux host firewall state could not be verified.", "")
		return
	}
	firewall := snapshot.LinuxBaseline.Firewall
	provider := fallback(strings.ToUpper(firewall.Provider), "Linux firewall")
	if !*firewall.Active {
		addCheck(snapshot, "linux-firewall", "Network", "Host firewall", "attention", provider+" is not enabled on the host.", "A router boundary or container rules do not replace an explicit host policy")
		addFinding(snapshot, "linux-firewall-disabled", "Network", "The Ubuntu host firewall is disabled", "medium", provider+" is installed but not enabled, so host-level inbound policy is not being enforced by that provider.", "Inventory the server's required LAN and VPN services, then enable a default-deny host firewall with explicit allow rules. Verify Docker networking separately before applying changes.")
		return
	}
	evidence := provider + " active"
	if firewall.DefaultInboundAction != "" {
		evidence += "; inbound default " + strings.ToLower(firewall.DefaultInboundAction)
	}
	addCheck(snapshot, "linux-firewall", "Network", "Host firewall", "pass", provider+" is enabled.", evidence)
}

func evaluateLinuxSSH(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.SSH == nil || snapshot.LinuxBaseline.SSH.ServerRunning == nil {
		addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "unknown", "The OpenSSH service state could not be verified.", "")
		return
	}
	ssh := snapshot.LinuxBaseline.SSH
	if !*ssh.ServerRunning {
		addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "pass", "The OpenSSH server is not running.", "No SSH listener expected")
		return
	}
	rootLogin := strings.ToLower(ssh.PermitRootLogin)
	passwordAuthentication := strings.ToLower(ssh.PasswordAuthentication)
	keyboardInteractiveAuthentication := strings.ToLower(ssh.KeyboardInteractiveAuthentication)
	if rootLogin == "yes" {
		addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "attention", "SSH permits direct root login.", "permitrootlogin yes")
		addFinding(snapshot, "linux-ssh-root-login", "Remote access", "SSH permits direct root login", "high", "The SSH daemon reports that direct root login is permitted.", "Disable direct root login, use an accountable non-root administrator, and elevate only when required.")
		return
	}
	if passwordAuthentication == "yes" || keyboardInteractiveAuthentication == "yes" {
		addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "attention", "SSH password-capable authentication is enabled.", "Password authentication "+fallback(passwordAuthentication, "not verified")+"; keyboard-interactive "+fallback(keyboardInteractiveAuthentication, "not verified")+"; public-key authentication "+fallback(ssh.PublicKeyAuthentication, "not verified"))
		addFinding(snapshot, "linux-ssh-passwords", "Remote access", "SSH password-capable authentication is enabled", "medium", "The SSH daemon accepts password or keyboard-interactive authentication in addition to any configured keys.", "Confirm that key-based access works, then disable password and keyboard-interactive authentication while retaining a tested recovery path.")
		return
	}
	if passwordAuthentication == "" || keyboardInteractiveAuthentication == "" || rootLogin == "" {
		addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "unknown", "SSH is running, but all effective authentication settings could not be verified without additional read-only privilege.", "No usernames, keys, or login source addresses are collected")
		return
	}
	evidence := "Password authentication " + passwordAuthentication + "; keyboard-interactive " + keyboardInteractiveAuthentication + "; root login " + rootLogin
	if ssh.FailedLoginCount24Hours != nil {
		evidence += fmt.Sprintf("; %d failed login event(s) in 24h", *ssh.FailedLoginCount24Hours)
	}
	addCheck(snapshot, "linux-ssh", "Remote access", "OpenSSH", "configured", "SSH is running with password authentication disabled and direct root password access restricted.", evidence)
}

func evaluateLinuxAutomaticUpdates(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.AutomaticUpdates == nil || snapshot.LinuxBaseline.AutomaticUpdates.Enabled == nil {
		addCheck(snapshot, "linux-automatic-updates", "Maintenance", "Automatic security updates", "unknown", "The unattended-upgrades configuration could not be verified.", "")
		return
	}
	status := snapshot.LinuxBaseline.AutomaticUpdates
	if !*status.Enabled {
		addCheck(snapshot, "linux-automatic-updates", "Maintenance", "Automatic security updates", "attention", "The unattended-upgrades service is not enabled.", "")
		addFinding(snapshot, "linux-automatic-updates", "Maintenance", "Automatic Ubuntu updates are disabled", "medium", "The unattended-upgrades service is not enabled.", "Enable and review unattended-upgrades so important security patches are applied within an acceptable maintenance window.")
		return
	}
	evidence := "Enabled"
	if status.Active != nil {
		evidence += fmt.Sprintf("; service active: %t", *status.Active)
	}
	addCheck(snapshot, "linux-automatic-updates", "Maintenance", "Automatic security updates", "pass", "The unattended-upgrades service is enabled.", evidence)
}

func evaluateLinuxAppArmor(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.AppArmor == nil || snapshot.LinuxBaseline.AppArmor.Enabled == nil {
		addCheck(snapshot, "linux-apparmor", "Platform", "AppArmor", "unknown", "AppArmor enforcement could not be verified.", "")
		return
	}
	if !*snapshot.LinuxBaseline.AppArmor.Enabled {
		addCheck(snapshot, "linux-apparmor", "Platform", "AppArmor", "attention", "AppArmor is not enabled.", "")
		addFinding(snapshot, "linux-apparmor", "Platform", "AppArmor is disabled", "medium", "Ubuntu is not reporting its mandatory access-control framework as enabled.", "Review why AppArmor is disabled and restore it unless another deliberate mandatory access-control policy replaces it.")
		return
	}
	addCheck(snapshot, "linux-apparmor", "Platform", "AppArmor", "pass", "AppArmor is enabled.", "Kernel enforcement available")
}

func evaluateLinuxTimeSync(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.TimeSync == nil || snapshot.LinuxBaseline.TimeSync.Synchronized == nil {
		addCheck(snapshot, "linux-time", "Platform", "Time synchronization", "unknown", "Network time synchronization could not be verified.", "")
		return
	}
	if !*snapshot.LinuxBaseline.TimeSync.Synchronized {
		addCheck(snapshot, "linux-time", "Platform", "Time synchronization", "attention", "The server clock is not synchronized.", "")
		addFinding(snapshot, "linux-time", "Platform", "The Ubuntu clock is not synchronized", "medium", "Reliable timestamps are important for certificates, logs, updates, and authentication.", "Restore a trusted network time source and confirm that timedatectl reports synchronization.")
		return
	}
	addCheck(snapshot, "linux-time", "Platform", "Time synchronization", "pass", "The server clock is synchronized.", "timedatectl reports NTPSynchronized=yes")
}

func evaluateLinuxServices(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.Services == nil || snapshot.LinuxBaseline.Services.FailedUnitCount == nil {
		addCheck(snapshot, "linux-services", "Reliability", "Failed system services", "unknown", "Failed system-service count could not be verified.", "")
		return
	}
	count := *snapshot.LinuxBaseline.Services.FailedUnitCount
	if count > 0 {
		failedUnits := snapshot.LinuxBaseline.Services.FailedUnits
		evidence := "No unit names were returned"
		summary := fmt.Sprintf("systemd reports %d failed unit(s).", count)
		if len(failedUnits) > 0 {
			evidence = "Failed: " + strings.Join(failedUnits, ", ")
			summary += " Failed: " + strings.Join(failedUnits, ", ") + "."
		}
		addCheck(snapshot, "linux-services", "Reliability", "Failed system services", "attention", fmt.Sprintf("systemd reports %d failed unit(s).", count), evidence)
		addFinding(snapshot, "linux-failed-services", "Reliability", "Ubuntu has failed system services", "low", summary, "Review the named unit, then repair it or deliberately disable obsolete services. HAVEN does not collect journal contents.")
		return
	}
	addCheck(snapshot, "linux-services", "Reliability", "Failed system services", "pass", "systemd reports no failed units.", "0 failed units")
}

func evaluateLinuxStorage(snapshot *model.SecuritySnapshot) {
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.Storage == nil || snapshot.LinuxBaseline.Storage.UsedPercentage == nil {
		addCheck(snapshot, "linux-storage", "Reliability", "Root filesystem capacity", "unknown", "Root filesystem capacity could not be verified.", "")
		return
	}
	storage := snapshot.LinuxBaseline.Storage
	used := *storage.UsedPercentage
	evidence := fmt.Sprintf("%.0f%% used on %s", used, fallback(storage.MountPoint, "/"))
	if used >= 95 {
		addCheck(snapshot, "linux-storage", "Reliability", "Root filesystem capacity", "attention", "The root filesystem is critically full.", evidence)
		addFinding(snapshot, "linux-storage-critical", "Reliability", "Ubuntu storage is critically full", "high", evidence+".", "Free space immediately and identify unexpected growth before services or databases fail.")
		return
	}
	if used >= 85 {
		addCheck(snapshot, "linux-storage", "Reliability", "Root filesystem capacity", "attention", "The root filesystem is running low on free space.", evidence)
		addFinding(snapshot, "linux-storage-low", "Reliability", "Ubuntu storage is running low", "medium", evidence+".", "Review application data, container images, logs, and backup retention before the filesystem reaches a critical threshold.")
		return
	}
	addCheck(snapshot, "linux-storage", "Reliability", "Root filesystem capacity", "pass", "The root filesystem has reasonable free capacity.", evidence)
}

func evaluateDefender(snapshot *model.SecuritySnapshot, now time.Time) {
	defender := snapshot.Defender
	if defender == nil || defender.AntivirusEnabled == nil || defender.RealTimeProtectionEnabled == nil {
		addCheck(snapshot, "defender", "Protection", "Microsoft Defender", "unknown", "Defender protection state could not be verified.", "")
		return
	}
	if !*defender.AntivirusEnabled || !*defender.RealTimeProtectionEnabled {
		addCheck(snapshot, "defender", "Protection", "Microsoft Defender", "attention", "Antivirus or real-time protection is turned off.", "Defender protection is incomplete")
		addFinding(snapshot, "defender-disabled", "Protection", "Defender protection is incomplete", "high", "Antivirus or real-time monitoring is disabled.", "Open Windows Security and restore the disabled protection unless another trusted antivirus intentionally manages it.")
		return
	}
	if defender.TamperProtected != nil && !*defender.TamperProtected {
		addCheck(snapshot, "defender", "Protection", "Microsoft Defender", "attention", "Core protection is active, but tamper protection is off.", "Tamper protection off")
		addFinding(snapshot, "tamper-protection", "Protection", "Tamper protection is off", "medium", "Security settings may be easier for malware or another local process to change.", "Review Tamper Protection in Windows Security and enable it when compatible with your management setup.")
		return
	}
	if defender.SignatureUpdatedAt != nil && now.Sub(defender.SignatureUpdatedAt.UTC()) > 3*24*time.Hour {
		age := humanAge(now.Sub(defender.SignatureUpdatedAt.UTC()))
		addCheck(snapshot, "defender", "Protection", "Microsoft Defender", "attention", "Protection is active, but security intelligence appears old.", age+" since the last reported update")
		addFinding(snapshot, "defender-signatures", "Protection", "Defender security intelligence may be stale", "medium", "The last reported intelligence update was "+age+" ago.", "Check Windows Update and the Protection updates page in Windows Security.")
		return
	}
	addCheck(snapshot, "defender", "Protection", "Microsoft Defender", "pass", "Antivirus, real-time monitoring, and available tamper signals look healthy.", "Real-time protection on")
}

func evaluateFirewall(snapshot *model.SecuritySnapshot) {
	if len(snapshot.FirewallProfiles) == 0 {
		addCheck(snapshot, "firewall", "Network", "Windows Firewall", "unknown", "Firewall profiles could not be verified.", "")
		return
	}
	unknown := false
	for _, profile := range snapshot.FirewallProfiles {
		if profile.Enabled == nil {
			unknown = true
			continue
		}
		if !*profile.Enabled {
			addCheck(snapshot, "firewall", "Network", "Windows Firewall", "attention", profile.Name+" firewall is turned off.", profile.Name+" profile disabled")
			addFinding(snapshot, "firewall-disabled", "Network", "A Windows Firewall profile is disabled", "high", "The "+profile.Name+" network profile is not protected by Windows Firewall.", "Open Windows Security, confirm the active network profile, and restore the firewall unless another reviewed control replaces it.")
			return
		}
	}
	if unknown {
		addCheck(snapshot, "firewall", "Network", "Windows Firewall", "unknown", "Some firewall profile states could not be verified.", "")
		return
	}
	addCheck(snapshot, "firewall", "Network", "Windows Firewall", "pass", "Every reported Windows Firewall profile is enabled.", fmt.Sprintf("%d profiles enabled", len(snapshot.FirewallProfiles)))
}

func evaluateUpdate(snapshot *model.SecuritySnapshot, now time.Time) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.Update == nil {
		addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "unknown", "Recent update and restart state could not be verified.", "")
		return
	}
	update := snapshot.WindowsBaseline.Update
	pendingFileReplacement := update.PendingFileReplacement != nil && *update.PendingFileReplacement
	authoritativeReasons := make([]string, 0, len(update.RebootReasons))
	for _, reason := range update.RebootReasons {
		if strings.EqualFold(strings.TrimSpace(reason), "Pending file replacement") {
			pendingFileReplacement = true
			continue
		}
		authoritativeReasons = append(authoritativeReasons, reason)
	}
	authoritativeReboot := update.PendingReboot != nil && *update.PendingReboot && (len(update.RebootReasons) == 0 || len(authoritativeReasons) > 0)
	if authoritativeReboot {
		reason := "Windows has pending work normally completed by a restart"
		if len(authoritativeReasons) > 0 {
			reason = strings.Join(authoritativeReasons, ", ")
		}
		addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "attention", "A system restart may be needed to finish pending work.", reason)
		addFinding(snapshot, "pending-reboot", "Maintenance", "A system restart may be pending", "low", reason+" was reported. This does not necessarily mean Windows Update itself requires a restart.", "Save your work and restart Windows at a convenient time if this pending state is unexpected or persists.")
		return
	}
	if update.LastInstalledAt == nil {
		addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "unknown", "HAVEN could not find a dated installed update.", "")
		return
	}
	age := now.Sub(update.LastInstalledAt.UTC())
	if age > updateFreshnessWindow {
		ageLabel := humanAge(age)
		addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "attention", "The most recently reported installed update is older than 45 days.", ageLabel+" since last installed update")
		addFinding(snapshot, "updates-stale", "Maintenance", "Windows updates may be overdue", "medium", "The latest dated installed update reported by Windows was "+ageLabel+" ago.", "Open Windows Update, check for updates, and verify that quality updates are installing successfully.")
		return
	}
	if pendingFileReplacement {
		addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "configured", "Windows Update and component servicing do not require a restart. An application has queued file cleanup for a future restart.", "Pending file replacement (informational)")
		return
	}
	addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "pass", "A dated Windows update was installed within the last 45 days and no restart is pending.", update.LastInstalledAt.Local().Format("Jan 2, 2006"))
}

func evaluateEncryption(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.SystemEncryption == nil {
		addCheck(snapshot, "encryption", "Data", "System drive encryption", "unknown", "System-drive encryption could not be verified.", "")
		return
	}
	encryption := snapshot.WindowsBaseline.SystemEncryption
	if !strings.EqualFold(encryption.ProtectionStatus, "On") {
		addCheck(snapshot, "encryption", "Data at rest", "System drive encryption", "configured", "BitLocker is off. This affects data at rest after physical loss; HAVEN does not treat it as a network or malware-protection alert.", fallback(encryption.ProtectionStatus, "Off"))
		return
	}
	addCheck(snapshot, "encryption", "Data", "System drive encryption", "pass", "BitLocker protection is on for the system drive.", fallback(encryption.VolumeStatus, "Protected"))
}

func evaluatePlatform(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.PlatformSecurity == nil {
		addCheck(snapshot, "secure-boot", "Platform", "Secure Boot", "unknown", "Secure Boot state could not be verified.", "")
		addCheck(snapshot, "tpm", "Platform", "Trusted Platform Module", "unknown", "TPM state could not be verified.", "")
		return
	}
	platform := snapshot.WindowsBaseline.PlatformSecurity
	if platform.SecureBootEnabled == nil {
		addCheck(snapshot, "secure-boot", "Platform", "Secure Boot", "unknown", "Secure Boot state could not be verified.", "")
	} else if !*platform.SecureBootEnabled {
		addCheck(snapshot, "secure-boot", "Platform", "Secure Boot", "attention", "Secure Boot is not enabled.", "Disabled")
		addFinding(snapshot, "secure-boot", "Platform", "Secure Boot is disabled", "medium", "Windows cannot verify the boot chain with Secure Boot.", "Review firmware compatibility and enable Secure Boot only after checking disk-encryption recovery requirements.")
	} else {
		addCheck(snapshot, "secure-boot", "Platform", "Secure Boot", "pass", "Secure Boot is enabled.", "Enabled")
	}

	if platform.TPMPresent == nil || platform.TPMReady == nil {
		addCheck(snapshot, "tpm", "Platform", "Trusted Platform Module", "unknown", "TPM state could not be verified.", "")
	} else if !*platform.TPMPresent || !*platform.TPMReady {
		addCheck(snapshot, "tpm", "Platform", "Trusted Platform Module", "attention", "A ready TPM was not reported.", "Not present or not ready")
		addFinding(snapshot, "tpm", "Platform", "TPM is unavailable or not ready", "low", "Windows is not reporting a ready Trusted Platform Module.", "Check firmware TPM settings and Windows Security before making firmware changes.")
	} else {
		evidence := []string{"Present and ready"}
		if platform.TPMVersion != "" {
			evidence = append(evidence, "TPM "+platform.TPMVersion)
		}
		if platform.TPMManufacturer != "" {
			evidence = append(evidence, platform.TPMManufacturer)
		}
		if platform.TPMSource != "" {
			evidence = append(evidence, "verified by "+platform.TPMSource)
		}
		addCheck(snapshot, "tpm", "Platform", "Trusted Platform Module", "pass", "A ready TPM is present.", strings.Join(evidence, "; "))
	}
}

func evaluateRemoteAccess(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.RemoteAccess == nil {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "unknown", "Remote access configuration could not be verified.", "")
		return
	}
	remote := snapshot.WindowsBaseline.RemoteAccess
	if remote.SMB1Enabled != nil && *remote.SMB1Enabled {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "attention", "The legacy SMB1 file-sharing protocol is enabled.", "SMB1 enabled")
		addFinding(snapshot, "smb1", "Network", "Legacy SMB1 is enabled", "high", "SMB1 is an obsolete file-sharing protocol with serious security limitations.", "Disable SMB1 after confirming that no required legacy device depends on it.")
		return
	}
	if remote.RemoteDesktopEnabled != nil && *remote.RemoteDesktopEnabled {
		if remote.NetworkLevelAuthRequired == nil {
			addCheck(snapshot, "remote-access", "Network", "Remote access", "unknown", "Remote Desktop is enabled, but its Network Level Authentication state could not be verified.", "RDP enabled; NLA unknown")
			addFinding(snapshot, "rdp-nla-unknown", "Network", "Verify Remote Desktop authentication", "low", "HAVEN could not confirm whether Remote Desktop requires Network Level Authentication.", "Open Remote Desktop settings and confirm that Network Level Authentication is required.")
			return
		}
		if !*remote.NetworkLevelAuthRequired {
			addCheck(snapshot, "remote-access", "Network", "Remote access", "attention", "Remote Desktop is enabled without required Network Level Authentication.", "RDP enabled; NLA not required")
			addFinding(snapshot, "rdp-nla", "Network", "Remote Desktop does not require NLA", "high", "Remote Desktop accepts connections before Network Level Authentication.", "Require Network Level Authentication or disable Remote Desktop if it is not needed.")
			return
		}
	}
	if remote.RemoteAssistanceEnabled != nil && *remote.RemoteAssistanceEnabled {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "attention", "Windows Remote Assistance is enabled.", "Remote Assistance enabled")
		addFinding(snapshot, "remote-assistance", "Network", "Remote Assistance is enabled", "low", "This computer permits Remote Assistance invitations.", "Disable Remote Assistance if you do not use it, or review who can initiate and approve sessions.")
		return
	}
	if remote.RemoteDesktopEnabled != nil && *remote.RemoteDesktopEnabled {
		ruleEvidence := "RDP enabled; NLA required"
		if remote.RDPFirewallRuleCount != nil {
			ruleEvidence = fmt.Sprintf("%s; %d applicable inbound allow rule(s)", ruleEvidence, *remote.RDPFirewallRuleCount)
		}
		if remote.OpenSSHServerRunning != nil && *remote.OpenSSHServerRunning {
			ruleEvidence += "; OpenSSH running"
		}
		switch remote.RDPFirewallScope {
		case "restricted":
			addCheck(snapshot, "remote-access", "Network", "Remote access", "configured", "Remote Desktop is enabled with NLA, and its inbound firewall access is limited by remote-address or interface scope.", ruleEvidence+"; scope restricted")
		case "blocked":
			addCheck(snapshot, "remote-access", "Network", "Remote access", "configured", "Remote Desktop is enabled with NLA, but HAVEN found no active inbound firewall rule that permits it.", ruleEvidence+"; inbound blocked")
		case "unrestricted":
			addCheck(snapshot, "remote-access", "Network", "Remote access", "attention", "Remote Desktop requires NLA, but at least one applicable inbound firewall rule has no remote-address or interface restriction.", ruleEvidence+"; unrestricted rule detected")
			addFinding(snapshot, "rdp-firewall-scope", "Network", "Review Remote Desktop firewall scope", "medium", "An active inbound firewall rule may allow RDP without a remote-address or interface boundary.", "Restrict RDP to a trusted VPN subnet or interface and avoid forwarding TCP or UDP 3389 directly from the internet.")
		default:
			addCheck(snapshot, "remote-access", "Network", "Remote access", "unknown", "Remote Desktop is enabled with NLA, but its inbound firewall scope could not be verified.", ruleEvidence+"; firewall scope unknown")
			addFinding(snapshot, "rdp-firewall-unknown", "Network", "Verify Remote Desktop firewall scope", "low", "HAVEN could not determine which inbound firewall boundaries protect RDP.", "Review enabled Remote Desktop firewall rules and restrict them to a trusted VPN subnet or interface.")
		}
		return
	}
	if remote.OpenSSHServerRunning != nil && *remote.OpenSSHServerRunning {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "configured", "OpenSSH is running as a remote-administration service. Service presence alone is not treated as a threat.", "sshd running; evaluate authentication and firewall boundaries separately")
		return
	}
	if remote.RemoteDesktopEnabled == nil || remote.RemoteAssistanceEnabled == nil || remote.SMB1Enabled == nil || remote.OpenSSHServerRunning == nil {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "unknown", "Some remote-access settings could not be verified.", "")
		return
	}
	addCheck(snapshot, "remote-access", "Network", "Remote access", "pass", "RDP, Remote Assistance, SMB1, and OpenSSH server are not reported as enabled.", "No reviewed service enabled")
}

func evaluateLocalAccounts(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.LocalAccounts == nil || snapshot.WindowsBaseline.LocalAccounts.AdministratorCount == nil {
		addCheck(snapshot, "local-admins", "Identity", "Local administrators", "unknown", "Local administrator membership count could not be verified.", "")
		return
	}
	accounts := snapshot.WindowsBaseline.LocalAccounts
	totalCount := *accounts.AdministratorCount
	if accounts.EnabledAdministratorCount == nil {
		addCheck(snapshot, "local-admins", "Identity", "Local administrators", "unknown", "HAVEN counted administrator memberships but could not verify which accounts are enabled.", fmt.Sprintf("%d total; names are intentionally not collected", totalCount))
		return
	}
	enabledCount := *accounts.EnabledAdministratorCount
	evidence := fmt.Sprintf("%d enabled of %d total; names are intentionally not collected", enabledCount, totalCount)
	if enabledCount > 2 {
		addCheck(snapshot, "local-admins", "Identity", "Local administrators", "attention", fmt.Sprintf("%d enabled principals have local administrator membership.", enabledCount), evidence)
		addFinding(snapshot, "local-admins", "Identity", "Review local administrator access", "low", fmt.Sprintf("HAVEN counted %d enabled local administrator principals without collecting their names.", enabledCount), "Open Computer Management and confirm that every enabled administrator entry is expected and still required.")
		return
	}
	addCheck(snapshot, "local-admins", "Identity", "Local administrators", "pass", fmt.Sprintf("%d enabled local administrator principal(s) reported.", enabledCount), evidence)
}

func evaluateThreats(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.Threats == nil || snapshot.WindowsBaseline.Threats.ActiveThreatCount == nil || snapshot.WindowsBaseline.Threats.RecentDetectionCount == nil {
		addCheck(snapshot, "threats", "Protection", "Defender detections", "unknown", "Defender threat counts could not be verified.", "")
		return
	}
	threats := snapshot.WindowsBaseline.Threats
	if *threats.ActiveThreatCount > 0 {
		addCheck(snapshot, "threats", "Protection", "Defender detections", "attention", fmt.Sprintf("Defender reports %d active threat(s).", *threats.ActiveThreatCount), "Resource paths are intentionally not collected")
		addFinding(snapshot, "active-threats", "Protection", "Microsoft Defender reports active threats", "high", fmt.Sprintf("Defender reports %d threat(s) that are still active.", *threats.ActiveThreatCount), "Open Protection history in Windows Security, review the affected item, and follow Microsoft's remediation guidance.")
		return
	}
	if *threats.RecentDetectionCount > 0 {
		addCheck(snapshot, "threats", "Protection", "Defender detections", "attention", fmt.Sprintf("Defender recorded %d detection(s) in the last 30 days; none are reported active.", *threats.RecentDetectionCount), "Resource paths are intentionally not collected")
		addFinding(snapshot, "recent-threats", "Protection", "Review recent Defender detections", "low", fmt.Sprintf("Defender recorded %d detection(s) in the last 30 days and reports none as active.", *threats.RecentDetectionCount), "Review Protection history to confirm the detections were expected and remediated.")
		return
	}
	addCheck(snapshot, "threats", "Protection", "Defender detections", "pass", "Defender reports no active threats or detections in the last 30 days.", "Paths and threat names are not collected")
}

func addCheck(snapshot *model.SecuritySnapshot, id, category, title, status, summary, evidence string) {
	snapshot.BaselineChecks = append(snapshot.BaselineChecks, model.BaselineCheck{ID: id, Category: category, Title: title, Status: status, Summary: summary, Evidence: evidence})
}

func addFinding(snapshot *model.SecuritySnapshot, id, category, title, severity, summary, recommendation string) {
	snapshot.Findings = append(snapshot.Findings, model.SecurityFinding{ID: id, Category: category, Title: title, Severity: severity, Summary: summary, Recommendation: recommendation})
}

func humanAge(duration time.Duration) string {
	days := int(duration.Hours() / 24)
	if days < 1 {
		return "less than a day"
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

func fallback(value, alternative string) string {
	if strings.TrimSpace(value) == "" {
		return alternative
	}
	return value
}
