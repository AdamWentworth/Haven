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
	if !strings.Contains(strings.ToLower(snapshot.Device.OperatingSystem), "windows") {
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
	if update.PendingReboot != nil && *update.PendingReboot {
		reason := "Windows has pending work normally completed by a restart"
		if len(update.RebootReasons) > 0 {
			reason = strings.Join(update.RebootReasons, ", ")
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
	addCheck(snapshot, "updates", "Maintenance", "Windows servicing", "pass", "A dated Windows update was installed within the last 45 days and no restart is pending.", update.LastInstalledAt.Local().Format("Jan 2, 2006"))
}

func evaluateEncryption(snapshot *model.SecuritySnapshot) {
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.SystemEncryption == nil {
		addCheck(snapshot, "encryption", "Data", "System drive encryption", "unknown", "System-drive encryption could not be verified.", "")
		return
	}
	encryption := snapshot.WindowsBaseline.SystemEncryption
	if !strings.EqualFold(encryption.ProtectionStatus, "On") {
		addCheck(snapshot, "encryption", "Data", "System drive encryption", "attention", "BitLocker protection is not reported as on for the system drive.", encryption.ProtectionStatus)
		addFinding(snapshot, "drive-encryption", "Data", "System-drive encryption is not protected", "medium", "BitLocker protection for "+encryption.SystemDrive+" is reported as "+fallback(encryption.ProtectionStatus, "unknown")+".", "Review Device Encryption or BitLocker settings and protect the system drive after confirming that a recovery key is stored safely.")
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
	if remote.OpenSSHServerRunning != nil && *remote.OpenSSHServerRunning {
		addCheck(snapshot, "remote-access", "Network", "Remote access", "attention", "The OpenSSH server is running.", "sshd running")
		addFinding(snapshot, "openssh-running", "Network", "OpenSSH server is running", "low", "This computer is accepting SSH connections.", "Confirm SSH is intentional, use key-based access, and restrict its firewall scope.")
		return
	}
	if remote.RemoteDesktopEnabled != nil && *remote.RemoteDesktopEnabled {
		ruleEvidence := "RDP enabled; NLA required"
		if remote.RDPFirewallRuleCount != nil {
			ruleEvidence = fmt.Sprintf("%s; %d applicable inbound allow rule(s)", ruleEvidence, *remote.RDPFirewallRuleCount)
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
