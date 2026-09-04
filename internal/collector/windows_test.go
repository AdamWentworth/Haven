package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubRunner struct {
	output []byte
	err    error
}

func (runner stubRunner) Run(context.Context, string) ([]byte, error) {
	return runner.output, runner.err
}

func TestWindowsCollectorMapsSnapshot(t *testing.T) {
	collector := NewWindowsCollector(stubRunner{output: []byte(`{
		"device":{"hostName":"test-device","operatingSystem":"Windows","architecture":"X64","uptimeSeconds":3600},
		"defender":{"antivirusEnabled":true,"realTimeProtectionEnabled":true,"tamperProtected":true,"signatureVersion":"1.2.3.4","signatureUpdatedAt":"2026-09-01T06:00:00Z","lastQuickScanAt":null,"lastFullScanAt":null},
		"windowsBaseline":{"update":{"lastInstalledAt":"2026-08-20T06:00:00Z","pendingReboot":false},"systemEncryption":{"systemDrive":"C:","volumeStatus":"FullyEncrypted","protectionStatus":"On","encryptionPercentage":100},"platformSecurity":{"secureBootEnabled":true,"tpmPresent":true,"tpmReady":true,"tpmVersion":"2.0","tpmManufacturer":"Example","tpmSource":"Windows TPM Tool"},"remoteAccess":{"remoteDesktopEnabled":false,"networkLevelAuthRequired":true,"rdpFirewallScope":"blocked","rdpFirewallRuleCount":0,"remoteAssistanceEnabled":false,"smb1Enabled":false,"openSshServerRunning":false},"localAccounts":{"administratorCount":3,"enabledAdministratorCount":2},"threats":{"activeThreatCount":0,"recentDetectionCount":0,"lastDetectedAt":null}},
		"firewallProfiles":[{"name":"Private","enabled":true,"defaultInboundAction":"Block","defaultOutboundAction":"Allow"}],
		"connections":[{"protocol":"TCP","localAddress":"127.0.0.1","localPort":5080,"remoteAddress":"0.0.0.0","remotePort":0,"state":"Listen","processId":42,"processName":"haven"}],
		"notices":[]
	}`)})

	snapshot := collector.Collect(context.Background())

	if snapshot.Device.HostName != "test-device" {
		t.Fatalf("unexpected device name: %q", snapshot.Device.HostName)
	}
	if snapshot.Defender == nil || snapshot.Defender.AntivirusEnabled == nil || !*snapshot.Defender.AntivirusEnabled {
		t.Fatal("expected antivirus to be enabled")
	}
	if len(snapshot.FirewallProfiles) != 1 || snapshot.FirewallProfiles[0].Enabled == nil || !*snapshot.FirewallProfiles[0].Enabled {
		t.Fatal("expected enabled private firewall profile")
	}
	if len(snapshot.Connections) != 1 || snapshot.Connections[0].ProcessName != "haven" {
		t.Fatal("expected mapped network connection")
	}
	if snapshot.WindowsBaseline == nil || snapshot.WindowsBaseline.SystemEncryption == nil || snapshot.WindowsBaseline.SystemEncryption.ProtectionStatus != "On" {
		t.Fatal("expected mapped Windows baseline")
	}
	if snapshot.WindowsBaseline.PlatformSecurity.TPMVersion != "2.0" || snapshot.WindowsBaseline.PlatformSecurity.TPMSource != "Windows TPM Tool" {
		t.Fatal("expected mapped TPM evidence")
	}
	if snapshot.WindowsBaseline.RemoteAccess.RDPFirewallScope != "blocked" || snapshot.WindowsBaseline.RemoteAccess.RDPFirewallRuleCount == nil || *snapshot.WindowsBaseline.RemoteAccess.RDPFirewallRuleCount != 0 {
		t.Fatal("expected mapped RDP firewall evidence")
	}
	if len(snapshot.Notices) != 0 {
		t.Fatalf("expected no notices, got %d", len(snapshot.Notices))
	}
}

func TestWindowsSnapshotScriptUsesReadOnlyTPMAndFirewallFallbacks(t *testing.T) {
	for _, expected := range []string{
		"tpmtool.exe",
		"getdeviceinformation",
		"FirewallPolicy\\FirewallRules",
		"RdpFirewallScope",
	} {
		if !strings.Contains(windowsSnapshotScript, expected) {
			t.Fatalf("Windows snapshot script is missing %q", expected)
		}
	}
}

func TestWindowsSnapshotScriptSeparatesAuthoritativeRebootSignalsFromFileCleanup(t *testing.T) {
	for _, expected := range []string{
		"PendingFileRenameOperations",
		"PendingFileReplacement = [bool]$pendingFileReplacement",
		"PendingReboot = [bool]($rebootReasons.Count -gt 0)",
	} {
		if !strings.Contains(windowsSnapshotScript, expected) {
			t.Fatalf("Windows snapshot script is missing %q", expected)
		}
	}
	if strings.Contains(windowsSnapshotScript, "$rebootReasons.Add('Pending file replacement')") {
		t.Fatal("generic pending file replacements must not be classified as an authoritative restart requirement")
	}
}

func TestWindowsCollectorReportsRunnerFailure(t *testing.T) {
	collector := NewWindowsCollector(stubRunner{err: errors.New("access denied")})

	snapshot := collector.Collect(context.Background())

	if snapshot.Defender != nil {
		t.Fatal("expected defender status to be unavailable")
	}
	if len(snapshot.Notices) != 1 || snapshot.Notices[0].Source != "Windows collector" {
		t.Fatalf("expected a Windows collector notice, got %#v", snapshot.Notices)
	}
}

func TestWindowsCollectorReportsMalformedData(t *testing.T) {
	collector := NewWindowsCollector(stubRunner{output: []byte("not-json")})

	snapshot := collector.Collect(context.Background())

	if len(snapshot.Notices) != 1 {
		t.Fatalf("expected one parse notice, got %d", len(snapshot.Notices))
	}
}
