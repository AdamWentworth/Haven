package fleet

import (
	"testing"

	"github.com/AdamWentworth/haven/internal/buildinfo"
	"github.com/AdamWentworth/haven/internal/model"
)

func TestMetadataUsesObservedCapabilitiesAndBoundsInstallation(t *testing.T) {
	enabled := true
	snapshot := model.SecuritySnapshot{
		Defender:         &model.DefenderStatus{},
		WindowsBaseline:  &model.WindowsBaseline{},
		FirewallProfiles: []model.FirewallProfileStatus{{Name: "Private", Enabled: &enabled}},
		BrowserSecurity:  &model.BrowserSecurityStatus{Coverage: "observed", Protections: []model.BrowserProtectionStatus{{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "enabled"}}},
		Notices:          []model.CollectorNotice{{Source: "test", Message: "limited"}},
	}
	metadata := MetadataForSnapshot(snapshot, "windows-task")
	if metadata.Version != buildinfo.Version || metadata.Installation != "windows-task" || metadata.CollectionNotices != 1 {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	if !ValidateMetadata(&metadata) {
		t.Fatal("generated metadata must pass validation")
	}
	if !containsCapability(metadata.Capabilities, "browser-inventory") || !containsCapability(metadata.Capabilities, "web-protection") {
		t.Fatalf("browser capabilities were not advertised: %#v", metadata.Capabilities)
	}
	metadata = MetadataForSnapshot(snapshot, "../../private/path")
	if metadata.Installation != "interactive" {
		t.Fatalf("unsafe installation label was retained: %#v", metadata)
	}
}

func containsCapability(capabilities []string, target string) bool {
	for _, capability := range capabilities {
		if capability == target {
			return true
		}
	}
	return false
}

func TestCompatibilityIsMaintenanceEvidenceNotDeviceStatus(t *testing.T) {
	legacy := Present(model.DeviceRecord{Status: "current"})
	if legacy.Agent != nil || legacy.Status != "current" {
		t.Fatalf("legacy metadata must not alter endpoint freshness: %#v", legacy)
	}

	device := model.DeviceRecord{Status: "current", Agent: &model.AgentMetadata{Version: buildinfo.Version, Revision: "development"}}
	presented := Present(device)
	if presented.Agent.Compatibility != CompatibilityDevelopment || presented.Status != "current" {
		t.Fatalf("build classification must remain separate from security freshness: %#v", presented)
	}

	device.Agent.Version = "0.13.0"
	if got := Present(device).Agent.Compatibility; got != CompatibilityCompatible {
		t.Fatalf("expected protocol-compatible release drift, got %q", got)
	}
}

func TestMetadataRejectsUnboundedOrDuplicateCapabilities(t *testing.T) {
	metadata := model.AgentMetadata{SchemaVersion: model.ObservationSchemaVersion, Version: buildinfo.Version, Revision: "development", Platform: "linux", Installation: "systemd-user", Capabilities: []string{"host-firewall", "host-firewall"}}
	if ValidateMetadata(&metadata) {
		t.Fatal("duplicate capabilities must be rejected")
	}
	metadata.Capabilities = []string{"host-firewall"}
	metadata.CollectionNotices = 101
	if ValidateMetadata(&metadata) {
		t.Fatal("unbounded notice counts must be rejected")
	}
}
