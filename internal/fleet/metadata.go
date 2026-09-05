// Package fleet owns the public, server-derived lifecycle classification for
// enrolled HAVEN agents. It never turns build drift into a security alert.
package fleet

import (
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/AdamWentworth/haven/internal/buildinfo"
	"github.com/AdamWentworth/haven/internal/model"
)

const (
	CompatibilityCurrent       = "current"
	CompatibilityDevelopment   = "development"
	CompatibilityVersionDrift  = "version-drift"
	CompatibilityRevisionDrift = "revision-drift"
)

var tokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// MetadataForSnapshot creates privacy-bounded evidence for an observation.
// Capabilities describe the evidence present in this report, rather than
// promising that every collector will succeed forever.
func MetadataForSnapshot(snapshot model.SecuritySnapshot, installation string) model.AgentMetadata {
	capabilities := []string{"network-observation"}
	if len(snapshot.FirewallProfiles) > 0 {
		capabilities = append(capabilities, "host-firewall")
	}
	if snapshot.Defender != nil {
		capabilities = append(capabilities, "windows-defender")
	}
	if snapshot.WindowsBaseline != nil {
		capabilities = append(capabilities, "windows-posture")
	}
	if snapshot.BrowserSecurity != nil && snapshot.BrowserSecurity.Coverage != "unavailable" {
		capabilities = append(capabilities, "browser-inventory")
	}
	if snapshot.BrowserSecurity != nil && len(snapshot.BrowserSecurity.Protections) > 0 {
		capabilities = append(capabilities, "web-protection")
	}
	if snapshot.LinuxBaseline != nil {
		capabilities = append(capabilities, "linux-posture", "systemd-attribution")
		if snapshot.LinuxBaseline.Workloads != nil {
			capabilities = append(capabilities, "docker-attribution")
		}
	}
	sort.Strings(capabilities)
	installation = strings.ToLower(strings.TrimSpace(installation))
	if !tokenPattern.MatchString(installation) || len(installation) > 40 {
		installation = "interactive"
	}
	return model.AgentMetadata{
		SchemaVersion:     model.ObservationSchemaVersion,
		Version:           buildinfo.Version,
		Revision:          buildinfo.Revision,
		Platform:          runtime.GOOS,
		Installation:      installation,
		Capabilities:      capabilities,
		CollectionNotices: len(snapshot.Notices),
	}
}

// ValidateMetadata prevents an authenticated but faulty endpoint from placing
// unbounded or ambiguous strings in the fleet inventory.
func ValidateMetadata(metadata *model.AgentMetadata) bool {
	if metadata == nil {
		return true
	}
	if metadata.SchemaVersion != model.ObservationSchemaVersion || len(metadata.Version) < 1 || len(metadata.Version) > 32 || len(metadata.Revision) < 1 || len(metadata.Revision) > 64 || metadata.CollectionNotices < 0 || metadata.CollectionNotices > 100 {
		return false
	}
	if !tokenPattern.MatchString(metadata.Platform) || len(metadata.Platform) > 20 || !tokenPattern.MatchString(metadata.Installation) || len(metadata.Installation) > 40 || len(metadata.Capabilities) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(metadata.Capabilities))
	for _, capability := range metadata.Capabilities {
		if len(capability) > 40 || !tokenPattern.MatchString(capability) {
			return false
		}
		if _, exists := seen[capability]; exists {
			return false
		}
		seen[capability] = struct{}{}
	}
	return true
}

// Present adds the hub-owned lifecycle interpretation to stored agent facts.
func Present(device model.DeviceRecord) model.DeviceRecord {
	if device.Agent == nil {
		return device
	}
	presented := *device.Agent
	presented.Capabilities = append([]string(nil), device.Agent.Capabilities...)
	presented.Compatibility = classify(presented)
	device.Agent = &presented
	return device
}

func classify(agent model.AgentMetadata) string {
	if agent.Version != buildinfo.Version {
		return CompatibilityVersionDrift
	}
	if agent.Revision == "development" || buildinfo.Revision == "development" {
		return CompatibilityDevelopment
	}
	if agent.Revision != buildinfo.Revision {
		return CompatibilityRevisionDrift
	}
	return CompatibilityCurrent
}
