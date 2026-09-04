import { describe, expect, it } from "vitest";
import { capabilityLabel, fleetPresentation, fleetSummary } from "./fleet";
import type { DeviceRecord } from "./types";

function device(overrides: Partial<DeviceRecord> = {}): DeviceRecord {
	return {
		id: "device-a", displayName: "ADAM-TEST", hostName: "adam-test", operatingSystem: "Test OS", architecture: "amd64", trustState: "enrolled", status: "current", enrolledAt: "2026-09-01T00:00:00Z", lastSeenAt: "2026-09-04T08:00:00Z", lastCollectedAt: "2026-09-04T08:00:00Z", certificateExpiresAt: null, revokedAt: null,
		agent: { schemaVersion: 2, version: "0.14.0", revision: "abc", platform: "windows", installation: "windows-task", capabilities: ["host-firewall"], collectionNotices: 0, compatibility: "current" },
		...overrides,
	};
}

describe("fleet lifecycle", () => {
	it("keeps report freshness ahead of build maintenance", () => {
		expect(fleetPresentation(device({ status: "stale" })).state).toBe("overdue");
		expect(fleetPresentation(device({ agent: null })).state).toBe("legacy");
		expect(fleetPresentation(device({ agent: { ...device().agent!, compatibility: "version-drift" } })).state).toBe("version-drift");
	});

	it("summarizes reporting and maintenance without calling either a threat", () => {
		const summary = fleetSummary([device(), device({ id: "legacy", agent: null }), device({ id: "offline", status: "stale" }), device({ id: "revoked", status: "revoked", trustState: "revoked" })]);
		expect(summary).toEqual({ total: 3, reporting: 2, verified: 1, maintenance: 1, limited: 0 });
	});

	it("counts synthetic inventory without inventing build verification", () => {
		const summary = fleetSummary([device({ trustState: "synthetic", agent: null })]);
		expect(summary).toEqual({ total: 1, reporting: 1, verified: 0, maintenance: 0, limited: 0 });
	});

	it("formats stable capability identifiers", () => {
		expect(capabilityLabel("systemd-attribution")).toBe("systemd Attribution");
	});
});
