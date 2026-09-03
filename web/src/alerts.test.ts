import { describe, expect, it } from "vitest";
import { deriveCurrentAlerts } from "./alerts";
import type { NetworkDeviceObservation } from "./network";
import type { DeviceRecord, ExpectedService, NetworkConnection, SecurityEvent, SecurityFinding, SecuritySnapshot } from "./types";

const collectedAt = "2026-09-02T20:00:00Z";

function record(overrides: Partial<DeviceRecord> = {}): DeviceRecord {
  return { id: "device", displayName: "Test Device", hostName: "test", operatingSystem: "Test OS", architecture: "amd64", trustState: "enrolled", status: "current", enrolledAt: "2026-09-01T20:00:00Z", lastSeenAt: collectedAt, lastCollectedAt: collectedAt, certificateExpiresAt: null, revokedAt: null, ...overrides };
}

function listener(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
  return { protocol: "TCP", localAddress: "0.0.0.0", localPort: 443, remoteAddress: "", remotePort: 0, state: "Listen", processId: 10, processName: "caddy", ...overrides };
}

function snapshot(connections: NetworkConnection[] = [], findings: SecurityFinding[] = []): SecuritySnapshot {
  return { collectedAt, device: { deviceId: "device", hostName: "test", operatingSystem: "Test OS", architecture: "amd64", uptimeSeconds: 100 }, defender: null, windowsBaseline: null, linuxBaseline: null, baselineChecks: [], findings, firewallProfiles: [{ name: "Host", enabled: true }], connections, notices: [] };
}

function observation(overrides: Partial<NetworkDeviceObservation> = {}): NetworkDeviceObservation {
  return { device: record(), snapshot: snapshot(), expectedServices: [], listenerObservations: [], ...overrides };
}

function expected(overrides: Partial<ExpectedService> = {}): ExpectedService {
  return { id: "svc", deviceId: "device", label: "HTTPS", protocol: "TCP", port: 443, portEnd: 443, bindScope: "wildcard", processNames: ["caddy"], workloadNames: [], systemdUnits: [], createdAt: collectedAt, updatedAt: collectedAt, ...overrides };
}

describe("current alert derivation", () => {
  it("returns no alert for a current device matching its service baseline", () => {
    const current = observation({ snapshot: snapshot([listener()]), expectedServices: [expected()], listenerObservations: [{ deviceId: "device", protocol: "TCP", port: 443, bindScope: "wildcard", firstSeenAt: collectedAt, appearedAt: collectedAt, lastSeenAt: collectedAt, present: true }] });
    expect(deriveCurrentAlerts([current], [])).toEqual([]);
  });

  it("uses the current finding and its latest opened lifecycle timestamp", () => {
    const finding: SecurityFinding = { id: "firewall-off", category: "Network", title: "Host firewall is disabled", severity: "high", summary: "The verified firewall provider is inactive.", recommendation: "Restore the reviewed policy." };
    const opened: SecurityEvent = { id: 7, deviceId: "device", deviceName: "Test Device", findingId: finding.id, kind: "opened", category: finding.category, title: finding.title, severity: finding.severity, summary: finding.summary, occurredAt: "2026-09-02T19:00:00Z" };
    const alert = deriveCurrentAlerts([observation({ snapshot: snapshot([], [finding]) })], [opened])[0];
    expect(alert).toMatchObject({ kind: "finding", severity: "high", startedAt: opened.occurredAt, title: finding.title });
  });

  it("does not resurrect a resolved finding that is absent from current posture", () => {
    const resolved: SecurityEvent = { id: 8, deviceId: "device", deviceName: "Test Device", findingId: "old", kind: "resolved", category: "Network", title: "Old", severity: "medium", summary: "Resolved", occurredAt: collectedAt };
    expect(deriveCurrentAlerts([observation()], [resolved])).toEqual([]);
  });

  it("alerts when an authenticated agent exceeds the server freshness allowance", () => {
    const stale = observation({ device: record({ status: "stale", lastSeenAt: "2026-09-02T19:00:00Z" }), snapshot: null });
    const alert = deriveCurrentAlerts([stale], [], 20 * 60)[0];
    expect(alert).toMatchObject({ kind: "stale-agent", severity: "medium", startedAt: "2026-09-02T19:20:00.000Z" });
    expect(alert.summary).toContain("20-minute freshness allowance");
  });

  it("shows enrollment awaiting its first report without issuing a medium alert", () => {
    const awaiting = observation({ device: record({ status: "awaiting-first-report", lastSeenAt: null, lastCollectedAt: null }), snapshot: null });
    expect(deriveCurrentAlerts([awaiting], [])[0]).toMatchObject({ kind: "awaiting-agent", severity: "low" });
  });

  it("alerts on a new non-local listener but explicitly avoids an intrusion claim", () => {
    const current = observation({ snapshot: snapshot([listener()]), listenerObservations: [{ deviceId: "device", protocol: "TCP", port: 443, bindScope: "wildcard", firstSeenAt: collectedAt, appearedAt: collectedAt, lastSeenAt: collectedAt, present: true }] });
    const alert = deriveCurrentAlerts([current], [])[0];
    expect(alert).toMatchObject({ kind: "new-service", severity: "medium", startedAt: collectedAt });
    expect(alert.summary).toContain("not, by itself, evidence");
  });

  it("does not alert on an unclassified loopback-only listener", () => {
    expect(deriveCurrentAlerts([observation({ snapshot: snapshot([listener({ localAddress: "127.0.0.1" })]) })], [])).toEqual([]);
  });

  it("detects owner drift without claiming the expected port itself changed", () => {
    const drifted = observation({ snapshot: snapshot([listener({ processName: "unexpected" })]), expectedServices: [expected()], listenerObservations: [{ deviceId: "device", protocol: "TCP", port: 443, bindScope: "wildcard", firstSeenAt: collectedAt, appearedAt: collectedAt, lastSeenAt: collectedAt, present: true }] });
    const alert = deriveCurrentAlerts([drifted], [])[0];
    expect(alert).toMatchObject({ kind: "service-drift", severity: "medium" });
    expect(alert.title).toContain("Service attribution changed");
    expect(alert.evidence).toContain("process unexpected");
  });

  it("sorts high-severity posture ahead of medium service review", () => {
    const finding: SecurityFinding = { id: "threat", category: "Protection", title: "Threat", severity: "high", summary: "Active threat", recommendation: "Review" };
    const alerts = deriveCurrentAlerts([observation({ snapshot: snapshot([listener()], [finding]) })], []);
    expect(alerts.map((alert) => alert.kind)).toEqual(["finding", "new-service"]);
  });
});
