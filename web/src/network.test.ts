import { describe, expect, it } from "vitest";
import serviceExpectationCases from "../../testdata/service_expectation_cases.json";
import { bindScopeLabel, canonicalOwnerName, endpoint, endpointBindScope, endpointScope, expectedServiceMatches, expectedServiceOwnerConstrained, isLoopbackAddress, isMulticastAddress, isPrivateNetworkAddress, isUnspecifiedAddress, listenerOwnerSummary, liveNetworkRelationships, logicalListeners, networkServiceLabel, normalizeAddress, workloadAttribution, type NetworkDeviceObservation } from "./network";
import type { DeviceRecord, ExpectedService, NetworkConnection, SecuritySnapshot, WorkloadInventory } from "./types";

const at = "2026-09-02T20:00:00Z";
const syntheticPrivateIPv4 = (...octets: number[]) => octets.join(".");

function connection(overrides: Partial<NetworkConnection> = {}): NetworkConnection {
  return { protocol: "TCP", localAddress: "0.0.0.0", localPort: 443, remoteAddress: "", remotePort: 0, state: "Listen", processId: 1, processName: "caddy", ...overrides };
}

function device(id: string, name: string, address: string, connections: NetworkConnection[]): NetworkDeviceObservation {
  const record: DeviceRecord = { id, displayName: name, hostName: name.toLowerCase(), operatingSystem: "Test OS", architecture: "amd64", trustState: "enrolled", status: "current", enrolledAt: at, lastSeenAt: at, lastCollectedAt: at, certificateExpiresAt: null, revokedAt: null };
  const snapshot: SecuritySnapshot = { collectedAt: at, device: { deviceId: id, hostName: record.hostName, operatingSystem: record.operatingSystem, architecture: record.architecture, uptimeSeconds: 1 }, defender: null, windowsBaseline: null, linuxBaseline: null, baselineChecks: [], findings: [], firewallProfiles: [], connections: [connection({ localAddress: address, localPort: 65000, state: "Bound", protocol: "UDP", processName: "address-marker" }), ...connections], notices: [] };
  return { device: record, snapshot, expectedServices: [], listenerObservations: [] };
}

function expected(overrides: Partial<ExpectedService> = {}): ExpectedService {
  return { id: "svc", deviceId: "device", label: "HTTPS", protocol: "TCP", port: 443, portEnd: 443, bindScope: "wildcard", processNames: [], workloadNames: [], systemdUnits: [], expiresAt: null, createdAt: at, updatedAt: at, ...overrides };
}

describe("network address facts", () => {
  it("normalizes bracketed, zoned, and IPv4-mapped addresses", () => {
    expect(normalizeAddress("[FE80::1%eth0]")).toBe("fe80::1");
    expect(normalizeAddress("::ffff:192.0.2.77")).toBe("192.0.2.77");
  });

  it.each([
    ["127.0.0.1", "local"], ["::1", "local"], ["0.0.0.0", "wildcard"], ["::", "wildcard"],
    [syntheticPrivateIPv4(192, 168, 50, 77), "private"], [syntheticPrivateIPv4(172, 20, 1, 1), "private"], ["fe80::1", "private"], ["8.8.8.8", "specific"],
  ])("classifies %s as %s", (address, scope) => expect(endpointBindScope(connection({ localAddress: address }))).toBe(scope));

  it.each([[syntheticPrivateIPv4(10, 20, 30, 1), true], [syntheticPrivateIPv4(172, 31, 2, 3), true], [syntheticPrivateIPv4(192, 168, 50, 1), true], ["fd00::1", true], ["8.8.8.8", false]])("recognizes private address %s", (address, result) => expect(isPrivateNetworkAddress(address)).toBe(result));

  it("formats endpoints, scopes, owners, and known services consistently", () => {
    expect(endpoint("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
    expect(endpoint("", 443)).toBe("—");
    expect(endpoint("192.0.2.1", 0)).toBe("—");
    expect(endpointScope(connection({ state: "Established" }))).toBe("Active connection");
    expect(endpointScope(connection({ localAddress: "127.0.0.1" }))).toBe("This host only");
    expect(bindScopeLabel("any")).toBe("Any bind");
    expect(canonicalOwnerName(" SVCHOST.EXE ", true)).toBe("svchost");
    expect(networkServiceLabel("tcp", 443)).toBe("HTTPS");
    expect(networkServiceLabel("tcp", 12345)).toBe("");
  });

  it("separates loopback, unspecified, and multicast addresses", () => {
    expect(isLoopbackAddress("127.0.0.2")).toBe(true);
    expect(isLoopbackAddress("192.0.2.1")).toBe(false);
    expect(isUnspecifiedAddress("*")).toBe(true);
    expect(isUnspecifiedAddress("192.0.2.1")).toBe(false);
    expect(isMulticastAddress("239.1.1.1")).toBe(true);
    expect(isMulticastAddress("ff02::fb")).toBe(true);
    expect(isMulticastAddress("192.0.2.1")).toBe(false);
  });
});

describe("listener baselines", () => {
  it("groups dual-stack sockets into one logical listener", () => {
    const listeners = logicalListeners([connection({ localAddress: "0.0.0.0" }), connection({ localAddress: "::", processId: 2 })]);
    expect(listeners).toHaveLength(1);
    expect(listeners[0]).toMatchObject({ key: "TCP:443:wildcard", rawCount: 2, addresses: ["0.0.0.0", "::"] });
  });

  it("shows every attributed owner category in a listener summary", () => {
    const listener = logicalListeners([
      connection({ protocol: "UDP", localPort: 5353, processName: "avahi-daemon", systemdUnit: "avahi-daemon.service" }),
      connection({ protocol: "UDP", localPort: 5353, processName: "adb", systemdUnit: "" }),
    ])[0];
    expect(listenerOwnerSummary(listener)).toBe("processes: avahi-daemon, adb · service: avahi-daemon.service");
  });

  it("requires every observed process to be owner-approved", () => {
    const listener = logicalListeners([connection({ processName: "svchost.exe" })])[0];
    expect(expectedServiceMatches(listener, expected({ processNames: ["SVCHOST"] }), null)).toBe(true);
    const drifted = logicalListeners([connection({ processName: "svchost" }), connection({ processName: "unexpected.exe" })])[0];
    expect(expectedServiceMatches(drifted, expected({ processNames: ["svchost"] }), null)).toBe(false);
  });

  it("distinguishes a port-only rule from an owner-constrained baseline", () => {
    expect(expectedServiceOwnerConstrained(expected())).toBe(false);
    expect(expectedServiceOwnerConstrained(expected({ processNames: ["caddy"] }))).toBe(true);
    expect(expectedServiceOwnerConstrained(expected({ workloadNames: ["gateway"] }))).toBe(true);
    expect(expectedServiceOwnerConstrained(expected({ systemdUnits: ["caddy.service"] }))).toBe(true);
  });

  it("fails closed after a temporary expectation expires", () => {
    const listener = logicalListeners([connection()])[0];
    expect(expectedServiceMatches(listener, expected({ expiresAt: new Date(Date.now() + 60_000).toISOString() }), null)).toBe(true);
    expect(expectedServiceMatches(listener, expected({ expiresAt: new Date(Date.now() - 60_000).toISOString() }), null)).toBe(false);
    expect(expectedServiceMatches(listener, expected({ expiresAt: "not-a-timestamp" }), null)).toBe(false);
  });

  it("requires a live workload mapping for a workload-constrained baseline", () => {
    const listener = logicalListeners([connection()])[0];
    const inventory: WorkloadInventory = { runtime: "docker", collectedAt: at, workloads: [{ name: "haven_proxy", state: "running", ports: [{ protocol: "TCP", containerPort: 443, published: true, hostAddress: "0.0.0.0", hostPort: 443 }] }] };
    expect(workloadAttribution(listener, inventory).map(({ workload }) => workload.name)).toEqual(["haven_proxy"]);
    expect(expectedServiceMatches(listener, expected({ processNames: ["caddy"], workloadNames: ["haven_proxy"] }), inventory)).toBe(true);
    expect(expectedServiceMatches(listener, expected({ processNames: ["caddy"], workloadNames: ["different"] }), inventory)).toBe(false);
    expect(expectedServiceMatches(listener, expected({ processNames: ["caddy"], workloadNames: ["haven_proxy"] }), null)).toBe(false);
  });

  it("treats Docker's service unit as support evidence for a legacy workload-only baseline", () => {
    const inventory: WorkloadInventory = { runtime: "docker", collectedAt: at, workloads: [{ name: "gateway", state: "running", ports: [{ protocol: "TCP", containerPort: 443, published: true, hostAddress: "0.0.0.0", hostPort: 443 }] }] };
    const dockerOwned = logicalListeners([connection({ processName: "", systemdUnit: "docker.service" })])[0];
    expect(expectedServiceMatches(dockerOwned, expected({ workloadNames: ["gateway"] }), inventory)).toBe(true);
    const unrelated = logicalListeners([connection({ processName: "", systemdUnit: "unexpected.service" })])[0];
    expect(expectedServiceMatches(unrelated, expected({ workloadNames: ["gateway"] }), inventory)).toBe(false);
  });

  it("does not let a port range cover the wrong protocol or bind scope", () => {
    const listener = logicalListeners([connection({ localPort: 50000 })])[0];
    expect(expectedServiceMatches(listener, expected({ port: 49152, portEnd: 65535 }), null)).toBe(true);
    expect(expectedServiceMatches(listener, expected({ protocol: "UDP", port: 49152, portEnd: 65535 }), null)).toBe(false);
    expect(expectedServiceMatches(listener, expected({ port: 49152, portEnd: 65535, bindScope: "private" }), null)).toBe(false);
  });

  it("enforces systemd ownership when a baseline names a service", () => {
    const listener = logicalListeners([connection({ processName: "sshd", systemdUnit: "ssh.socket", localPort: 22 })])[0];
    expect(expectedServiceMatches(listener, expected({ port: 22, portEnd: 22, processNames: ["sshd"], systemdUnits: ["SSH.SOCKET"] }), null)).toBe(true);
    expect(expectedServiceMatches(listener, expected({ port: 22, portEnd: 22, processNames: ["sshd"], systemdUnits: ["other.service"] }), null)).toBe(false);
    expect(expectedServiceMatches(listener, expected({ port: 22, portEnd: 22, systemdUnits: ["ssh.socket"] }), null)).toBe(false);
  });
});

describe("shared hub/browser service expectation contract", () => {
  it.each(serviceExpectationCases)("matches $name identically", (item) => {
    const count = Math.max(1, item.listener.processes.length, item.listener.systemdUnits.length);
    const connections = Array.from({ length: count }, (_, index) => connection({
      protocol: item.listener.protocol,
      localAddress: item.listener.address,
      localPort: item.listener.port,
      processName: item.listener.processes[index] || "",
      systemdUnit: item.listener.systemdUnits[index] || "",
    }));
    const listener = logicalListeners(connections)[0];
    const service = expected({
      protocol: item.service.protocol as ExpectedService["protocol"],
      port: item.service.port,
      portEnd: item.service.portEnd,
      bindScope: item.service.bindScope as ExpectedService["bindScope"],
      processNames: item.service.processNames,
      workloadNames: item.service.workloadNames,
      systemdUnits: item.service.systemdUnits,
    });
    const inventory: WorkloadInventory | null = item.workloads.length > 0 ? {
      runtime: "docker",
      collectedAt: at,
      workloads: item.workloads.map((name) => ({ name, state: "running", ports: [{ protocol: item.listener.protocol as "TCP" | "UDP", containerPort: item.listener.port, published: true, hostAddress: item.listener.address, hostPort: item.listener.port }] })),
    } : null;
    expect(expectedServiceMatches(listener, service, inventory)).toBe(item.matches);
  });
});

describe("live relationship projection", () => {
  it("infers inbound SSH and deduplicates the socket reported by both endpoints", () => {
    const windows = device("windows", "Windows Workstation", "192.0.2.64", [connection({ localAddress: "192.0.2.64", localPort: 55152, remoteAddress: "192.0.2.77", remotePort: 22, state: "Established", processName: "ssh" })]);
    const ubuntu = device("ubuntu", "Ubuntu Application Server", "192.0.2.77", [
      connection({ localAddress: "0.0.0.0", localPort: 22, state: "Listen", processName: "sshd", systemdUnit: "ssh.socket" }),
      connection({ localAddress: "192.0.2.77", localPort: 22, remoteAddress: "192.0.2.64", remotePort: 55152, state: "Established", processName: "sshd", systemdUnit: "ssh.socket" }),
    ]);
    const relationships = liveNetworkRelationships([windows, ubuntu]).filter((item) => item.port === 22);
    expect(relationships).toHaveLength(1);
    expect(relationships[0]).toMatchObject({ sourceName: "Windows Workstation", targetName: "Ubuntu Application Server", peerKind: "enrolled", connectionCount: 1 });
    expect(relationships[0].owners).toEqual(["ssh", "sshd"]);
  });

  it("labels an unenrolled private peer as observed-only", () => {
    const observedAddress = syntheticPrivateIPv4(10, 20, 30, 69);
    const windows = device("windows", "Windows Workstation", "192.0.2.64", [connection({ localAddress: "192.0.2.64", localPort: 53000, remoteAddress: observedAddress, remotePort: 445, state: "Established", processName: "System" })]);
    expect(liveNetworkRelationships([windows]).find((item) => item.port === 445)).toMatchObject({ targetName: observedAddress, peerKind: "observed" });
  });

	 it("labels an explicitly configured private peer as a managed appliance", () => {
		 const managedAddress = syntheticPrivateIPv4(10, 20, 30, 69);
		 const windows = device("windows", "Windows Workstation", "192.0.2.64", [connection({ localAddress: "192.0.2.64", localPort: 53000, remoteAddress: managedAddress, remotePort: 445, state: "Established", processName: "System" })]);
		 const appliances = [{ id: "nas", displayName: "Home NAS", kind: "nas", address: managedAddress, status: "healthy" as const, configuredAt: new Date().toISOString(), lastCheckedAt: new Date().toISOString(), services: [] }];
		 expect(liveNetworkRelationships([windows], appliances).find((item) => item.port === 445)).toMatchObject({ targetName: "Home NAS", peerKind: "managed" });
	 });

  it("groups Internet destinations without exposing their addresses", () => {
    const windows = device("windows", "Windows Workstation", "192.0.2.64", [
      connection({ localAddress: "192.0.2.64", localPort: 53000, remoteAddress: "203.0.113.10", remotePort: 443, state: "Established", processName: "chrome" }),
      connection({ localAddress: "192.0.2.64", localPort: 53001, remoteAddress: "203.0.113.11", remotePort: 443, state: "Established", processName: "chrome" }),
    ]);
    const external = liveNetworkRelationships([windows]).find((item) => item.peerKind === "external")!;
    expect(external).toMatchObject({ sourceName: "Windows Workstation", targetName: "Internet", connectionCount: 2, destinationCount: 2 });
    expect(JSON.stringify(external)).not.toContain("203.0.113");
  });
});
