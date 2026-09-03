import type {
  BindScope,
  DeviceRecord,
  ExpectedService,
  NetworkConnection,
  ObservedListener,
  SecuritySnapshot,
  WorkloadInventory,
} from "./types";

export interface NetworkDeviceObservation {
  device: DeviceRecord;
  snapshot: SecuritySnapshot | null;
  expectedServices: ExpectedService[];
  listenerObservations: ObservedListener[];
}

export interface LogicalListener {
  key: string;
  protocol: "TCP" | "UDP";
  port: number;
  bindScope: Exclude<BindScope, "any">;
  addresses: string[];
  processes: string[];
  systemdUnits: string[];
  rawCount: number;
  state: "Listening" | "Bound";
}

export interface NetworkRelationship {
  key: string;
  sourceName: string;
  targetName: string;
  peerKind: "enrolled" | "observed" | "external";
  protocol: string;
  port: number;
  owners: string[];
  connectionCount: number;
  destinationCount: number;
}

export function normalizeAddress(value: string) {
  let address = value.trim().replace(/^\[|\]$/g, "");
  const zone = address.lastIndexOf("%");
  if (zone >= 0) address = address.slice(0, zone);
  if (address.toLowerCase().startsWith("::ffff:") && /^\d+\.\d+\.\d+\.\d+$/.test(address.slice(7))) address = address.slice(7);
  return address.toLowerCase();
}

export function endpoint(address: string, port: number) {
  const normalized = normalizeAddress(address);
  if (!normalized || port === 0) return "—";
  const host = normalized.includes(":") ? `[${normalized}]` : normalized;
  return `${host}:${port}`;
}

export function endpointBindScope(connection: NetworkConnection): Exclude<BindScope, "any"> {
  const address = normalizeAddress(connection.localAddress);
  if (address === "127.0.0.1" || address === "::1" || address.startsWith("127.")) return "local";
  if (address === "0.0.0.0" || address === "::" || address === "*" || address === "") return "wildcard";
  if (address.startsWith("10.") || address.startsWith("192.168.")) return "private";
  const octets = address.split(".").map(Number);
  if (octets.length === 4 && octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return "private";
  if (address.startsWith("169.254.") || address.startsWith("fe80:") || address.startsWith("fc") || address.startsWith("fd")) return "private";
  return "specific";
}

export function bindScopeLabel(scope: BindScope) {
  return ({ any: "Any bind", local: "This host only", private: "Private address", wildcard: "All interfaces", specific: "Specific address" } satisfies Record<BindScope, string>)[scope];
}

export function endpointScope(connection: NetworkConnection) {
  if (connection.state.toLowerCase() === "established") return "Active connection";
  return bindScopeLabel(endpointBindScope(connection));
}

export function logicalListeners(connections: NetworkConnection[]) {
  const grouped = new Map<string, LogicalListener>();
  connections.filter((connection) => ["listen", "open", "bound"].includes(connection.state.toLowerCase())).forEach((connection) => {
    const protocol = connection.protocol.toUpperCase() === "UDP" ? "UDP" : "TCP";
    const bindScope = endpointBindScope(connection);
    const key = `${protocol}:${connection.localPort}:${bindScope}`;
    const current = grouped.get(key) || { key, protocol, port: connection.localPort, bindScope, addresses: [], processes: [], systemdUnits: [], rawCount: 0, state: protocol === "UDP" ? "Bound" : "Listening" };
    const address = normalizeAddress(connection.localAddress);
    if (address && !current.addresses.includes(address)) current.addresses.push(address);
    if (connection.processName && !current.processes.includes(connection.processName)) current.processes.push(connection.processName);
    if (connection.systemdUnit && !current.systemdUnits.includes(connection.systemdUnit)) current.systemdUnits.push(connection.systemdUnit);
    current.rawCount += 1;
    grouped.set(key, current);
  });
  return [...grouped.values()].sort((left, right) => left.protocol.localeCompare(right.protocol) || left.port - right.port || left.bindScope.localeCompare(right.bindScope));
}

export function workloadAttribution(listener: LogicalListener, inventory: WorkloadInventory | null) {
  if (!inventory) return [];
  return inventory.workloads.flatMap((workload) => {
    const bindings = workload.ports.filter((binding) => binding.published && binding.protocol === listener.protocol && binding.hostPort === listener.port && (() => {
      const address = normalizeAddress(binding.hostAddress || "");
      if (!address || address === "0.0.0.0" || address === "::") return listener.bindScope === "wildcard";
      return listener.addresses.includes(address);
    })());
    return bindings.length > 0 ? [{ workload, bindings }] : [];
  });
}

export function canonicalOwnerName(value: string, executable = false) {
  let name = value.trim().toLowerCase();
  if (executable && name.endsWith(".exe")) name = name.slice(0, -4);
  return name;
}

export function listenerOwnerSummary(listener: LogicalListener) {
  const parts: string[] = [];
  if (listener.processes.length > 0) parts.push(`process${listener.processes.length === 1 ? "" : "es"}: ${listener.processes.join(", ")}`);
  if (listener.systemdUnits.length > 0) parts.push(`service${listener.systemdUnits.length === 1 ? "" : "s"}: ${listener.systemdUnits.join(", ")}`);
  return parts.join(" · ");
}

export function expectedServiceOwnerConstrained(service: ExpectedService) {
  return (service.processNames?.length || 0) > 0 || (service.workloadNames?.length || 0) > 0 || (service.systemdUnits?.length || 0) > 0;
}

export function expectedServiceMatches(listener: LogicalListener, service: ExpectedService, inventory: WorkloadInventory | null) {
  const portEnd = service.portEnd || service.port;
  if (service.protocol !== listener.protocol || listener.port < service.port || listener.port > portEnd || (service.bindScope !== "any" && service.bindScope !== listener.bindScope)) return false;
  const processNames = service.processNames || [];
  const workloadNames = service.workloadNames || [];
  const systemdUnits = service.systemdUnits || [];
  const ownerConstrained = expectedServiceOwnerConstrained(service);
  if (!ownerConstrained) return true;

  const observedWorkloads = workloadAttribution(listener, inventory).map(({ workload }) => workload.name);
  if (!ownerDimensionMatches(listener.processes, processNames, true)) return false;
  if (!ownerDimensionMatches(observedWorkloads, workloadNames)) return false;
  if (!ownerDimensionMatches(listener.systemdUnits, systemdUnits)) return false;
  return true;
}

function ownerDimensionMatches(observed: string[], expected: string[], executable = false) {
  if (observed.length === 0 || expected.length === 0) return observed.length === expected.length;
  const allowed = new Set(expected.map((value) => canonicalOwnerName(value, executable)));
  return observed.every((value) => allowed.has(canonicalOwnerName(value, executable)));
}

export function isLoopbackAddress(value: string) {
  const address = normalizeAddress(value);
  return address === "::1" || address.startsWith("127.");
}

export function isUnspecifiedAddress(value: string) {
  const address = normalizeAddress(value);
  return address === "" || address === "*" || address === "::" || address === "0.0.0.0";
}

export function isPrivateNetworkAddress(value: string) {
  const address = normalizeAddress(value);
  if (address.startsWith("10.") || address.startsWith("192.168.") || address.startsWith("169.254.")) return true;
  const octets = address.split(".").map(Number);
  if (octets.length === 4 && octets.every(Number.isFinite)) return octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31;
  return address.startsWith("fe80:") || address.startsWith("fc") || address.startsWith("fd");
}

export function isMulticastAddress(value: string) {
  const address = normalizeAddress(value);
  if (address.startsWith("ff")) return true;
  const firstOctet = Number(address.split(".")[0]);
  return Number.isFinite(firstOctet) && firstOctet >= 224 && firstOctet <= 239;
}

export function networkServiceLabel(protocol: string, port: number) {
  const labels: Record<string, string> = {
    "TCP:22": "SSH",
    "TCP:53": "DNS",
    "UDP:53": "DNS",
    "UDP:67": "DHCP",
    "TCP:80": "HTTP",
    "TCP:443": "HTTPS",
    "TCP:445": "SMB",
    "TCP:3389": "Remote Desktop",
    "TCP:4070": "Spotify",
    "TCP:5228": "push messaging",
    "TCP:8096": "Jellyfin",
    "TCP:8443": "HAVEN",
    "UDP:51822": "WireGuard",
  };
  return labels[`${protocol.toUpperCase()}:${port}`] || "";
}

export function liveNetworkRelationships(devices: NetworkDeviceObservation[]) {
  const addressOwners = new Map<string, NetworkDeviceObservation>();
  for (const device of devices) {
    for (const connection of device.snapshot?.connections || []) {
      const address = normalizeAddress(connection.localAddress);
      if (!isUnspecifiedAddress(address) && !isLoopbackAddress(address) && !isMulticastAddress(address)) addressOwners.set(address, device);
    }
  }

  type MutableRelationship = Omit<NetworkRelationship, "owners" | "connectionCount" | "destinationCount"> & { owners: Set<string>; connections: Set<string>; destinations: Set<string> };
  const grouped = new Map<string, MutableRelationship>();
  for (const localDevice of devices) {
    const listenerPorts = new Set(logicalListeners(localDevice.snapshot?.connections || []).map((listener) => `${listener.protocol}:${listener.port}`));
    for (const connection of localDevice.snapshot?.connections || []) {
      if (connection.state.toLowerCase() !== "established") continue;
      const remoteAddress = normalizeAddress(connection.remoteAddress);
      if (!remoteAddress || connection.remotePort < 1 || isLoopbackAddress(remoteAddress) || isUnspecifiedAddress(remoteAddress) || isMulticastAddress(remoteAddress)) continue;
      const peerDevice = addressOwners.get(remoteAddress);
      if (peerDevice?.device.id === localDevice.device.id) continue;
      const peerKind: NetworkRelationship["peerKind"] = peerDevice ? "enrolled" : isPrivateNetworkAddress(remoteAddress) ? "observed" : "external";
      const peerName = peerDevice?.device.displayName || (peerKind === "observed" ? remoteAddress : "Internet");
      const owner = connection.processName || connection.systemdUnit || "Not attributed";
      const protocol = connection.protocol.toUpperCase();
      const inbound = listenerPorts.has(`${protocol}:${connection.localPort}`);
      const servicePort = inbound ? connection.localPort : connection.remotePort;
      const peerIdentity = peerDevice ? `device:${peerDevice.device.id}` : peerKind === "observed" ? `asset:${remoteAddress}` : `internet:${canonicalOwnerName(owner)}`;
      const localIdentity = `device:${localDevice.device.id}`;
      const key = `${inbound ? `${peerIdentity}|${localIdentity}` : `${localIdentity}|${peerIdentity}`}|${protocol}:${servicePort}`;
      const localEndpoint = endpoint(connection.localAddress, connection.localPort);
      const remoteEndpoint = endpoint(connection.remoteAddress, connection.remotePort);
      const connectionIdentity = [localEndpoint, remoteEndpoint].sort().join(" ↔ ");
      const relationship = grouped.get(key) || {
        key,
        sourceName: inbound ? peerName : localDevice.device.displayName,
        targetName: inbound ? localDevice.device.displayName : peerName,
        peerKind,
        protocol,
        port: servicePort,
        owners: new Set<string>(),
        connections: new Set<string>(),
        destinations: new Set<string>(),
      };
      relationship.owners.add(owner);
      relationship.connections.add(connectionIdentity);
      relationship.destinations.add(remoteAddress);
      grouped.set(key, relationship);
    }
  }

  const order = { enrolled: 0, observed: 1, external: 2 } satisfies Record<NetworkRelationship["peerKind"], number>;
  return [...grouped.values()].map((relationship): NetworkRelationship => {
    const { owners, connections, destinations, ...identity } = relationship;
    return { ...identity, owners: [...owners].sort(), connectionCount: connections.size, destinationCount: destinations.size };
  }).sort((left, right) => order[left.peerKind] - order[right.peerKind]
    || left.sourceName.localeCompare(right.sourceName)
    || left.targetName.localeCompare(right.targetName)
    || left.port - right.port);
}
