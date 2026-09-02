import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { addPasskey, collectSnapshot, getAuthStatus, getDevice, getLatestSnapshot, getRuntimeStatus, listAuditEvents, listDevices, listEvents, listExpectedServices, listFindingReviews, listObservedListeners, listPasskeys, listSecurityActions, loginWithPasskey, logout, registerPasskey, removeExpectedService, removePasskey, requestSecurityAction, saveExpectedService, saveExpectedServices, saveFindingReview } from "./api";
import { ActivityIcon, AlertIcon, BellIcon, CheckIcon, ChipIcon, DefenderIcon, DevicesIcon, FirewallIcon, HavenIcon, HelpIcon, LaptopIcon, LockIcon, MonitorIcon, NetworkIcon, RefreshIcon, RemoteAccessIcon, ServerIcon, UpdateIcon, UsersIcon, WorkloadIcon } from "./icons";
import type {
  BaselineCheck,
  AuditEvent,
  ActionCapability,
  AuthStatus,
  BindScope,
  ContainerPortBinding,
  ContainerWorkload,
  DefenderStatus,
  DeviceRecord,
  ExpectedService,
  ExpectedServiceInput,
  FindingReview,
  FindingReviewState,
  FirewallProfileStatus,
  LinuxBaseline,
  NetworkConnection,
  ObservedListener,
  PasskeyInfo,
  RuntimeStatus,
  SecurityEvent,
  SecurityAction,
  SecurityActionKind,
  SecuritySnapshot,
  SecurityFinding,
  WorkloadInventory,
} from "./types";

type Tone = "healthy" | "configured" | "attention" | "danger" | "unknown";
type Accent = "green" | "blue" | "amber" | "cyan";

interface ChipProps {
  label: string;
  tone: Tone;
}

async function latestEnrolledObservation(inventory: DeviceRecord[], preferredId: string, signal?: AbortSignal) {
  const candidates = inventory.filter((device) => device.trustState !== "revoked" && device.lastCollectedAt);
  const selected = candidates.find((device) => device.id === preferredId)
    || candidates.find((device) => device.status === "current")
    || candidates[0];
  if (!selected) return null;
  const detail = await getDevice(selected.id, signal);
  return detail.snapshot ? { id: selected.id, snapshot: detail.snapshot } : null;
}

function AuthenticationGate({ status, authenticate }: { status: AuthStatus; authenticate: (bootstrapCode?: string, label?: string) => Promise<void> }) {
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [label, setLabel] = useState("This device");
  const [useLocalCode, setUseLocalCode] = useState(!status.configured);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passkeysSupported = typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

  const proceed = async () => {
    setWorking(true);
    setError(null);
    try {
      await authenticate(useLocalCode ? bootstrapCode.trim() : undefined, label.trim());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The passkey provider could not complete the request.");
    } finally {
      setWorking(false);
    }
  };

  if (status.useConfiguredOrigin) {
    return <main className="auth-shell"><section className="auth-card"><span className="brand-mark"><HavenIcon /></span><p className="eyebrow">TRUSTED PRIVATE ORIGIN</p><h1>Open HAVEN at its trusted address</h1><p>Passkeys require HAVEN's exact configured origin. Your data stays on your private network; only the browser address changes.</p><a className="primary-action" href={status.origin}>Continue to {status.origin}</a></section></main>;
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="auth-title">
        <span className="brand-mark"><HavenIcon /></span>
        <p className="eyebrow">HAVEN ACTION CENTER</p>
        <h1 id="auth-title">{useLocalCode ? (status.configured ? "Recover passkey access" : "Create the first owner passkey") : "Unlock with a passkey"}</h1>
        <p>{useLocalCode ? "Generate a short-lived enrollment code on the machine that hosts HAVEN, then paste it here. This is required only to create or recover owner access—not whenever HAVEN starts." : "Use any passkey already registered to HAVEN. Your browser and operating system choose the available provider, such as Windows Hello, Touch ID, a phone, or a hardware security key."}</p>
        {useLocalCode && <><label className="auth-field"><span>Passkey label</span><input value={label} maxLength={60} onChange={(event) => setLabel(event.target.value)} autoComplete="off" /></label><label className="auth-field"><span>One-time enrollment code</span><input value={bootstrapCode} onChange={(event) => setBootstrapCode(event.target.value)} autoComplete="one-time-code" spellCheck={false} /></label></>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        {!passkeysSupported && <p className="inline-error" role="alert">This browser does not expose the passkey APIs HAVEN needs.</p>}
        <button className="primary-action" type="button" onClick={() => void proceed()} disabled={working || !passkeysSupported || (useLocalCode && bootstrapCode.trim() === "")}>{working ? "Waiting for your passkey provider…" : useLocalCode ? "Create HAVEN passkey" : "Continue with a passkey"}</button>
        {status.configured && <button className="text-action" type="button" onClick={() => { setUseLocalCode((value) => !value); setError(null); }}>{useLocalCode ? "Return to passkey sign-in" : "Lost access? Use a local recovery code"}</button>}
        <p className="auth-footnote">No HAVEN password is stored. A trusted-browser session lasts up to 30 days; sensitive controls still require a fresh passkey confirmation.</p>
      </section>
    </main>
  );
}

function DeviceInventory({ devices, selectedId, select, demoMode }: { devices: DeviceRecord[]; selectedId: string; select: (id: string) => void; demoMode: boolean }) {
  return (
    <section className="device-inventory" aria-labelledby="devices-title">
      <div className="inventory-heading">
        <div className="heading-identity"><span className="section-icon cyan"><DevicesIcon /></span><div><p className="eyebrow">{demoMode ? "SYNTHETIC INVENTORY" : "TRUSTED INVENTORY"}</p><h2 id="devices-title">{demoMode ? "Demo devices" : "Devices"}</h2></div></div>
        <span>{devices.length} known</span>
      </div>
      <div className="device-list">
        {devices.map((device) => {
          const tone: Tone = device.status === "current" ? "healthy" : device.status === "revoked" ? "danger" : "attention";
          return (
            <button className={`device-button ${selectedId === device.id ? "selected" : ""}`} type="button" key={device.id} onClick={() => select(device.id)} aria-pressed={selectedId === device.id}>
              <span className="device-identity"><span className="device-icon">{device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon /> : device.displayName.toLowerCase().includes("laptop") ? <LaptopIcon /> : <MonitorIcon />}</span><span><strong>{device.displayName}</strong><small>{device.operatingSystem || "Awaiting first report"}{device.lastCollectedAt ? ` · reported ${formatRelativeTime(device.lastCollectedAt)}` : ""}</small></span></span>
              <StatusChip label={device.status.replaceAll("-", " ")} tone={tone} />
            </button>
          );
        })}
      </div>
    </section>
  );
}

function StatusChip({ label, tone }: ChipProps) {
  return <span className={`status-chip ${tone}`}>{label}</span>;
}

function formatDate(value: string | null | undefined, fallback = "Not reported") {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? fallback : date.toLocaleString();
}

function formatRelativeTime(value: string | null | undefined, fallback = "not reported") {
  if (!value) return fallback;
  const timestamp = new Date(value).valueOf();
  if (!Number.isFinite(timestamp)) return fallback;
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (elapsedSeconds < 10) return "just now";
  if (elapsedSeconds < 60) return `${elapsedSeconds}s ago`;
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  if (elapsedMinutes < 60) return `${elapsedMinutes} min ago`;
  const elapsedHours = Math.floor(elapsedMinutes / 60);
  if (elapsedHours < 48) return `${elapsedHours} hr ago`;
  return `${Math.floor(elapsedHours / 24)} days ago`;
}

function formatDuration(value: number | null) {
  if (value === null || !Number.isFinite(value)) return "Uptime unavailable";
  const totalHours = Math.floor(value / 3600);
  const days = Math.floor(totalHours / 24);
  const hours = totalHours % 24;
  return days > 0 ? `${days}d ${hours}h uptime` : `${hours}h uptime`;
}

function formatInterval(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  return minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} hr`;
}

function formatBytes(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "Not reported";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = Math.max(0, value);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function booleanValue(value: boolean | null) {
  if (value === true) return { label: "On", className: "value-good" };
  if (value === false) return { label: "Off", className: "value-bad" };
  return { label: "Unavailable", className: "value-muted" };
}

function endpoint(address: string, port: number) {
	const normalized = normalizeAddress(address);
	if (!normalized || port === 0) return "—";
  const host = normalized.includes(":") ? `[${normalized}]` : normalized;
  return `${host}:${port}`;
}

function normalizeAddress(value: string) {
	let address = value.trim().replace(/^\[|\]$/g, "");
	const zone = address.lastIndexOf("%");
	if (zone >= 0) address = address.slice(0, zone);
	if (address.toLowerCase().startsWith("::ffff:") && /^\d+\.\d+\.\d+\.\d+$/.test(address.slice(7))) address = address.slice(7);
	return address.toLowerCase();
}

function endpointBindScope(connection: NetworkConnection): Exclude<BindScope, "any"> {
  const address = normalizeAddress(connection.localAddress);
  if (address === "127.0.0.1" || address === "::1" || address.startsWith("127.")) return "local";
  if (address === "0.0.0.0" || address === "::" || address === "*" || address === "") return "wildcard";
  if (address.startsWith("10.") || address.startsWith("192.168.")) return "private";
  const octets = address.split(".").map(Number);
  if (octets.length === 4 && octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return "private";
  if (address.startsWith("169.254.") || address.startsWith("fe80:") || address.startsWith("fc") || address.startsWith("fd")) return "private";
  return "specific";
}

function bindScopeLabel(scope: BindScope) {
	return ({ any: "Any bind", local: "This host only", private: "Private address", wildcard: "All interfaces", specific: "Specific address" } satisfies Record<BindScope, string>)[scope];
}

function endpointScope(connection: NetworkConnection) {
  if (connection.state.toLowerCase() === "established") return "Active connection";
  return bindScopeLabel(endpointBindScope(connection));
}

interface LogicalListener {
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

function logicalListeners(connections: NetworkConnection[]) {
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

function workloadAttribution(listener: LogicalListener, inventory: WorkloadInventory | null) {
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

function canonicalOwnerName(value: string, executable = false) {
	let name = value.trim().toLowerCase();
	if (executable && name.endsWith(".exe")) name = name.slice(0, -4);
	return name;
}

function expectedServiceMatches(listener: LogicalListener, service: ExpectedService, inventory: WorkloadInventory | null) {
	const portEnd = service.portEnd || service.port;
	if (service.protocol !== listener.protocol || listener.port < service.port || listener.port > portEnd || (service.bindScope !== "any" && service.bindScope !== listener.bindScope)) return false;
	if (service.processNames?.length) {
		const expectedProcesses = new Set(service.processNames.map((process) => canonicalOwnerName(process, true)));
		const observedProcesses = listener.processes.map((process) => canonicalOwnerName(process, true));
		if (observedProcesses.length === 0 || !observedProcesses.every((process) => expectedProcesses.has(process))) return false;
	}
	if (service.workloadNames?.length) {
		const expectedWorkloads = new Set(service.workloadNames.map((workload) => canonicalOwnerName(workload)));
		const observedWorkloads = workloadAttribution(listener, inventory).map(({ workload }) => canonicalOwnerName(workload.name));
		if (observedWorkloads.length === 0 || !observedWorkloads.every((workload) => expectedWorkloads.has(workload))) return false;
	}
	if (service.systemdUnits?.length) {
		const expectedUnits = new Set(service.systemdUnits.map((unit) => canonicalOwnerName(unit)));
		const observedUnits = listener.systemdUnits.map((unit) => canonicalOwnerName(unit));
		if (observedUnits.length === 0 || !observedUnits.every((unit) => expectedUnits.has(unit))) return false;
	}
	return true;
}

interface BaselineSuggestion {
	id: string;
	title: string;
	description: string;
	listenerKeys: string[];
	services: ExpectedServiceInput[];
}

const workloadLabels: Record<string, string> = {
	frontend_nginx: "PokeGoNexus public web ingress",
	binderledger_api: "BinderLedger API",
	binderledger_web: "BinderLedger web",
	haven_dns: "HAVEN private DNS",
	haven_hub: "HAVEN agent hub",
	haven_proxy: "HAVEN HTTPS console",
	winrift_api: "WinRift API",
	winrift_web: "WinRift web",
};

function readableIdentifier(value: string) {
	return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function knownSystemdLabel(unit: string) {
	if (unit === "systemd-resolved.service") return "systemd-resolved local DNS";
	if (unit === "binderledger-localhost-proxy@8081.service") return "BinderLedger localhost proxy";
	return "";
}

function suggestedBaseline(deviceId: string, operatingSystem: string, listeners: LogicalListener[], inventory: WorkloadInventory | null, expectedServices: ExpectedService[]) {
	const suggestions: BaselineSuggestion[] = [];
	const isWindows = /windows/i.test(operatingSystem);
	const unreviewed = listeners.filter((listener) => !expectedServices.some((service) => expectedServiceMatches(listener, service, inventory)));
	const exactLabels = isWindows ? new Map<string, string>([
		["TCP:135", "Windows RPC Endpoint Mapper"],
		["TCP:139", "Windows file sharing (NetBIOS)"],
		["TCP:445", "Windows file sharing (SMB)"],
		["TCP:3389", "Remote Desktop"],
		["TCP:5040", "Windows Connected Devices"],
		["TCP:5357", "Windows device discovery (WSD)"],
		["TCP:8096", "Jellyfin"],
	]) : new Map<string, string>([
		["TCP:22", "OpenSSH"],
		["UDP:546", "DHCPv6 client"],
		["UDP:5353", "Avahi mDNS"],
		["UDP:51822", "WireGuard VPN"],
	]);

	for (const listener of unreviewed) {
		const attributions = workloadAttribution(listener, inventory);
		if (attributions.length === 1) {
			const workload = attributions[0].workload;
			const title = workloadLabels[workload.name] || readableIdentifier(workload.name);
			suggestions.push({
				id: `workload:${listener.key}:${workload.name}`,
				title,
				description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)} · currently published by Docker workload ${workload.name}.`,
				listenerKeys: [listener.key],
				services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: [], workloadNames: [workload.name], systemdUnits: [] }],
			});
			continue;
		}
		const knownUnitLabels = listener.systemdUnits.map(knownSystemdLabel);
		if (knownUnitLabels.length > 0 && knownUnitLabels.every(Boolean) && new Set(knownUnitLabels).size === 1) {
			const title = knownUnitLabels[0];
			suggestions.push({
				id: `systemd:${listener.key}:${listener.systemdUnits.join(",")}`,
				title,
				description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)} · owned by ${listener.systemdUnits.join(", ")}.`,
				listenerKeys: [listener.key],
				services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: [], workloadNames: [], systemdUnits: listener.systemdUnits }],
			});
			continue;
		}
		if (listener.bindScope === "local") continue;
		const title = exactLabels.get(`${listener.protocol}:${listener.port}`);
		if (!title) continue;
		suggestions.push({
			id: `native:${listener.key}`,
			title,
			description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)}${listener.processes.length ? ` · owned by ${listener.processes.join(", ")}` : listener.systemdUnits.length ? ` · owned by ${listener.systemdUnits.join(", ")}` : ""}.`,
			listenerKeys: [listener.key],
			services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: [], systemdUnits: listener.systemdUnits }],
		});
	}

	if (isWindows) {
		const systemProcesses = new Set(["system", "svchost", "services", "lsass", "wininit", "winlogon", "spoolsv"]);
		const exactSuggestionKeys = new Set(suggestions.flatMap((suggestion) => suggestion.listenerKeys));
		const dynamicByScope = new Map<LogicalListener["bindScope"], LogicalListener[]>();
		for (const listener of unreviewed) {
			const processes = listener.processes.map((process) => canonicalOwnerName(process, true));
			if (exactSuggestionKeys.has(listener.key) || listener.protocol !== "TCP" || listener.port < 49152 || listener.port > 65535 || processes.length === 0 || !processes.every((process) => systemProcesses.has(process))) continue;
			dynamicByScope.set(listener.bindScope, [...(dynamicByScope.get(listener.bindScope) || []), listener]);
		}
		for (const [scope, grouped] of dynamicByScope) {
			const processes = [...new Set(grouped.flatMap((listener) => listener.processes.map((process) => canonicalOwnerName(process, true))))].sort();
			suggestions.push({
				id: `windows-rpc:${scope}:${processes.join(",")}`,
				title: "Windows dynamic RPC services",
				description: `Groups ${grouped.length} current listener${grouped.length === 1 ? "" : "s"} in TCP 49152–65535, but only while owned by reviewed Windows system processes: ${processes.join(", ")}.`,
				listenerKeys: grouped.map((listener) => listener.key),
				services: [{ deviceId, label: "Windows dynamic RPC services", protocol: "TCP", port: 49152, portEnd: 65535, bindScope: scope, processNames: processes, workloadNames: [], systemdUnits: [] }],
			});
		}
	} else {
		const containerdByScope = new Map<LogicalListener["bindScope"], LogicalListener[]>();
		for (const listener of unreviewed) {
			const units = listener.systemdUnits.map((unit) => canonicalOwnerName(unit));
			if (listener.protocol !== "TCP" || listener.port < 32768 || listener.port > 60999 || units.length === 0 || !units.every((unit) => unit === "containerd.service")) continue;
			containerdByScope.set(listener.bindScope, [...(containerdByScope.get(listener.bindScope) || []), listener]);
		}
		for (const [scope, grouped] of containerdByScope) {
			suggestions.push({
				id: `containerd:${scope}`,
				title: "containerd internal runtime listeners",
				description: `Covers ${grouped.length} current TCP listener${grouped.length === 1 ? "" : "s"} in the Linux ephemeral range 32768–60999, but only while owned by containerd.service.`,
				listenerKeys: grouped.map((listener) => listener.key),
				services: [{ deviceId, label: "containerd internal runtime listeners", protocol: "TCP", port: 32768, portEnd: 60999, bindScope: scope, processNames: [], workloadNames: [], systemdUnits: ["containerd.service"] }],
			});
		}
	}

	return suggestions;
}

function formatPortBinding(binding: ContainerPortBinding) {
	if (!binding.published) return `${binding.containerPort}/${binding.protocol.toLowerCase()} · container only`;
	const address = normalizeAddress(binding.hostAddress || "") || "*";
	const host = address.includes(":") ? `[${address}]` : address;
	return `${host}:${binding.hostPort} → ${binding.containerPort}/${binding.protocol.toLowerCase()}`;
}

function policyValue(value?: string) {
  return !value || value === "NotConfigured" ? "System default" : value;
}

function SummaryCard({
  icon,
  title,
  label,
  tone,
  accent,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  label: string;
  tone: Tone;
  accent: Accent;
  children: React.ReactNode;
}) {
  return (
    <article className={`summary-card accent-${accent}`}>
      <div className="card-heading">
        <span className="card-icon" aria-hidden="true">{icon}</span>
        <StatusChip label={label} tone={tone} />
      </div>
      <h2>{title}</h2>
      <p>{children}</p>
    </article>
  );
}

function DefenderPanel({ defender }: { defender: DefenderStatus | null }) {
  if (!defender) {
    return (
      <section className="panel" aria-labelledby="defender-title">
        <PanelHeading eyebrow="HOST PROTECTION" title="Microsoft Defender" id="defender-title" icon={<DefenderIcon />} accent="blue">
          Read-only status from Windows Security
        </PanelHeading>
        <p className="empty-state">Defender status is unavailable.</p>
      </section>
    );
  }

  const details = [
    ["Antivirus", booleanValue(defender.antivirusEnabled)],
    ["Real-time protection", booleanValue(defender.realTimeProtectionEnabled)],
    ["Tamper protection", booleanValue(defender.tamperProtected)],
    [
      "Security intelligence",
      {
        label: defender.signatureVersion
          ? `${defender.signatureVersion} · ${formatDate(defender.signatureUpdatedAt)}`
          : "Not reported",
        className: defender.signatureVersion ? "" : "value-muted",
      },
    ],
    ["Last quick scan", { label: formatDate(defender.lastQuickScanAt), className: defender.lastQuickScanAt ? "" : "value-muted" }],
    ["Last full scan", { label: formatDate(defender.lastFullScanAt), className: defender.lastFullScanAt ? "" : "value-muted" }],
  ] as const;

  return (
    <section className="panel" aria-labelledby="defender-title">
      <PanelHeading eyebrow="HOST PROTECTION" title="Microsoft Defender" id="defender-title" icon={<DefenderIcon />} accent="blue">
        Read-only status from Windows Security
      </PanelHeading>
      <dl className="details-grid">
        {details.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd className={value.className}>{value.label}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function LinuxPanel({ baseline }: { baseline: LinuxBaseline }) {
  const updates = baseline.updates;
  const ssh = baseline.ssh;
  const storage = baseline.storage;
  const details = [
    ["Available updates", updates?.pendingPackageCount === null || updates?.pendingPackageCount === undefined ? "Not verified" : String(updates.pendingPackageCount)],
    ["Security updates", updates?.pendingSecurityPackageCount === null || updates?.pendingSecurityPackageCount === undefined ? "Not verified" : String(updates.pendingSecurityPackageCount)],
    ["Restart required", booleanValue(updates?.pendingReboot ?? null).label],
    ["Automatic updates", booleanValue(baseline.automaticUpdates?.enabled ?? null).label],
    ["AppArmor", booleanValue(baseline.appArmor?.enabled ?? null).label],
    ["Clock synchronized", booleanValue(baseline.timeSync?.synchronized ?? null).label],
    ["OpenSSH server", booleanValue(ssh?.serverRunning ?? null).label],
    ["SSH password authentication", ssh?.passwordAuthentication || "Not fully verified"],
    ["SSH keyboard-interactive", ssh?.keyboardInteractiveAuthentication || "Not fully verified"],
    ["SSH root login", ssh?.permitRootLogin || "Not fully verified"],
    ["Failed systemd units", baseline.services?.failedUnitCount === null || baseline.services?.failedUnitCount === undefined ? "Not verified" : String(baseline.services.failedUnitCount)],
    ["Failed unit names", baseline.services?.failedUnits?.length ? baseline.services.failedUnits.join(", ") : "None reported"],
    ["Root filesystem", storage?.usedPercentage === null || storage?.usedPercentage === undefined ? "Not verified" : `${storage.usedPercentage.toFixed(0)}% used · ${formatBytes(storage.availableBytes)} available`],
	...(baseline.workloads ? [["Docker workloads", `${baseline.workloads.workloads.length} running · observed ${formatRelativeTime(baseline.workloads.collectedAt)}`]] : []),
  ];
  return (
    <section className="panel" aria-labelledby="linux-title">
      <PanelHeading eyebrow="HOST PROTECTION" title="Ubuntu host posture" id="linux-title" icon={<ServerIcon />} accent="blue">
        Read-only status from the native Linux agent
      </PanelHeading>
      <dl className="details-grid">
        {details.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
    </section>
  );
}

function workloadTone(workload: ContainerWorkload): Tone {
	if (workload.health === "unhealthy") return "danger";
	if (workload.health === "starting") return "attention";
	if (workload.health === "healthy") return "healthy";
	return "configured";
}

function WorkloadsPanel({ inventory }: { inventory: WorkloadInventory | null }) {
	if (!inventory) return null;
	const published = inventory.workloads.filter((workload) => workload.ports.some((port) => port.published));
	const internal = inventory.workloads.flatMap((workload) => {
		const ports = workload.ports.filter((port) => !port.published);
		return ports.length > 0 ? [{ workload, ports }] : [];
	});
	const publishedPortCount = inventory.workloads.reduce((count, workload) => count + workload.ports.filter((port) => port.published).length, 0);
	return (
		<section className="panel workloads-panel" aria-labelledby="workloads-title">
			<PanelHeading eyebrow="WORKLOAD INVENTORY" title="Docker port attribution" id="workloads-title" icon={<WorkloadIcon />} accent="cyan">
				{inventory.workloads.length} running container{inventory.workloads.length === 1 ? "" : "s"} · {publishedPortCount} host mapping{publishedPortCount === 1 ? "" : "s"} · observed {formatRelativeTime(inventory.collectedAt)}
			</PanelHeading>
			<p className="service-explainer">Published mappings can receive traffic through a host address and port. Container-only ports stay inside Docker networks unless another workload forwards to them. This inventory is read-only, sanitized, and not retained in observation history.</p>
			<div className="workload-grid">
				{published.length === 0 ? <p className="activity-empty"><strong>No Docker ports are published on this host.</strong><span>Running containers may still communicate over private Docker networks.</span></p> : published.map((workload) => (
					<article className="workload-card" key={workload.name}>
						<div className="workload-card-heading"><div><span className="workload-mark"><WorkloadIcon size={17} /></span><div><h3>{workload.name}</h3><p>{workload.project && workload.service ? `${workload.project} · ${workload.service}` : workload.service || workload.project || "Standalone container"}</p></div></div><StatusChip label={workload.health === "not-configured" ? workload.state : workload.health || workload.state} tone={workloadTone(workload)} /></div>
					{workload.image && <p className="workload-image">{workload.image}</p>}
					<ul className="port-mappings">{workload.ports.filter((port) => port.published).map((port, index) => <li key={`${port.protocol}-${port.hostAddress}-${port.hostPort}-${port.containerPort}-${index}`}>{formatPortBinding(port)}</li>)}</ul>
					</article>
				))}
			</div>
			<details className="container-only-ports">
				<summary>Container-only ports ({internal.reduce((count, item) => count + item.ports.length, 0)})</summary>
				<p>These declarations are not bound to a host port. They are useful for understanding service-to-service traffic, but they are not additional host listeners.</p>
				{internal.length === 0 ? <p className="footnote">No container-only ports were reported.</p> : <ul>{internal.map(({ workload, ports }) => <li key={workload.name}><strong>{workload.name}</strong><span>{ports.map(formatPortBinding).join(", ")}</span></li>)}</ul>}
			</details>
		</section>
	);
}

function PanelHeading({
  eyebrow,
  title,
  id,
  children,
  icon,
  accent = "green",
}: {
  eyebrow: string;
  title: string;
  id: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
  accent?: Accent;
}) {
  return (
    <div className="section-heading">
      <div className="heading-identity">
        {icon && <span className={`section-icon ${accent}`}>{icon}</span>}
        <div><p className="eyebrow">{eyebrow}</p><h2 id={id}>{title}</h2></div>
      </div>
      <p>{children}</p>
    </div>
  );
}

function FirewallPanel({ profiles, isLinux }: { profiles: FirewallProfileStatus[]; isLinux: boolean }) {
  return (
    <section className="panel" aria-labelledby="firewall-title">
      <PanelHeading eyebrow="NETWORK BOUNDARY" title="Host firewall" id="firewall-title" icon={<FirewallIcon />} accent="amber">
        Reported host-level inbound and outbound policy
      </PanelHeading>
      <div className="profile-grid">
        {profiles.length === 0 ? (
          <p className="empty-state">Firewall profile data is unavailable.</p>
        ) : profiles.map((profile) => (
          <article className="profile-card" key={profile.name}>
            <header>
              <h3>{profile.name}</h3>
              <StatusChip
                label={profile.enabled === true ? "On" : profile.enabled === false ? "Off" : "Unknown"}
                tone={profile.enabled === true ? "healthy" : profile.enabled === false ? "danger" : "unknown"}
              />
            </header>
            <dl>
			  <div><dt>{isLinux && profile.enabled === false ? "Configured inbound default (inactive)" : "Inbound default"}</dt><dd>{policyValue(profile.defaultInboundAction)}</dd></div>
			  <div><dt>{isLinux && profile.enabled === false ? "Configured outbound default (inactive)" : "Outbound default"}</dt><dd>{policyValue(profile.defaultOutboundAction)}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function ConnectionsPanel({ deviceId, operatingSystem, connections, workloads, expectedServices, observations, saveExpectation, saveExpectations, removeExpectation, busy }: { deviceId: string; operatingSystem: string; connections: NetworkConnection[]; workloads: WorkloadInventory | null; expectedServices: ExpectedService[]; observations: ObservedListener[]; saveExpectation: (service: ExpectedServiceInput) => void; saveExpectations: (services: ExpectedServiceInput[]) => void; removeExpectation: (service: ExpectedService) => void; busy: boolean }) {
  const [filter, setFilter] = useState("");
	const [view, setView] = useState<"review" | "expected" | "local" | "active">("review");
	const [manualLabel, setManualLabel] = useState("");
	const [manualProtocol, setManualProtocol] = useState<"TCP" | "UDP">("TCP");
	const [manualPort, setManualPort] = useState("");
	const [manualScope, setManualScope] = useState<BindScope>("any");
	const listeners = useMemo(() => logicalListeners(connections), [connections]);
	const active = useMemo(() => connections.filter((connection) => connection.state.toLowerCase() === "established"), [connections]);
	const expectedFor = useCallback((listener: LogicalListener) => expectedServices.find((service) => expectedServiceMatches(listener, service, workloads)), [expectedServices, workloads]);
	const reviewListeners = listeners.filter((listener) => listener.bindScope !== "local" && !expectedFor(listener));
	const expectedListeners = listeners.filter((listener) => !!expectedFor(listener));
	const localListeners = listeners.filter((listener) => listener.bindScope === "local" && !expectedFor(listener));
	const shownListeners = view === "review" ? reviewListeners : view === "expected" ? expectedListeners : view === "local" ? localListeners : [];
	const baselineSuggestions = useMemo(() => suggestedBaseline(deviceId, operatingSystem, listeners, workloads, expectedServices), [deviceId, operatingSystem, listeners, workloads, expectedServices]);
	const suggestionSignature = baselineSuggestions.map((suggestion) => suggestion.id).join("|");
	const [selectedSuggestions, setSelectedSuggestions] = useState<Set<string>>(new Set());
	useEffect(() => setSelectedSuggestions(new Set(baselineSuggestions.map((suggestion) => suggestion.id))), [deviceId, suggestionSignature]);
	const selectedBaseline = baselineSuggestions.filter((suggestion) => selectedSuggestions.has(suggestion.id));
  const filtered = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return connections;
    return connections.filter((connection) =>
      Object.values(connection).some((value) => String(value).toLowerCase().includes(query))
      || endpointScope(connection).toLowerCase().includes(query),
    );
  }, [connections, filter]);
	const ownerAttributionAvailable = connections.some((connection) => connection.processName || connection.processId > 0 || connection.systemdUnit);
	const markExpected = (listener: LogicalListener) => {
		const entered = window.prompt(`Friendly name for ${listener.protocol} port ${listener.port} (for example, SSH or WireGuard).`, `${listener.protocol} ${listener.port}`);
		if (entered === null || entered.trim() === "") return;
		saveExpectation({ deviceId, label: entered.trim(), protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: workloadAttribution(listener, workloads).map(({ workload }) => workload.name), systemdUnits: listener.systemdUnits });
	};
	const addManual = (event: React.FormEvent) => {
		event.preventDefault();
		const port = Number(manualPort);
		if (!manualLabel.trim() || !Number.isInteger(port) || port < 1 || port > 65535) return;
		saveExpectation({ deviceId, label: manualLabel.trim(), protocol: manualProtocol, port, portEnd: port, bindScope: manualScope, processNames: [], workloadNames: [], systemdUnits: [] });
		setManualLabel("");
		setManualPort("");
	};
	const observationFor = (listener: LogicalListener) => observations.find((item) => item.present && item.protocol === listener.protocol && item.port === listener.port && item.bindScope === listener.bindScope);

  return (
    <section className="panel connections-panel" aria-labelledby="connections-title">
      <div className="section-heading connections-heading">
		<div className="heading-identity"><span className="section-icon cyan"><NetworkIcon /></span><div><p className="eyebrow">SERVICE EXPOSURE · NOT A THREAT LIST</p><h2 id="connections-title">Listener review</h2></div></div>
		<p>{listeners.length} logical service endpoint{listeners.length === 1 ? "" : "s"} from {connections.filter((item) => ["listen", "open", "bound"].includes(item.state.toLowerCase())).length} raw sockets</p>
	  </div>
	  <p className="service-explainer">HAVEN groups IPv4/IPv6 duplicates and asks you to classify intended services. “Unreviewed” means no expectation has been saved yet—it does not mean malicious or Internet-accessible.</p>
	  {baselineSuggestions.length > 0 && <section className="baseline-review" aria-labelledby="baseline-review-title">
		<div className="baseline-review-heading"><div><p className="eyebrow">ONE-TIME REVIEW</p><h3 id="baseline-review-title">Suggested service baseline</h3></div><StatusChip label={`${baselineSuggestions.length} suggestion${baselineSuggestions.length === 1 ? "" : "s"}`} tone="configured" /></div>
		<p>These are high-confidence suggestions derived from platform roles, current process or system-service ownership, and Docker workload mappings. Nothing becomes trusted until you approve it; unchecked listeners remain visible for individual review.</p>
		<div className="baseline-suggestion-list">
		  {baselineSuggestions.map((suggestion) => <label className="baseline-suggestion" key={suggestion.id}><input type="checkbox" checked={selectedSuggestions.has(suggestion.id)} disabled={busy} onChange={(event) => setSelectedSuggestions((current) => { const next = new Set(current); if (event.target.checked) next.add(suggestion.id); else next.delete(suggestion.id); return next; })} /><span><strong>{suggestion.title}</strong><small>{suggestion.description}</small></span><em>{suggestion.listenerKeys.length} listener{suggestion.listenerKeys.length === 1 ? "" : "s"}</em></label>)}
		</div>
		<div className="baseline-review-actions"><span>{selectedBaseline.reduce((count, suggestion) => count + suggestion.listenerKeys.length, 0)} current listener{selectedBaseline.reduce((count, suggestion) => count + suggestion.listenerKeys.length, 0) === 1 ? "" : "s"} covered</span><button type="button" disabled={busy || selectedBaseline.length === 0} onClick={() => saveExpectations(selectedBaseline.flatMap((suggestion) => suggestion.services))}>{busy ? "Saving…" : `Approve selected baseline (${selectedBaseline.length})`}</button></div>
	  </section>}
	  <div className="endpoint-tabs" role="tablist" aria-label="Endpoint categories">
		<button className={view === "review" ? "selected" : ""} type="button" onClick={() => setView("review")}>Needs review <span>{reviewListeners.length}</span></button>
		<button className={view === "expected" ? "selected" : ""} type="button" onClick={() => setView("expected")}>Expected <span>{expectedListeners.length}</span></button>
		<button className={view === "local" ? "selected" : ""} type="button" onClick={() => setView("local")}>Local only <span>{localListeners.length}</span></button>
		<button className={view === "active" ? "selected" : ""} type="button" onClick={() => setView("active")}>Active connections <span>{active.length}</span></button>
	  </div>
	  {view !== "active" && <div className="service-grid">
		{shownListeners.length === 0 ? <p className="activity-empty"><strong>{view === "review" ? "No unreviewed non-local listeners." : `No ${view === "expected" ? "expected" : "unclassified local-only"} listeners are active.`}</strong><span>{view === "review" ? "New non-local services will appear here for classification." : "Choose another category or inspect the raw technical details below."}</span></p> : shownListeners.map((listener) => {
		  const expectation = expectedFor(listener);
		  const observation = observationFor(listener);
		  const attributions = workloadAttribution(listener, workloads);
		  const recentlyAppeared = !!observation && Date.now() - new Date(observation.appearedAt).valueOf() < 24 * 60 * 60 * 1000;
		  return <article className={`service-card ${expectation ? "expected" : listener.bindScope === "local" ? "local" : "review"}`} key={listener.key}>
			<div className="service-card-heading"><div><span className="protocol">{listener.protocol}</span><strong>Port {listener.port}</strong></div><StatusChip label={expectation ? "expected" : recentlyAppeared ? "new · unreviewed" : listener.bindScope === "local" ? "local only" : "unreviewed"} tone={expectation ? "healthy" : listener.bindScope === "local" ? "configured" : "attention"} /></div>
			<h3>{expectation?.label || (attributions.length === 1 ? attributions[0].workload.name : `${listener.protocol} service on port ${listener.port}`)}</h3>
			<dl><div><dt>Bind scope</dt><dd>{bindScopeLabel(listener.bindScope)}</dd></div><div><dt>State</dt><dd>{listener.state}</dd></div><div><dt>Addresses</dt><dd className="endpoint">{listener.addresses.join(", ") || "Not reported"}</dd></div>{listener.processes.length > 0 && <div><dt>Host process</dt><dd>{listener.processes.join(", ")}</dd></div>}{listener.systemdUnits.length > 0 && <div><dt>System service</dt><dd>{listener.systemdUnits.join(", ")}</dd></div>}{attributions.length > 0 && <><div><dt>Runtime owner</dt><dd>{attributions.map(({ workload }) => workload.name).join(", ")}</dd></div><div><dt>Docker mapping</dt><dd className="endpoint">{attributions.flatMap(({ bindings }) => bindings).map(formatPortBinding).join(", ")}</dd></div></>}</dl>
			<p>{observation ? `First observed ${formatDate(observation.firstSeenAt)} · continuously present since ${formatDate(observation.appearedAt)} · last confirmed ${formatRelativeTime(observation.lastSeenAt)}` : "Appearance history will begin with the next agent report."}{listener.rawCount > 1 ? ` · ${listener.rawCount} raw sockets grouped` : ""}</p>
			{expectation ? <button className="secondary-action" type="button" disabled={busy} onClick={() => removeExpectation(expectation)}>Remove expectation</button> : <button className="secondary-action" type="button" disabled={busy} onClick={() => markExpected(listener)}>Mark expected…</button>}
		  </article>;
		})}
	  </div>}
	  {view === "active" && <div className="table-wrap compact-table"><table><thead><tr><th>Protocol</th><th>Local endpoint</th><th>Remote endpoint</th><th>Owner</th><th>State</th></tr></thead><tbody>{active.length === 0 ? <tr><td colSpan={5} className="empty-state">No established TCP connections were returned.</td></tr> : active.map((connection) => <tr key={`${connection.protocol}-${connection.processId}-${connection.localAddress}-${connection.localPort}-${connection.remoteAddress}-${connection.remotePort}`}><td className="protocol">{connection.protocol}</td><td className="endpoint">{endpoint(connection.localAddress, connection.localPort)}</td><td className="endpoint">{endpoint(connection.remoteAddress, connection.remotePort)}</td><td>{connection.processName || connection.systemdUnit || "Not attributed"}{connection.processId > 0 ? ` · PID ${connection.processId}` : ""}</td><td className="state">{connection.state}</td></tr>)}</tbody></table></div>}
	  <details className="expectation-registry">
		<summary>Manage expected-service registry ({expectedServices.length})</summary>
		<p>Expectations are local HAVEN metadata. They do not open ports or change firewall rules.</p>
		<form className="expectation-form" onSubmit={addManual}><label><span>Friendly label</span><input maxLength={80} value={manualLabel} onChange={(event) => setManualLabel(event.target.value)} placeholder="SSH" /></label><label><span>Protocol</span><select value={manualProtocol} onChange={(event) => setManualProtocol(event.target.value as "TCP" | "UDP")}><option>TCP</option><option>UDP</option></select></label><label><span>Port</span><input type="number" min={1} max={65535} value={manualPort} onChange={(event) => setManualPort(event.target.value)} placeholder="22" /></label><label><span>Expected bind</span><select value={manualScope} onChange={(event) => setManualScope(event.target.value as BindScope)}><option value="any">Any bind</option><option value="local">This host only</option><option value="private">Private address</option><option value="wildcard">All interfaces</option><option value="specific">Specific address</option></select></label><button type="submit" disabled={busy || !manualLabel.trim() || !manualPort}>Add expectation</button></form>
		{expectedServices.length > 0 && <ul className="registry-list">{expectedServices.map((service) => <li key={service.id}><span><strong>{service.label}</strong><small>{service.protocol} {service.portEnd > service.port ? `${service.port}–${service.portEnd}` : service.port} · {bindScopeLabel(service.bindScope)}{service.processNames?.length ? ` · processes: ${service.processNames.join(", ")}` : ""}{service.workloadNames?.length ? ` · workloads: ${service.workloadNames.join(", ")}` : ""}{service.systemdUnits?.length ? ` · services: ${service.systemdUnits.join(", ")}` : ""}</small></span><button type="button" disabled={busy} onClick={() => removeExpectation(service)}>Remove</button></li>)}</ul>}
	  </details>
	  <details className="raw-endpoints">
		<summary>Raw technical details ({connections.length})</summary>
		<label className="search-field"><span className="sr-only">Filter raw endpoints</span><input type="search" placeholder="Filter protocol, scope, address, or state" autoComplete="off" value={filter} onChange={(event) => setFilter(event.target.value)} /></label>
		{!ownerAttributionAvailable && connections.length > 0 && <p className="footnote">Process and system-service attribution are unavailable to this least-privilege agent, so HAVEN omits the repetitive empty owner column.</p>}
		<div className="table-wrap">
        <table>
		  <thead><tr><th>Protocol</th>{ownerAttributionAvailable && <th>Owner</th>}<th>Local endpoint</th><th>Remote endpoint</th><th>Bind scope</th><th>State</th></tr></thead>
          <tbody>
            {filtered.length === 0 ? (
			  <tr><td colSpan={ownerAttributionAvailable ? 6 : 5} className="empty-state">{connections.length ? "No endpoints match this filter." : "No network endpoints were returned."}</td></tr>
            ) : filtered.map((connection) => (
              <tr key={`${connection.protocol}-${connection.processId}-${connection.localAddress}-${connection.localPort}-${connection.remoteAddress}-${connection.remotePort}-${connection.state}`}>
                <td className="protocol">{connection.protocol}</td>
				{ownerAttributionAvailable && <td><div className="process-name">{connection.processName || connection.systemdUnit || "Not attributed"}</div>{connection.processName && connection.systemdUnit && <div className="process-id">{connection.systemdUnit}</div>}{connection.processId > 0 && <div className="process-id">PID {connection.processId}</div>}</td>}
                <td className="endpoint">{endpoint(connection.localAddress, connection.localPort)}</td>
				<td className="endpoint">{["listen", "open", "bound"].includes(connection.state.toLowerCase()) ? "—" : endpoint(connection.remoteAddress, connection.remotePort)}</td>
                <td className="scope">{endpointScope(connection)}</td>
                <td className="state">{connection.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
		</div>
		<p className="footnote">Showing {filtered.length} of {connections.length} raw live endpoints. Bind scope describes the local address—not proven LAN or Internet reachability. Payload contents and remote connection history are never captured or stored.</p>
	  </details>
    </section>
  );
}

function baselineIcon(id: string) {
  if (id === "defender" || id === "threats") return <DefenderIcon />;
  if (id === "firewall" || id === "linux-firewall") return <FirewallIcon />;
  if (id === "updates" || id === "linux-updates" || id === "linux-reboot" || id === "linux-automatic-updates") return <UpdateIcon />;
  if (id === "encryption") return <LockIcon />;
  if (id === "secure-boot" || id === "tpm" || id === "linux-apparmor" || id === "linux-time") return <ChipIcon />;
  if (id === "remote-access" || id === "linux-ssh") return <RemoteAccessIcon />;
  if (id === "local-admins") return <UsersIcon />;
  if (id === "linux-services" || id === "linux-storage") return <ServerIcon />;
  return <HelpIcon />;
}

function FindingsPanel({ findings, checks, reviews, review }: { findings: SecurityFinding[]; checks: BaselineCheck[]; reviews: FindingReview[]; review: (finding: SecurityFinding, state: FindingReviewState) => void }) {
  const ordered = [...findings].sort((left, right) => ({ high: 0, medium: 1, low: 2 }[left.severity] - { high: 0, medium: 1, low: 2 }[right.severity]));
  const unknown = checks.filter((check) => check.status === "unknown").length;
  return (
    <section className={`panel findings-panel ${ordered.length === 0 ? "clear" : ""}`} aria-labelledby="findings-title">
      <PanelHeading eyebrow="PRIORITIZED REVIEW" title={ordered.length === 0 ? "No actionable findings" : `${ordered.length} finding${ordered.length === 1 ? "" : "s"} to review`} id="findings-title" icon={ordered.length === 0 ? <CheckIcon /> : <AlertIcon />} accent={ordered.length === 0 ? "green" : "amber"}>
        {unknown > 0 ? `${unknown} check${unknown === 1 ? " is" : "s are"} still unknown` : "All available baseline signals were evaluated"}
      </PanelHeading>
      {ordered.length === 0 ? (
        <p className="findings-clear-copy">HAVEN did not derive an action from the signals it could verify. This is a baseline review, not a guarantee that the device is malware-free.</p>
      ) : (
        <div className="findings-list">
          {ordered.map((finding) => {
            const currentReview = reviews.find((item) => item.findingId === finding.id && (item.state !== "snoozed" || !item.snoozedUntil || new Date(item.snoozedUntil) > new Date()));
            return <article className={`finding-card severity-${finding.severity}`} key={finding.id}>
              <div className="finding-heading"><span className="finding-icon">{finding.severity === "low" ? <HelpIcon /> : <AlertIcon />}</span><div><p className="finding-category">{finding.category}</p><h3>{finding.title}</h3></div><span className="severity-label">{finding.severity}</span></div>
              <p>{finding.summary}</p>
              <div className="next-step"><strong>Suggested next step</strong><span>{finding.recommendation}</span></div>
              {currentReview && <div className="review-summary"><StatusChip label={currentReview.state.replaceAll("-", " ")} tone="configured" /><span>{currentReview.note || (currentReview.snoozedUntil ? `Snoozed until ${formatDate(currentReview.snoozedUntil)}` : `Reviewed ${formatDate(currentReview.reviewedAt)}`)}</span></div>}
              <div className="review-actions">{currentReview && currentReview.state !== "new" && <button type="button" onClick={() => review(finding, "new")}>Mark new</button>}<button type="button" onClick={() => review(finding, "acknowledged")}>Acknowledge…</button><button type="button" onClick={() => review(finding, "snoozed")}>Snooze 24h</button><button type="button" onClick={() => review(finding, "accepted-risk")}>Accept risk…</button></div>
            </article>;
          })}
        </div>
      )}
    </section>
  );
}

function PasskeyPanel({ passkeys, add, remove, busy }: { passkeys: PasskeyInfo[]; add: () => void; remove: (passkey: PasskeyInfo) => void; busy: boolean }) {
  return (
    <section className="panel passkey-panel" aria-labelledby="passkeys-title">
      <PanelHeading eyebrow="CROSS-PLATFORM ACCESS" title="Owner passkeys" id="passkeys-title" icon={<LockIcon />} accent="green">Register a passkey from each trusted computer, phone, or hardware security key</PanelHeading>
      <div className="passkey-list">{passkeys.map((passkey) => <article className="passkey-card" key={passkey.id}><span className="passkey-icon"><LockIcon size={18} /></span><div><h3>{passkey.label}</h3><p>Added {formatDate(passkey.createdAt)} · {passkey.lastUsedAt ? `Last used ${formatDate(passkey.lastUsedAt)}` : "Not used for sign-in yet"}</p></div><button type="button" disabled={busy || passkeys.length <= 1} title={passkeys.length <= 1 ? "Add a replacement before removing the final passkey" : "Remove this passkey"} onClick={() => remove(passkey)}>Remove</button></article>)}</div>
      <button className="secondary-action" type="button" disabled={busy} onClick={add}>Add a passkey</button>
      <p className="footnote">Adding or removing a passkey requires confirmation from an existing passkey. If every passkey is lost, a short-lived recovery code can be generated locally on the hub.</p>
    </section>
  );
}

function ActionCenter({ actions, audit, capabilities, run, busy }: { actions: SecurityAction[]; audit: AuditEvent[]; capabilities: ActionCapability[]; run: (kind: SecurityActionKind) => void; busy: boolean }) {
  const latest = actions.slice(0, 5);
  return (
    <section className="panel action-center" aria-labelledby="action-center-title">
      <PanelHeading eyebrow="CAPABILITY-BASED CONTROLS" title="Action center" id="action-center-title" icon={<ChipIcon />} accent="blue">Each hub or enrolled agent advertises only the fixed actions its platform supports</PanelHeading>
      <div className="action-grid">
		{capabilities.length === 0 ? <p className="muted-copy">No controls are advertised for the selected device. Observation remains read-only.</p> : capabilities.map((capability) => {
          const active = actions.some((item) => item.kind === capability.id && (item.status === "queued" || item.status === "running"));
          return <article className="action-card" key={capability.id}>{capability.provider.includes("Defender") ? <DefenderIcon /> : <ChipIcon />}<div><p className="finding-category">{capability.provider} · {capability.platform}</p><h3>{capability.label}</h3><p>{capability.description}</p></div><button type="button" disabled={busy || active} onClick={() => run(capability.id)}>{active ? "Action in progress" : capability.requiresReauthorization ? "Confirm and run" : "Run"}</button></article>;
        })}
      </div>
      <div className="action-history-grid">
        <div><h3>Recent control requests</h3>{latest.length === 0 ? <p className="muted-copy">No control actions requested yet.</p> : <ol className="compact-history">{latest.map((item) => <li key={item.id}><span><strong>{capabilities.find((capability) => capability.id === item.kind)?.label || item.kind.replaceAll("-", " ")}</strong><small>{formatDate(item.requestedAt)}</small></span><StatusChip label={item.status} tone={item.status === "succeeded" ? "healthy" : item.status === "failed" ? "danger" : "attention"} /></li>)}</ol>}</div>
        <div><h3>Audit trail</h3>{audit.length === 0 ? <p className="muted-copy">No owner decisions recorded yet.</p> : <ol className="compact-history">{audit.slice(0, 6).map((item) => <li key={item.id}><span><strong>{item.action.replaceAll(".", " ")}</strong><small>{item.detail} · {formatDate(item.occurredAt)}</small></span><StatusChip label={item.outcome} tone={item.outcome === "failed" ? "danger" : "configured"} /></li>)}</ol>}</div>
      </div>
    </section>
  );
}

function AwaitingAgents({ devices, runtime, passkeys, actions, audit, error, selectDevice, addOwnerPasskey, removeOwnerPasskey, actionBusy, signOut }: { devices: DeviceRecord[]; runtime: RuntimeStatus | null; passkeys: PasskeyInfo[]; actions: SecurityAction[]; audit: AuditEvent[]; error: string | null; selectDevice: (id: string) => void; addOwnerPasskey: () => void; removeOwnerPasskey: (passkey: PasskeyInfo) => void; actionBusy: boolean; signOut: () => void }) {
  const awaiting = devices.some((device) => device.status === "awaiting-first-report");
  return <>
    <header className="topbar">
      <a className="brand" href="/" aria-label="HAVEN home"><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
      <div className="topbar-actions"><span className="local-pill"><span className="local-dot" />Hub ready</span><button className="signout-button" type="button" onClick={signOut}>Lock</button></div>
    </header>
    <main>
      <DeviceInventory devices={devices} selectedId="" select={selectDevice} demoMode={false} />
      {error && <p className="inline-error" role="alert">{error}</p>}
      <section className="panel awaiting-panel">
        <PanelHeading eyebrow="NATIVE AGENTS" title={awaiting ? "Waiting for the first observation" : "No endpoints are enrolled yet"} id="awaiting-title" icon={<DevicesIcon />} accent="cyan">The production hub stores and explains observations; native agents collect them from each operating system</PanelHeading>
        <div className="activity-empty"><strong>{awaiting ? "An enrolled agent has not reported yet." : "The hub is healthy and ready for its first trusted endpoint."}</strong><span>Once ADAM-PC reports, its real Windows Defender, firewall, baseline, and connection signals will appear here. Container identities are never treated as household devices.</span></div>
      </section>
      <PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} />
      <ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={() => undefined} busy={actionBusy} />
    </main>
    <footer><span>HAVEN milestone 0.7 · Native agent hub</span><span>Observe continuously. Act deliberately.</span></footer>
  </>;
}

interface FindingLifecycle {
  event: SecurityEvent;
  openedAt: string | null;
}

function latestFindingLifecycles(events: SecurityEvent[]) {
  const ordered = [...events].sort((left, right) => new Date(right.occurredAt).valueOf() - new Date(left.occurredAt).valueOf() || right.id - left.id);
  const seen = new Set<string>();
  const lifecycles: FindingLifecycle[] = [];
  for (const event of ordered) {
    const key = `${event.deviceId}:${event.findingId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const opened = event.kind === "opened" ? event : ordered.find((candidate) => candidate.deviceId === event.deviceId && candidate.findingId === event.findingId && candidate.kind === "opened" && new Date(candidate.occurredAt) <= new Date(event.occurredAt));
    lifecycles.push({ event, openedAt: opened?.occurredAt || null });
  }
  return lifecycles.sort((left, right) => Number(left.event.kind === "resolved") - Number(right.event.kind === "resolved") || new Date(right.event.occurredAt).valueOf() - new Date(left.event.occurredAt).valueOf());
}

function ActivityPanel({ events }: { events: SecurityEvent[] }) {
  const recent = useMemo(() => latestFindingLifecycles(events).slice(0, 12), [events]);
  const activeCount = recent.filter((item) => item.event.kind === "opened").length;
  const resolvedCount = recent.filter((item) => item.event.kind === "resolved").length;
  return (
    <section className="panel activity-panel" aria-labelledby="activity-title">
      <PanelHeading eyebrow="WHAT CHANGED" title="Current findings and resolved history" id="activity-title" icon={<ActivityIcon />} accent="cyan">
		{recent.length > 0 ? `${activeCount} current · ${resolvedCount} resolved` : "Latest lifecycle only; superseded historical entries stay out of the active-looking list"}
      </PanelHeading>
      {recent.length === 0 ? (
        <p className="activity-empty"><strong>No posture changes recorded yet.</strong><span>HAVEN will add an event when a finding appears or resolves; routine unchanged observations stay quiet.</span></p>
      ) : (
        <ol className="activity-list">
          {recent.map(({ event, openedAt }) => {
            const resolved = event.kind === "resolved";
            const tone: Tone = resolved ? "healthy" : event.severity === "high" ? "danger" : event.severity === "medium" ? "attention" : "configured";
            return (
              <li className={`activity-item ${resolved ? "resolved" : `severity-${event.severity}`}`} key={event.id}>
                <span className="activity-marker">{resolved ? <CheckIcon size={17} /> : <AlertIcon size={17} />}</span>
                <div className="activity-copy">
                  <div className="activity-heading"><div><p>{event.category} · {event.deviceName}</p><h3>{resolved ? `Resolved: ${event.title}` : event.title}</h3></div><StatusChip label={resolved ? "resolved" : `active · ${event.severity}`} tone={tone} /></div>
                  <p><strong>{resolved ? "Resolved." : "Currently active."}</strong> {resolved ? "The latest observation no longer derives this finding." : event.summary}</p>
                  <time dateTime={event.occurredAt}>{resolved ? `${openedAt ? `Opened ${formatDate(openedAt)} · ` : ""}Resolved ${formatDate(event.occurredAt)}` : `Active since ${formatDate(event.occurredAt)}`}</time>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function BaselinePanel({ checks, collectedAt, platform }: { checks: BaselineCheck[]; collectedAt: string; platform: string }) {
  if (checks.length === 0) return null;
  const passing = checks.filter((check) => check.status === "pass").length;
  const configured = checks.filter((check) => check.status === "configured").length;
	const attention = checks.filter((check) => check.status === "attention").length;
	const unknown = checks.filter((check) => check.status === "unknown").length;
  const statusLabel = (status: BaselineCheck["status"]) => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "review" : "not verified";
  const statusTone = (status: BaselineCheck["status"]): Tone => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "attention" : "unknown";
  return (
    <section className="panel baseline-panel" aria-labelledby="baseline-title">
      <PanelHeading eyebrow={`${platform.toUpperCase()} SECURITY BASELINE`} title="Posture checks" id="baseline-title" icon={<ChipIcon />} accent="blue">
		{passing} healthy{configured > 0 ? ` · ${configured} configured` : ""}{attention > 0 ? ` · ${attention} to review` : ""}{unknown > 0 ? ` · ${unknown} not verified` : ""}
      </PanelHeading>
      <div className="baseline-grid">
        {checks.map((check) => (
          <article className={`baseline-card status-${check.status}`} key={check.id}>
            <div className="baseline-card-heading"><span className="baseline-icon">{baselineIcon(check.id)}</span><StatusChip label={statusLabel(check.status)} tone={statusTone(check.status)} /></div>
            <p className="baseline-category">{check.category}</p>
            <h3>{check.title}</h3>
            <p>{check.summary}</p>
            {check.evidence && <span className="baseline-evidence">{check.evidence}</span>}
            <span className="baseline-observed">Observed {formatDate(collectedAt)}</span>
          </article>
        ))}
      </div>
    </section>
  );
}

function Application({ snapshot, devices, events, runtime, selectedDevice, selectDevice, refresh, refreshing, error, demoMode, alertsEnabled, alertsSupported, enableAlerts, reviews, expectedServices, listenerObservations, audit, actions, passkeys, reviewFinding, saveServiceExpectation, saveServiceExpectations, removeServiceExpectation, runAction, addOwnerPasskey, removeOwnerPasskey, actionBusy, signOut }: { snapshot: SecuritySnapshot; devices: DeviceRecord[]; events: SecurityEvent[]; runtime: RuntimeStatus | null; selectedDevice: DeviceRecord | null; selectDevice: (id: string) => void; refresh: () => void; refreshing: boolean; error: string | null; demoMode: boolean; alertsEnabled: boolean; alertsSupported: boolean; enableAlerts: () => void; reviews: FindingReview[]; expectedServices: ExpectedService[]; listenerObservations: ObservedListener[]; audit: AuditEvent[]; actions: SecurityAction[]; passkeys: PasskeyInfo[]; reviewFinding: (finding: SecurityFinding, state: FindingReviewState) => void; saveServiceExpectation: (service: ExpectedServiceInput) => void; saveServiceExpectations: (services: ExpectedServiceInput[]) => void; removeServiceExpectation: (service: ExpectedService) => void; runAction: (kind: SecurityActionKind) => void; addOwnerPasskey: () => void; removeOwnerPasskey: (passkey: PasskeyInfo) => void; actionBusy: boolean; signOut: () => void }) {
  const isLinux = snapshot.linuxBaseline !== null || /linux|ubuntu/i.test(snapshot.device.operatingSystem);
  const defenderHealthy = snapshot.defender?.antivirusEnabled === true
    && snapshot.defender.realTimeProtectionEnabled === true
    && snapshot.defender.tamperProtected !== false;
  const firewallsKnown = snapshot.firewallProfiles.length > 0;
  const firewallsEnabled = firewallsKnown && snapshot.firewallProfiles.every((profile) => profile.enabled === true);
  const established = snapshot.connections.filter((item) => item.state.toLowerCase() === "established").length;
	const listeners = logicalListeners(snapshot.connections);
	const broadListeners = listeners.filter((item) => item.bindScope === "wildcard").length;
	const workloadInventory = snapshot.linuxBaseline?.workloads ?? null;
	const unreviewedListeners = listeners.filter((listener) => listener.bindScope !== "local" && !expectedServices.some((service) => expectedServiceMatches(listener, service, workloadInventory))).length;
	const findingCount = (snapshot.findings || []).length;
	const unknownChecks = (snapshot.baselineChecks || []).filter((check) => check.status === "unknown").length;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/" aria-label="HAVEN home"><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
        <div className="topbar-actions">
          <span className={`local-pill ${demoMode ? "demo-pill" : ""}`}><span className="local-dot" />{demoMode ? "Synthetic demo" : runtime?.localCollection ? "Local monitor" : "Agent hub"}</span>
          {!demoMode && alertsSupported && <button className={`desktop-alert-button ${alertsEnabled ? "enabled" : ""}`} type="button" onClick={enableAlerts} disabled={alertsEnabled} aria-label={alertsEnabled ? "Desktop alerts enabled" : "Enable desktop alerts"}><BellIcon size={15} /><span>{alertsEnabled ? "Alerts on" : "Enable alerts"}</span></button>}
          {!demoMode && <button className="refresh-button" type="button" onClick={refresh} disabled={refreshing}>{refreshing ? (runtime?.localCollection ? "Collecting…" : "Refreshing…") : <><RefreshIcon size={15} />{runtime?.localCollection ? "Collect now" : "Refresh view"}</>}</button>}
          {!demoMode && <button className="signout-button" type="button" onClick={signOut}>Lock</button>}
        </div>
      </header>
      <main>
        <DeviceInventory devices={devices} selectedId={selectedDevice?.id || snapshot.device.deviceId || ""} select={selectDevice} demoMode={demoMode} />
        {demoMode && <p className="demo-banner" role="status"><strong>Synthetic demo mode.</strong> Every device and observation on this page is invented. HAVEN is not showing or collecting data from this computer.</p>}
        {!demoMode && <p className="context-banner"><strong>Continuous, read-only monitoring.</strong> {runtime?.localCollection ? `HAVEN observes this computer every ${runtime.monitor.enabled ? formatInterval(runtime.monitor.intervalSeconds) : "configured interval"}.` : "A native agent reports this endpoint's security posture to the private HAVEN hub on its own schedule; this page checks the hub for a newer report every minute."} The current-posture sections always come from the latest observation. The activity section retains only the latest lifecycle for each finding, while routine unchanged observations stay quiet.</p>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        <section className="hero" aria-labelledby="device-name">
          <div className="hero-identity"><span className="hero-device-icon">{snapshot.device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon size={28} /> : selectedDevice?.displayName.toLowerCase().includes("laptop") ? <LaptopIcon size={28} /> : <MonitorIcon size={28} />}</span><div><p className="eyebrow">{selectedDevice?.trustState === "local" ? "THIS DEVICE" : "DEVICE OBSERVATION"}</p><h1 id="device-name">{selectedDevice?.displayName || snapshot.device.hostName}</h1><p className="device-detail">{snapshot.device.hostName} · {snapshot.device.operatingSystem} · {snapshot.device.architecture} · {formatDuration(snapshot.device.uptimeSeconds)}</p></div></div>
          <div className="collection-time"><span>Last observation</span><strong>{formatRelativeTime(snapshot.collectedAt)}</strong><time dateTime={snapshot.collectedAt}>{formatDate(snapshot.collectedAt)}</time></div>
        </section>
        <section className="summary-grid" aria-label="Security summary">
		  <SummaryCard icon={isLinux ? <ChipIcon /> : <DefenderIcon />} accent="blue" title={isLinux ? "Host posture" : "Protection"} label={isLinux ? (findingCount > 0 ? `${findingCount} to review` : unknownChecks > 0 ? `${unknownChecks} unverified` : "No findings") : snapshot.defender ? (defenderHealthy ? "Protected" : "Attention") : "Unavailable"} tone={isLinux ? (findingCount > 0 ? "attention" : unknownChecks > 0 ? "unknown" : "healthy") : snapshot.defender ? (defenderHealthy ? "healthy" : "attention") : "unknown"}>{isLinux ? (findingCount > 0 ? `AppArmor and automatic updates are platform protections, but ${findingCount} current finding${findingCount === 1 ? " still needs" : "s still need"} review.` : unknownChecks > 0 ? "No action is derived from the verified signals, but some checks remain unknown." : "No actionable finding was derived from the latest verified Linux signals.") : snapshot.defender ? (defenderHealthy ? "Antivirus and real-time monitoring are active." : "One or more protection signals are off or unavailable.") : "Defender status was not returned."}</SummaryCard>
          <SummaryCard icon={<FirewallIcon />} accent="amber" title="Firewall" label={firewallsKnown ? (firewallsEnabled ? "Enabled" : "Attention") : "Unavailable"} tone={firewallsKnown ? (firewallsEnabled ? "healthy" : "danger") : "unknown"}>{firewallsKnown ? (isLinux ? `${snapshot.firewallProfiles[0].name} is ${firewallsEnabled ? "enabled" : "disabled"} as the host firewall provider.` : firewallsEnabled ? `All ${snapshot.firewallProfiles.length} Windows Firewall profiles are enabled.` : "At least one Windows Firewall profile is disabled.") : "Firewall status was not returned."}</SummaryCard>
		  <SummaryCard icon={<NetworkIcon />} accent="cyan" title="Network" label={unreviewedListeners > 0 ? `${unreviewedListeners} unreviewed` : `${listeners.length} classified/local`} tone={unreviewedListeners > 0 ? "attention" : "healthy"}>{listeners.length} logical listener{listeners.length === 1 ? "" : "s"} ({broadListeners} on all interfaces) and {established} active connection{established === 1 ? "" : "s"}. Bind scope is not proof of Internet reachability.</SummaryCard>
          <SummaryCard icon={<ActivityIcon />} accent="green" title="Monitor" label={runtime?.localCollection && runtime.monitor.enabled ? `Every ${formatInterval(runtime.monitor.intervalSeconds)}` : formatRelativeTime(snapshot.collectedAt)} tone={selectedDevice?.status === "stale" || runtime?.monitor.lastCollectionError ? "attention" : "healthy"}>{runtime?.localCollection ? (runtime.monitor.lastCollectionError || (runtime.monitor.lastSuccessfulAt ? `Last automatic observation succeeded ${formatDate(runtime.monitor.lastSuccessfulAt)}.` : "Automatic monitoring is starting.")) : `Latest authenticated report was collected ${formatDate(snapshot.collectedAt)}. The view checks for newer hub data every minute.`}</SummaryCard>
        </section>
        {!demoMode && <><PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} /><ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={runAction} busy={actionBusy} /></>}
        <ActivityPanel events={events} />
        {(snapshot.baselineChecks || []).length > 0 && <><FindingsPanel findings={snapshot.findings || []} checks={snapshot.baselineChecks || []} reviews={reviews} review={reviewFinding} /><BaselinePanel checks={snapshot.baselineChecks || []} collectedAt={snapshot.collectedAt} platform={isLinux ? "Linux" : "Windows"} /></>}
        {snapshot.notices.length > 0 && <section className="panel notices-panel" aria-labelledby="notices-title"><PanelHeading eyebrow="COLLECTION NOTES" title="Some signals could not be verified" id="notices-title" icon={<AlertIcon />} accent="amber">A collection limitation is not automatically a security problem</PanelHeading><ul className="notices-list">{snapshot.notices.map((notice, index) => <li className="notice" key={`${notice.source}-${index}`}><strong>{notice.source}: </strong>{notice.message}</li>)}</ul></section>}
        {isLinux && snapshot.linuxBaseline ? <LinuxPanel baseline={snapshot.linuxBaseline} /> : <DefenderPanel defender={snapshot.defender} />}
		{isLinux && <WorkloadsPanel inventory={snapshot.linuxBaseline?.workloads ?? null} />}
		<FirewallPanel profiles={snapshot.firewallProfiles} isLinux={isLinux} />
		<ConnectionsPanel deviceId={selectedDevice?.id || snapshot.device.deviceId || ""} operatingSystem={snapshot.device.operatingSystem} connections={snapshot.connections} workloads={workloadInventory} expectedServices={expectedServices} observations={listenerObservations} saveExpectation={saveServiceExpectation} saveExpectations={saveServiceExpectations} removeExpectation={removeServiceExpectation} busy={actionBusy} />
      </main>
	  <footer><span>HAVEN milestone 0.7.5 · Linux service attribution</span><span>Observe continuously. Act deliberately.</span></footer>
    </>
  );
}

export function App() {
  const [authentication, setAuthentication] = useState<AuthStatus | null>(null);
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [reviews, setReviews] = useState<FindingReview[]>([]);
	const [expectedServices, setExpectedServices] = useState<ExpectedService[]>([]);
	const [listenerObservations, setListenerObservations] = useState<ObservedListener[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [actions, setActions] = useState<SecurityAction[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [demoMode, setDemoMode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [inventoryLoaded, setInventoryLoaded] = useState(false);
  const selectedIdRef = useRef("");
  const alertsSupported = typeof window !== "undefined" && "Notification" in window;
  const [alertsEnabled, setAlertsEnabled] = useState(() => alertsSupported && window.Notification.permission === "granted" && window.localStorage.getItem("haven.desktopAlerts") === "enabled");
  const lastNotifiedEvent = useRef<number>(typeof window === "undefined" ? -1 : Number(window.localStorage.getItem("haven.lastNotifiedEvent") ?? "-1"));

  const authenticate = useCallback(async (bootstrapCode?: string, label?: string) => {
    if (bootstrapCode === undefined) await loginWithPasskey();
    else await registerPasskey(bootstrapCode, label || "This device");
    setAuthentication(await getAuthStatus());
    setSnapshot(null);
  }, []);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const [initialInventory, runtimeStatus, activity] = await Promise.all([listDevices(signal), getRuntimeStatus(signal), listEvents(undefined, signal)]);
      let inventory = initialInventory;
      let observed: { id: string; snapshot: SecuritySnapshot } | null;
      if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
        const collected = await collectSnapshot(signal);
        inventory = await listDevices(signal);
        observed = { id: collected.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: collected };
      } else {
        observed = await latestEnrolledObservation(inventory, selectedIdRef.current, signal);
      }
      setSnapshot(observed?.snapshot || null);
      setDevices(inventory);
      setEvents(activity);
      setRuntime(runtimeStatus);
      setDemoMode(runtimeStatus.demoMode);
      const nextId = observed?.id || inventory.find((device) => device.status === "awaiting-first-report")?.id || "";
	  if (!runtimeStatus.demoMode && nextId) setListenerObservations(await listObservedListeners(nextId, signal));
      selectedIdRef.current = nextId;
      setSelectedId(nextId);
      setInventoryLoaded(true);
      setError(null);
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : "An unexpected collection error occurred.");
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, []);

  const selectDevice = useCallback(async (deviceId: string) => {
    setRefreshing(true);
    try {
      const detail = await getDevice(deviceId);
      if (!detail.snapshot) throw new Error("This device has not submitted its first observation yet.");
      setSnapshot(detail.snapshot);
      selectedIdRef.current = deviceId;
      setSelectedId(deviceId);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The device observation could not be loaded.");
    } finally {
      setRefreshing(false);
    }
  }, []);

  const loadControls = useCallback(async (deviceId: string, signal?: AbortSignal) => {
	const [findingReviews, serviceExpectations, observedListeners, recentAudit, recentActions, ownerPasskeys] = await Promise.all([
      deviceId ? listFindingReviews(deviceId, signal) : Promise.resolve([]),
	  deviceId ? listExpectedServices(deviceId, signal) : Promise.resolve([]),
	  deviceId ? listObservedListeners(deviceId, signal) : Promise.resolve([]),
      listAuditEvents(signal),
      listSecurityActions(signal),
      listPasskeys(signal),
    ]);
    setReviews(findingReviews);
	setExpectedServices(serviceExpectations);
	setListenerObservations(observedListeners);
    setAudit(recentAudit);
    setActions(recentActions);
    setPasskeys(ownerPasskeys);
  }, []);

  const reviewFinding = useCallback(async (finding: SecurityFinding, state: FindingReviewState) => {
    if (!selectedId) return;
    let note = "";
    let snoozedUntil: string | null = null;
    if (state === "accepted-risk" || state === "acknowledged") {
      const entered = window.prompt(state === "accepted-risk" ? `Why are you accepting the risk for “${finding.title}”? This note stays in HAVEN's local database and is omitted from the audit summary.` : `Optional note for “${finding.title}”. It stays in HAVEN's local database and is omitted from the audit summary.`);
      if (entered === null) return;
      note = entered.trim();
      if (state === "accepted-risk" && !note) { setError("Accepting risk requires a short reason."); return; }
    }
    if (state === "snoozed") snoozedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    try {
      await saveFindingReview({ deviceId: selectedId, findingId: finding.id, state, note, snoozedUntil });
      await loadControls(selectedId);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The finding review could not be saved.");
    }
  }, [loadControls, selectedId]);

	const saveServiceExpectation = useCallback(async (service: ExpectedServiceInput) => {
		setActionBusy(true);
		try {
			await saveExpectedService(service);
			setExpectedServices(await listExpectedServices(service.deviceId));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The service expectation could not be saved.");
		} finally {
			setActionBusy(false);
		}
	}, []);

	const saveServiceBaseline = useCallback(async (services: ExpectedServiceInput[]) => {
		if (!selectedId || services.length === 0) return;
		setActionBusy(true);
		try {
			const saved = await saveExpectedServices(selectedId, services);
			setExpectedServices(saved);
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The suggested service baseline could not be saved.");
		} finally {
			setActionBusy(false);
		}
	}, [selectedId]);

	const removeServiceExpectation = useCallback(async (service: ExpectedService) => {
		if (!window.confirm(`Remove the expected-service classification “${service.label}”? This changes HAVEN's interpretation only; it does not stop the service.`)) return;
		setActionBusy(true);
		try {
			await removeExpectedService(service);
			setExpectedServices(await listExpectedServices(service.deviceId));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The service expectation could not be removed.");
		} finally {
			setActionBusy(false);
		}
	}, []);

  const runAction = useCallback(async (kind: SecurityActionKind) => {
    const capability = runtime?.actionCapabilities.find((item) => item.id === kind);
    const label = capability?.label || kind.replaceAll("-", " ");
    if (!window.confirm(`Request “${label}” from the ${capability?.platform || "selected"} provider? HAVEN will ask for a fresh passkey confirmation next.`)) return;
    setActionBusy(true);
    try {
      await requestSecurityAction(kind);
      const recent = await listSecurityActions();
      setActions(recent);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The security action could not be requested.");
    } finally {
      setActionBusy(false);
    }
  }, [runtime?.actionCapabilities]);

  const addOwnerPasskey = useCallback(async () => {
    const entered = window.prompt("Name this passkey so you can recognize it later (for example, Ubuntu laptop, iPhone, or security key).", "Another trusted device");
    if (entered === null || entered.trim() === "") return;
    setActionBusy(true);
    try {
      await addPasskey(entered.trim());
      setPasskeys(await listPasskeys());
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The passkey could not be added.");
    } finally {
      setActionBusy(false);
    }
  }, []);

  const removeOwnerPasskey = useCallback(async (passkey: PasskeyInfo) => {
    if (!window.confirm(`Remove the passkey “${passkey.label}”? HAVEN will first ask for a fresh confirmation from a remaining registered passkey.`)) return;
    setActionBusy(true);
    try {
      await removePasskey(passkey.id);
      setPasskeys(await listPasskeys());
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The passkey could not be removed.");
    } finally {
      setActionBusy(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    try { await logout(); } finally {
      setAuthentication((current) => current ? { ...current, authenticated: false } : current);
      setSnapshot(null);
      setDevices([]);
      setEvents([]);
      setReviews([]);
	  setExpectedServices([]);
	  setListenerObservations([]);
      setAudit([]);
      setActions([]);
      setPasskeys([]);
      setInventoryLoaded(false);
    }
  }, []);

  const enableAlerts = useCallback(async () => {
    if (!alertsSupported) {
      setError("This browser does not support desktop notifications.");
      return;
    }
    const permission = await window.Notification.requestPermission();
    if (permission !== "granted") {
      setError("Desktop notifications remain blocked. You can change this site's notification permission in the browser.");
      return;
    }
    const newestEvent = events.reduce((highest, event) => Math.max(highest, event.id), 0);
    lastNotifiedEvent.current = newestEvent;
    window.localStorage.setItem("haven.lastNotifiedEvent", String(newestEvent));
    window.localStorage.setItem("haven.desktopAlerts", "enabled");
    setAlertsEnabled(true);
    setError(null);
  }, [alertsSupported, events]);

  useEffect(() => {
    const controller = new AbortController();
    getAuthStatus(controller.signal).then(setAuthentication).catch((reason) => setError(reason instanceof Error ? reason.message : "HAVEN authentication status is unavailable."));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!authentication?.authenticated) return;
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [authentication?.authenticated, refresh]);

	useEffect(() => {
		if (!authentication?.authenticated || !inventoryLoaded || demoMode) return;
    const controller = new AbortController();
    void loadControls(selectedId, controller.signal).catch((reason) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not be loaded.");
    });
    return () => controller.abort();
	}, [authentication?.authenticated, demoMode, inventoryLoaded, loadControls, selectedId]);

	useEffect(() => {
		if (!authentication?.authenticated || !inventoryLoaded || demoMode) return;
    const controller = new AbortController();
    const pollControls = async () => {
      try {
        const [recentActions, recentAudit] = await Promise.all([listSecurityActions(controller.signal), listAuditEvents(controller.signal)]);
        setActions(recentActions);
        setAudit(recentAudit);
      } catch (reason) {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not refresh.");
      }
    };
    const interval = window.setInterval(() => void pollControls(), 10_000);
    return () => { controller.abort(); window.clearInterval(interval); };
	}, [authentication?.authenticated, demoMode, inventoryLoaded]);

  useEffect(() => {
    if (!authentication?.authenticated) return;
    const controller = new AbortController();
    const poll = async () => {
      try {
        const [inventory, runtimeStatus, activity] = await Promise.all([listDevices(controller.signal), getRuntimeStatus(controller.signal), listEvents(undefined, controller.signal)]);
        let observed: { id: string; snapshot: SecuritySnapshot } | null;
        if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
          const latest = await getLatestSnapshot(controller.signal);
          observed = { id: latest.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: latest };
        } else {
          observed = await latestEnrolledObservation(inventory, selectedIdRef.current, controller.signal);
        }
        setDevices(inventory);
        setEvents(activity);
        setRuntime(runtimeStatus);
        setDemoMode(runtimeStatus.demoMode);
        setSnapshot(observed?.snapshot || null);
        const nextId = observed?.id || inventory.find((device) => device.status === "awaiting-first-report")?.id || "";
		if (!runtimeStatus.demoMode && nextId) setListenerObservations(await listObservedListeners(nextId, controller.signal));
        selectedIdRef.current = nextId;
        setSelectedId(nextId);
        setInventoryLoaded(true);
        setError(null);
      } catch (reason) {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "HAVEN could not refresh its monitoring status.");
      }
    };
    const interval = window.setInterval(() => void poll(), 60_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [authentication?.authenticated]);

  useEffect(() => {
    if (!alertsEnabled || !alertsSupported || window.Notification.permission !== "granted" || events.length === 0) return;
    const newestEvent = events.reduce((highest, event) => Math.max(highest, event.id), 0);
    if (lastNotifiedEvent.current < 0) {
      lastNotifiedEvent.current = newestEvent;
      window.localStorage.setItem("haven.lastNotifiedEvent", String(newestEvent));
      return;
    }
    events
      .filter((event) => event.id > lastNotifiedEvent.current && event.kind === "opened" && (event.severity === "high" || event.severity === "medium"))
      .sort((left, right) => left.id - right.id)
      .forEach((event) => {
        const notification = new window.Notification(`HAVEN · ${event.title}`, {
          body: `${event.deviceName}: ${event.summary}`,
          tag: `haven-event-${event.id}`,
        });
        notification.onclick = () => {
          window.focus();
          notification.close();
        };
      });
    if (newestEvent > lastNotifiedEvent.current) {
      lastNotifiedEvent.current = newestEvent;
      window.localStorage.setItem("haven.lastNotifiedEvent", String(newestEvent));
    }
  }, [alertsEnabled, alertsSupported, events]);

  if (!authentication) {
    return <main className="loading-state"><div className="brand-mark"><HavenIcon /></div><p>{error || "Checking HAVEN's security boundary…"}</p></main>;
  }

  if (!authentication.authenticated) {
    return <AuthenticationGate status={authentication} authenticate={authenticate} />;
  }

  if (!snapshot && !inventoryLoaded) {
    return <main className="loading-state"><div className="brand-mark"><HavenIcon /></div><p>{error || "Collecting security posture…"}</p>{error && <button className="refresh-button" onClick={() => void refresh()}>Try again</button>}</main>;
  }

  if (!snapshot) {
    return <AwaitingAgents devices={devices} runtime={runtime} passkeys={passkeys} actions={actions} audit={audit} error={error} selectDevice={(id) => void selectDevice(id)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} actionBusy={actionBusy} signOut={() => void signOut()} />;
  }

  const selectedDevice = devices.find((device) => device.id === selectedId) || null;
  const selectedEvents = selectedId ? events.filter((event) => event.deviceId === selectedId) : events;
	return <Application snapshot={snapshot} devices={devices} events={selectedEvents} runtime={runtime} selectedDevice={selectedDevice} selectDevice={(id) => void selectDevice(id)} refresh={() => void refresh()} refreshing={refreshing} error={error} demoMode={demoMode} alertsEnabled={alertsEnabled} alertsSupported={alertsSupported} enableAlerts={() => void enableAlerts()} reviews={reviews} expectedServices={expectedServices} listenerObservations={listenerObservations} audit={audit} actions={actions} passkeys={passkeys} reviewFinding={(finding, state) => void reviewFinding(finding, state)} saveServiceExpectation={(service) => void saveServiceExpectation(service)} saveServiceExpectations={(services) => void saveServiceBaseline(services)} removeServiceExpectation={(service) => void removeServiceExpectation(service)} runAction={(kind) => void runAction(kind)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} actionBusy={actionBusy} signOut={() => void signOut()} />;
}
