import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { addPasskey, collectSnapshot, getAuthStatus, getDevice, getLatestSnapshot, getRuntimeStatus, listAuditEvents, listDevices, listEvents, listFindingReviews, listPasskeys, listSecurityActions, loginWithPasskey, logout, registerPasskey, removePasskey, requestSecurityAction, saveFindingReview } from "./api";
import { ActivityIcon, AlertIcon, BellIcon, CheckIcon, ChipIcon, DefenderIcon, DevicesIcon, FirewallIcon, HavenIcon, HelpIcon, LaptopIcon, LockIcon, MonitorIcon, NetworkIcon, RefreshIcon, RemoteAccessIcon, ServerIcon, UpdateIcon, UsersIcon } from "./icons";
import type {
  BaselineCheck,
  AuditEvent,
  ActionCapability,
  AuthStatus,
  DefenderStatus,
  DeviceRecord,
  FindingReview,
  FindingReviewState,
  FirewallProfileStatus,
  LinuxBaseline,
  NetworkConnection,
  PasskeyInfo,
  RuntimeStatus,
  SecurityEvent,
  SecurityAction,
  SecurityActionKind,
  SecuritySnapshot,
  SecurityFinding,
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
              <span className="device-identity"><span className="device-icon">{device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon /> : device.displayName.toLowerCase().includes("laptop") ? <LaptopIcon /> : <MonitorIcon />}</span><span><strong>{device.displayName}</strong><small>{device.operatingSystem || "Awaiting first report"}</small></span></span>
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
  const host = address.includes(":") ? `[${address}]` : address || "—";
  return `${host}:${port}`;
}

function endpointScope(connection: NetworkConnection) {
  if (connection.state.toLowerCase() === "established") return "Active connection";
  const address = connection.localAddress.toLowerCase();
  if (address === "127.0.0.1" || address === "::1" || address.startsWith("127.")) return "This host only";
  if (address === "0.0.0.0" || address === "*") return "All IPv4 interfaces";
  if (address === "::") return "All IPv6 interfaces";
  if (address.startsWith("10.") || address.startsWith("192.168.")) return "Private network address";
  const octets = address.split(".").map(Number);
  if (octets.length === 4 && octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return "Private network address";
  if (address.startsWith("169.254.") || address.startsWith("fe80:")) return "Link-local address";
  return "Specific interface address";
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
    ["SSH root login", ssh?.permitRootLogin || "Not fully verified"],
    ["Failed systemd units", baseline.services?.failedUnitCount === null || baseline.services?.failedUnitCount === undefined ? "Not verified" : String(baseline.services.failedUnitCount)],
    ["Failed unit names", baseline.services?.failedUnits?.length ? baseline.services.failedUnits.join(", ") : "None reported"],
    ["Root filesystem", storage?.usedPercentage === null || storage?.usedPercentage === undefined ? "Not verified" : `${storage.usedPercentage.toFixed(0)}% used · ${formatBytes(storage.availableBytes)} available`],
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

function FirewallPanel({ profiles }: { profiles: FirewallProfileStatus[] }) {
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
              <div><dt>Inbound default</dt><dd>{policyValue(profile.defaultInboundAction)}</dd></div>
              <div><dt>Outbound default</dt><dd>{policyValue(profile.defaultOutboundAction)}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function ConnectionsPanel({ connections }: { connections: NetworkConnection[] }) {
  const [filter, setFilter] = useState("");
  const filtered = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return connections;
    return connections.filter((connection) =>
      Object.values(connection).some((value) => String(value).toLowerCase().includes(query))
      || endpointScope(connection).toLowerCase().includes(query),
    );
  }, [connections, filter]);

  return (
    <section className="panel connections-panel" aria-labelledby="connections-title">
      <div className="section-heading connections-heading">
        <div className="heading-identity"><span className="section-icon cyan"><NetworkIcon /></span><div><p className="eyebrow">LIVE OBSERVATION · NOT A THREAT LIST</p><h2 id="connections-title">Network endpoints</h2></div></div>
        <label className="search-field">
          <span className="sr-only">Filter connections</span>
          <input
            type="search"
            placeholder="Filter process, address, or state"
            autoComplete="off"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </label>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Protocol</th><th>Process</th><th>Local endpoint</th><th>Remote endpoint</th><th>Scope</th><th>State</th></tr></thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="empty-state">{connections.length ? "No endpoints match this filter." : "No network endpoints were returned."}</td></tr>
            ) : filtered.map((connection) => (
              <tr key={`${connection.protocol}-${connection.processId}-${connection.localAddress}-${connection.localPort}-${connection.remoteAddress}-${connection.remotePort}-${connection.state}`}>
                <td className="protocol">{connection.protocol}</td>
                <td><div className="process-name">{connection.processName || "Owner unavailable"}</div><div className="process-id">{connection.processId > 0 ? `PID ${connection.processId}` : "Process hidden from this agent"}</div></td>
                <td className="endpoint">{endpoint(connection.localAddress, connection.localPort)}</td>
                <td className="endpoint">{endpoint(connection.remoteAddress, connection.remotePort)}</td>
                <td className="scope">{endpointScope(connection)}</td>
                <td className="state">{connection.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="footnote">Showing {filtered.length} of {connections.length} live TCP and UDP endpoints. “All interfaces” describes the local bind—not proven Internet reachability. Payload contents are never captured or stored.</p>
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
        {capabilities.length === 0 ? <p className="muted-copy">The selected hub has not advertised any control capabilities.</p> : capabilities.map((capability) => {
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

function ActivityPanel({ events }: { events: SecurityEvent[] }) {
  const recent = events.slice(0, 12);
  return (
    <section className="panel activity-panel" aria-labelledby="activity-title">
      <PanelHeading eyebrow="WHAT CHANGED" title="Security activity" id="activity-title" icon={<ActivityIcon />} accent="cyan">
        New findings and automatic resolutions from continuous observations
      </PanelHeading>
      {recent.length === 0 ? (
        <p className="activity-empty"><strong>No posture changes recorded yet.</strong><span>HAVEN will add an event when a finding appears or resolves; routine unchanged observations stay quiet.</span></p>
      ) : (
        <ol className="activity-list">
          {recent.map((event) => {
            const resolved = event.kind === "resolved";
            const tone: Tone = resolved ? "healthy" : event.severity === "high" ? "danger" : event.severity === "medium" ? "attention" : "configured";
            return (
              <li className={`activity-item ${resolved ? "resolved" : `severity-${event.severity}`}`} key={event.id}>
                <span className="activity-marker">{resolved ? <CheckIcon size={17} /> : <AlertIcon size={17} />}</span>
                <div className="activity-copy">
                  <div className="activity-heading"><div><p>{event.category} · {event.deviceName}</p><h3>{event.title}</h3></div><StatusChip label={resolved ? "resolved" : event.severity} tone={tone} /></div>
                  <p>{resolved ? "HAVEN no longer derives this finding from the latest observation." : event.summary}</p>
                  <time dateTime={event.occurredAt}>{formatDate(event.occurredAt)}</time>
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
  const statusLabel = (status: BaselineCheck["status"]) => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "review" : "not verified";
  const statusTone = (status: BaselineCheck["status"]): Tone => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "attention" : "unknown";
  return (
    <section className="panel baseline-panel" aria-labelledby="baseline-title">
      <PanelHeading eyebrow={`${platform.toUpperCase()} SECURITY BASELINE`} title="Posture checks" id="baseline-title" icon={<ChipIcon />} accent="blue">
        {passing} healthy{configured > 0 ? `, ${configured} intentionally configured` : ""}; unverified is never counted as safe
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

function Application({ snapshot, devices, events, runtime, selectedDevice, selectDevice, refresh, refreshing, error, demoMode, alertsEnabled, alertsSupported, enableAlerts, reviews, audit, actions, passkeys, reviewFinding, runAction, addOwnerPasskey, removeOwnerPasskey, actionBusy, signOut }: { snapshot: SecuritySnapshot; devices: DeviceRecord[]; events: SecurityEvent[]; runtime: RuntimeStatus | null; selectedDevice: DeviceRecord | null; selectDevice: (id: string) => void; refresh: () => void; refreshing: boolean; error: string | null; demoMode: boolean; alertsEnabled: boolean; alertsSupported: boolean; enableAlerts: () => void; reviews: FindingReview[]; audit: AuditEvent[]; actions: SecurityAction[]; passkeys: PasskeyInfo[]; reviewFinding: (finding: SecurityFinding, state: FindingReviewState) => void; runAction: (kind: SecurityActionKind) => void; addOwnerPasskey: () => void; removeOwnerPasskey: (passkey: PasskeyInfo) => void; actionBusy: boolean; signOut: () => void }) {
  const isLinux = snapshot.linuxBaseline !== null || /linux|ubuntu/i.test(snapshot.device.operatingSystem);
  const defenderHealthy = snapshot.defender?.antivirusEnabled === true
    && snapshot.defender.realTimeProtectionEnabled === true
    && snapshot.defender.tamperProtected !== false;
  const firewallsKnown = snapshot.firewallProfiles.length > 0;
  const firewallsEnabled = firewallsKnown && snapshot.firewallProfiles.every((profile) => profile.enabled === true);
  const linuxHardeningKnown = snapshot.linuxBaseline?.appArmor?.enabled !== null && snapshot.linuxBaseline?.appArmor?.enabled !== undefined
    && snapshot.linuxBaseline?.automaticUpdates?.enabled !== null && snapshot.linuxBaseline?.automaticUpdates?.enabled !== undefined;
  const linuxHardeningHealthy = snapshot.linuxBaseline?.appArmor?.enabled === true && snapshot.linuxBaseline?.automaticUpdates?.enabled === true;
  const established = snapshot.connections.filter((item) => item.state.toLowerCase() === "established").length;
  const listening = snapshot.connections.filter((item) => ["listen", "open"].includes(item.state.toLowerCase())).length;
  const broadListeners = snapshot.connections.filter((item) => ["All IPv4 interfaces", "All IPv6 interfaces"].includes(endpointScope(item))).length;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/" aria-label="HAVEN home"><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
        <div className="topbar-actions">
          <span className={`local-pill ${demoMode ? "demo-pill" : ""}`}><span className="local-dot" />{demoMode ? "Synthetic demo" : runtime?.localCollection ? "Local monitor" : "Agent hub"}</span>
          {!demoMode && alertsSupported && <button className={`desktop-alert-button ${alertsEnabled ? "enabled" : ""}`} type="button" onClick={enableAlerts} disabled={alertsEnabled} aria-label={alertsEnabled ? "Desktop alerts enabled" : "Enable desktop alerts"}><BellIcon size={15} /><span>{alertsEnabled ? "Alerts on" : "Enable alerts"}</span></button>}
          {selectedDevice?.trustState === "local" && <button className="refresh-button" type="button" onClick={refresh} disabled={refreshing}>{refreshing ? "Collecting…" : <><RefreshIcon size={15} />Refresh now</>}</button>}
          {!demoMode && <button className="signout-button" type="button" onClick={signOut}>Lock</button>}
        </div>
      </header>
      <main>
        <DeviceInventory devices={devices} selectedId={selectedDevice?.id || snapshot.device.deviceId || ""} select={selectDevice} demoMode={demoMode} />
        {demoMode && <p className="demo-banner" role="status"><strong>Synthetic demo mode.</strong> Every device and observation on this page is invented. HAVEN is not showing or collecting data from this computer.</p>}
        {!demoMode && <p className="context-banner"><strong>Continuous, read-only monitoring.</strong> {runtime?.localCollection ? `HAVEN observes this computer every ${runtime.monitor.enabled ? formatInterval(runtime.monitor.intervalSeconds) : "configured interval"}.` : "A native agent reports this endpoint's security posture to the private HAVEN hub."} HAVEN records only meaningful finding transitions. This inventory contains explicitly enrolled devices—not every device on the network—and an event does not by itself prove an attack.</p>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        <section className="hero" aria-labelledby="device-name">
          <div className="hero-identity"><span className="hero-device-icon">{snapshot.device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon size={28} /> : selectedDevice?.displayName.toLowerCase().includes("laptop") ? <LaptopIcon size={28} /> : <MonitorIcon size={28} />}</span><div><p className="eyebrow">{selectedDevice?.trustState === "local" ? "THIS DEVICE" : "DEVICE OBSERVATION"}</p><h1 id="device-name">{selectedDevice?.displayName || snapshot.device.hostName}</h1><p className="device-detail">{snapshot.device.hostName} · {snapshot.device.operatingSystem} · {snapshot.device.architecture} · {formatDuration(snapshot.device.uptimeSeconds)}</p></div></div>
          <div className="collection-time"><span>Last observation</span><strong>{formatDate(snapshot.collectedAt)}</strong></div>
        </section>
        <section className="summary-grid" aria-label="Security summary">
          <SummaryCard icon={isLinux ? <ChipIcon /> : <DefenderIcon />} accent="blue" title={isLinux ? "Host hardening" : "Protection"} label={isLinux ? (linuxHardeningKnown ? (linuxHardeningHealthy ? "Active" : "Attention") : "Unavailable") : snapshot.defender ? (defenderHealthy ? "Protected" : "Attention") : "Unavailable"} tone={isLinux ? (linuxHardeningKnown ? (linuxHardeningHealthy ? "healthy" : "attention") : "unknown") : snapshot.defender ? (defenderHealthy ? "healthy" : "attention") : "unknown"}>{isLinux ? (linuxHardeningKnown ? (linuxHardeningHealthy ? "AppArmor and automatic update protections are enabled." : "One or more Linux hardening signals need review.") : "Linux hardening status was not fully returned.") : snapshot.defender ? (defenderHealthy ? "Antivirus and real-time monitoring are active." : "One or more protection signals are off or unavailable.") : "Defender status was not returned."}</SummaryCard>
          <SummaryCard icon={<FirewallIcon />} accent="amber" title="Firewall" label={firewallsKnown ? (firewallsEnabled ? "Enabled" : "Attention") : "Unavailable"} tone={firewallsKnown ? (firewallsEnabled ? "healthy" : "danger") : "unknown"}>{firewallsKnown ? (isLinux ? `${snapshot.firewallProfiles[0].name} is ${firewallsEnabled ? "enabled" : "disabled"} as the host firewall provider.` : firewallsEnabled ? `All ${snapshot.firewallProfiles.length} Windows Firewall profiles are enabled.` : "At least one Windows Firewall profile is disabled.") : "Firewall status was not returned."}</SummaryCard>
          <SummaryCard icon={<NetworkIcon />} accent="cyan" title="Network" label={`${broadListeners} broad bind${broadListeners === 1 ? "" : "s"}`} tone={broadListeners > 0 ? "configured" : "healthy"}>{established} established connection{established === 1 ? "" : "s"}, {listening} listening/open endpoint{listening === 1 ? "" : "s"}, and {broadListeners} bound to all IPv4 or IPv6 interfaces. These are exposure clues, not threat counts.</SummaryCard>
          <SummaryCard icon={<ActivityIcon />} accent="green" title="Monitor" label={runtime?.localCollection && runtime.monitor.enabled ? `Every ${formatInterval(runtime.monitor.intervalSeconds)}` : "Agent reported"} tone={runtime?.monitor.lastCollectionError ? "attention" : "healthy"}>{runtime?.localCollection ? (runtime.monitor.lastCollectionError || (runtime.monitor.lastSuccessfulAt ? `Last automatic observation succeeded ${formatDate(runtime.monitor.lastSuccessfulAt)}.` : "Automatic monitoring is starting.")) : `Latest authenticated agent observation arrived ${formatDate(snapshot.collectedAt)}.`}</SummaryCard>
        </section>
        {!demoMode && <><PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} /><ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={runAction} busy={actionBusy} /></>}
        <ActivityPanel events={events} />
        {(snapshot.baselineChecks || []).length > 0 && <><FindingsPanel findings={snapshot.findings || []} checks={snapshot.baselineChecks || []} reviews={reviews} review={reviewFinding} /><BaselinePanel checks={snapshot.baselineChecks || []} collectedAt={snapshot.collectedAt} platform={isLinux ? "Linux" : "Windows"} /></>}
        {snapshot.notices.length > 0 && <section className="panel notices-panel" aria-labelledby="notices-title"><PanelHeading eyebrow="COLLECTION NOTES" title="Some signals could not be verified" id="notices-title" icon={<AlertIcon />} accent="amber">A collection limitation is not automatically a security problem</PanelHeading><ul className="notices-list">{snapshot.notices.map((notice, index) => <li className="notice" key={`${notice.source}-${index}`}><strong>{notice.source}: </strong>{notice.message}</li>)}</ul></section>}
        {isLinux && snapshot.linuxBaseline ? <LinuxPanel baseline={snapshot.linuxBaseline} /> : <DefenderPanel defender={snapshot.defender} />}
        <FirewallPanel profiles={snapshot.firewallProfiles} />
        <ConnectionsPanel connections={snapshot.connections} />
      </main>
      <footer><span>HAVEN milestone 0.7 · Native Linux monitoring</span><span>Observe continuously. Act deliberately.</span></footer>
    </>
  );
}

export function App() {
  const [authentication, setAuthentication] = useState<AuthStatus | null>(null);
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [reviews, setReviews] = useState<FindingReview[]>([]);
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
    const [findingReviews, recentAudit, recentActions, ownerPasskeys] = await Promise.all([
      deviceId ? listFindingReviews(deviceId, signal) : Promise.resolve([]),
      listAuditEvents(signal),
      listSecurityActions(signal),
      listPasskeys(signal),
    ]);
    setReviews(findingReviews);
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
    if (!authentication?.authenticated || demoMode) return;
    const controller = new AbortController();
    void loadControls(selectedId, controller.signal).catch((reason) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not be loaded.");
    });
    return () => controller.abort();
  }, [authentication?.authenticated, demoMode, loadControls, selectedId]);

  useEffect(() => {
    if (!authentication?.authenticated || demoMode) return;
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
  }, [authentication?.authenticated, demoMode]);

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
  return <Application snapshot={snapshot} devices={devices} events={selectedEvents} runtime={runtime} selectedDevice={selectedDevice} selectDevice={(id) => void selectDevice(id)} refresh={() => void refresh()} refreshing={refreshing} error={error} demoMode={demoMode} alertsEnabled={alertsEnabled} alertsSupported={alertsSupported} enableAlerts={() => void enableAlerts()} reviews={reviews} audit={audit} actions={actions} passkeys={passkeys} reviewFinding={(finding, state) => void reviewFinding(finding, state)} runAction={(kind) => void runAction(kind)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} actionBusy={actionBusy} signOut={() => void signOut()} />;
}
