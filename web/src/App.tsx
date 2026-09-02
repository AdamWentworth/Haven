import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { collectSnapshot, getAuthStatus, getDevice, getLatestSnapshot, getRuntimeStatus, listAuditEvents, listDevices, listEvents, listFindingReviews, listSecurityActions, loginWithPasskey, logout, registerPasskey, requestSecurityAction, saveFindingReview } from "./api";
import { ActivityIcon, AlertIcon, BellIcon, CheckIcon, ChipIcon, DefenderIcon, DevicesIcon, FirewallIcon, HavenIcon, HelpIcon, LaptopIcon, LockIcon, MonitorIcon, NetworkIcon, RefreshIcon, RemoteAccessIcon, ServerIcon, UpdateIcon, UsersIcon } from "./icons";
import type {
  BaselineCheck,
  AuditEvent,
  AuthStatus,
  DefenderStatus,
  DeviceRecord,
  FindingReview,
  FindingReviewState,
  FirewallProfileStatus,
  NetworkConnection,
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

function AuthenticationGate({ status, authenticate }: { status: AuthStatus; authenticate: (bootstrapCode?: string) => Promise<void> }) {
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passkeysSupported = typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

  const proceed = async () => {
    setWorking(true);
    setError(null);
    try {
      await authenticate(status.configured ? undefined : bootstrapCode.trim());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Windows Hello could not complete the passkey request.");
    } finally {
      setWorking(false);
    }
  };

  if (status.useLocalhost) {
    return <main className="auth-shell"><section className="auth-card"><span className="brand-mark"><HavenIcon /></span><p className="eyebrow">SECURE LOCAL ORIGIN</p><h1>Open HAVEN as localhost</h1><p>Windows Hello passkeys require HAVEN's exact trusted origin. Your data stays on this machine; only the browser address changes.</p><a className="primary-action" href={status.origin}>Continue to {status.origin}</a></section></main>;
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="auth-title">
        <span className="brand-mark"><HavenIcon /></span>
        <p className="eyebrow">HAVEN ACTION CENTER</p>
        <h1 id="auth-title">{status.configured ? "Unlock with your passkey" : "Create the owner passkey"}</h1>
        <p>{status.configured ? "Use Windows Hello to open security observations, review decisions, and allowlisted controls." : "In a terminal, run the command below. Paste its one-time code here, then let Windows Hello create your passkey."}</p>
        {!status.configured && <><code className="bootstrap-command">go run .\cmd\haven-hub auth bootstrap</code><label className="auth-field"><span>One-time bootstrap code</span><input value={bootstrapCode} onChange={(event) => setBootstrapCode(event.target.value)} autoComplete="one-time-code" spellCheck={false} /></label></>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        {!passkeysSupported && <p className="inline-error" role="alert">This browser does not expose the passkey APIs HAVEN needs.</p>}
        <button className="primary-action" type="button" onClick={() => void proceed()} disabled={working || !passkeysSupported || (!status.configured && bootstrapCode.trim() === "")}>{working ? "Waiting for Windows Hello…" : status.configured ? "Sign in with Windows Hello" : "Create HAVEN passkey"}</button>
        <p className="auth-footnote">No HAVEN password is stored. Sessions expire after 12 hours, and control requests also require same-origin anti-forgery verification.</p>
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

function booleanValue(value: boolean | null) {
  if (value === true) return { label: "On", className: "value-good" };
  if (value === false) return { label: "Off", className: "value-bad" };
  return { label: "Unavailable", className: "value-muted" };
}

function endpoint(address: string, port: number) {
  const host = address.includes(":") ? `[${address}]` : address || "—";
  return `${host}:${port}`;
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
      <PanelHeading eyebrow="NETWORK BOUNDARY" title="Firewall profiles" id="firewall-title" icon={<FirewallIcon />} accent="amber">
        Domain, private, and public network behavior
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
      Object.values(connection).some((value) => String(value).toLowerCase().includes(query)),
    );
  }, [connections, filter]);

  return (
    <section className="panel connections-panel" aria-labelledby="connections-title">
      <div className="section-heading connections-heading">
        <div className="heading-identity"><span className="section-icon cyan"><NetworkIcon /></span><div><p className="eyebrow">LIVE OBSERVATION · NOT A THREAT LIST</p><h2 id="connections-title">TCP connections</h2></div></div>
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
          <thead><tr><th>Process</th><th>Local endpoint</th><th>Remote endpoint</th><th>State</th></tr></thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={4} className="empty-state">{connections.length ? "No connections match this filter." : "No TCP connections were returned."}</td></tr>
            ) : filtered.map((connection) => (
              <tr key={`${connection.processId}-${connection.localAddress}-${connection.localPort}-${connection.remoteAddress}-${connection.remotePort}-${connection.state}`}>
                <td><div className="process-name">{connection.processName || "Unknown"}</div><div className="process-id">PID {connection.processId}</div></td>
                <td className="endpoint">{endpoint(connection.localAddress, connection.localPort)}</td>
                <td className="endpoint">{endpoint(connection.remoteAddress, connection.remotePort)}</td>
                <td className="state">{connection.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="footnote">Showing {filtered.length} of {connections.length} established and listening TCP endpoints. An entry is not automatically suspicious, and payload contents are never captured or stored.</p>
    </section>
  );
}

function baselineIcon(id: string) {
  if (id === "defender" || id === "threats") return <DefenderIcon />;
  if (id === "firewall") return <FirewallIcon />;
  if (id === "updates") return <UpdateIcon />;
  if (id === "encryption") return <LockIcon />;
  if (id === "secure-boot" || id === "tpm") return <ChipIcon />;
  if (id === "remote-access") return <RemoteAccessIcon />;
  if (id === "local-admins") return <UsersIcon />;
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

function ActionCenter({ actions, audit, run, busy, available }: { actions: SecurityAction[]; audit: AuditEvent[]; run: (kind: SecurityActionKind) => void; busy: boolean; available: boolean }) {
  const latest = actions.slice(0, 5);
  const scanActive = actions.some((item) => item.kind === "defender-quick-scan" && (item.status === "queued" || item.status === "running"));
  const updateActive = actions.some((item) => item.kind === "defender-signature-update" && (item.status === "queued" || item.status === "running"));
  return (
    <section className="panel action-center" aria-labelledby="action-center-title">
      <PanelHeading eyebrow="AUTHENTICATED CONTROLS" title="Action center" id="action-center-title" icon={<DefenderIcon />} accent="blue">Fixed Windows Security actions only—no arbitrary commands</PanelHeading>
      <div className="action-grid">
        <article className="action-card"><DefenderIcon /><div><h3>Defender quick scan</h3><p>Ask Microsoft Defender to scan common malware locations now.</p></div><button type="button" disabled={busy || !available || scanActive} onClick={() => run("defender-quick-scan")}>{!available ? "Local Windows hub only" : scanActive ? "Scan in progress" : "Run quick scan"}</button></article>
        <article className="action-card"><UpdateIcon /><div><h3>Update threat intelligence</h3><p>Ask Defender to retrieve the latest available security intelligence.</p></div><button type="button" disabled={busy || !available || updateActive} onClick={() => run("defender-signature-update")}>{!available ? "Local Windows hub only" : updateActive ? "Update in progress" : "Update Defender"}</button></article>
      </div>
      <div className="action-history-grid">
        <div><h3>Recent control requests</h3>{latest.length === 0 ? <p className="muted-copy">No control actions requested yet.</p> : <ol className="compact-history">{latest.map((item) => <li key={item.id}><span><strong>{item.kind === "defender-quick-scan" ? "Defender quick scan" : "Defender intelligence update"}</strong><small>{formatDate(item.requestedAt)}</small></span><StatusChip label={item.status} tone={item.status === "succeeded" ? "healthy" : item.status === "failed" ? "danger" : "attention"} /></li>)}</ol>}</div>
        <div><h3>Audit trail</h3>{audit.length === 0 ? <p className="muted-copy">No owner decisions recorded yet.</p> : <ol className="compact-history">{audit.slice(0, 6).map((item) => <li key={item.id}><span><strong>{item.action.replaceAll(".", " ")}</strong><small>{item.detail} · {formatDate(item.occurredAt)}</small></span><StatusChip label={item.outcome} tone={item.outcome === "failed" ? "danger" : "configured"} /></li>)}</ol>}</div>
      </div>
    </section>
  );
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

function BaselinePanel({ checks, collectedAt }: { checks: BaselineCheck[]; collectedAt: string }) {
  if (checks.length === 0) return null;
  const passing = checks.filter((check) => check.status === "pass").length;
  const configured = checks.filter((check) => check.status === "configured").length;
  const statusLabel = (status: BaselineCheck["status"]) => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "review" : "not verified";
  const statusTone = (status: BaselineCheck["status"]): Tone => status === "pass" ? "healthy" : status === "configured" ? "configured" : status === "attention" ? "attention" : "unknown";
  return (
    <section className="panel baseline-panel" aria-labelledby="baseline-title">
      <PanelHeading eyebrow="WINDOWS SECURITY BASELINE" title="Posture checks" id="baseline-title" icon={<ChipIcon />} accent="blue">
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

function Application({ snapshot, devices, events, runtime, selectedDevice, selectDevice, refresh, refreshing, error, demoMode, alertsEnabled, alertsSupported, enableAlerts, reviews, audit, actions, reviewFinding, runAction, actionBusy, signOut }: { snapshot: SecuritySnapshot; devices: DeviceRecord[]; events: SecurityEvent[]; runtime: RuntimeStatus | null; selectedDevice: DeviceRecord | null; selectDevice: (id: string) => void; refresh: () => void; refreshing: boolean; error: string | null; demoMode: boolean; alertsEnabled: boolean; alertsSupported: boolean; enableAlerts: () => void; reviews: FindingReview[]; audit: AuditEvent[]; actions: SecurityAction[]; reviewFinding: (finding: SecurityFinding, state: FindingReviewState) => void; runAction: (kind: SecurityActionKind) => void; actionBusy: boolean; signOut: () => void }) {
  const defenderHealthy = snapshot.defender?.antivirusEnabled === true
    && snapshot.defender.realTimeProtectionEnabled === true
    && snapshot.defender.tamperProtected !== false;
  const firewallsKnown = snapshot.firewallProfiles.length > 0;
  const firewallsEnabled = firewallsKnown && snapshot.firewallProfiles.every((profile) => profile.enabled === true);
  const established = snapshot.connections.filter((item) => item.state.toLowerCase() === "established").length;
  const listening = snapshot.connections.filter((item) => item.state.toLowerCase() === "listen").length;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/" aria-label="HAVEN home"><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
        <div className="topbar-actions">
          <span className={`local-pill ${demoMode ? "demo-pill" : ""}`}><span className="local-dot" />{demoMode ? "Synthetic demo" : runtime?.monitor.enabled ? "Monitoring" : "Read-only"}</span>
          {!demoMode && alertsSupported && <button className={`desktop-alert-button ${alertsEnabled ? "enabled" : ""}`} type="button" onClick={enableAlerts} disabled={alertsEnabled} aria-label={alertsEnabled ? "Desktop alerts enabled" : "Enable desktop alerts"}><BellIcon size={15} /><span>{alertsEnabled ? "Alerts on" : "Enable alerts"}</span></button>}
          {selectedDevice?.trustState === "local" && <button className="refresh-button" type="button" onClick={refresh} disabled={refreshing}>{refreshing ? "Collecting…" : <><RefreshIcon size={15} />Refresh now</>}</button>}
          {!demoMode && <button className="signout-button" type="button" onClick={signOut}>Lock</button>}
        </div>
      </header>
      <main>
        <DeviceInventory devices={devices} selectedId={selectedDevice?.id || snapshot.device.deviceId || ""} select={selectDevice} demoMode={demoMode} />
        {demoMode && <p className="demo-banner" role="status"><strong>Synthetic demo mode.</strong> Every device and observation on this page is invented. HAVEN is not showing or collecting data from this computer.</p>}
        {!demoMode && <p className="context-banner"><strong>Continuous, read-only monitoring.</strong> HAVEN observes this computer every {runtime?.monitor.enabled ? formatInterval(runtime.monitor.intervalSeconds) : "configured interval"} and records only meaningful finding transitions. This inventory contains explicitly enrolled devices—not every device on the network—and an event does not by itself prove an attack.</p>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        <section className="hero" aria-labelledby="device-name">
          <div className="hero-identity"><span className="hero-device-icon">{snapshot.device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon size={28} /> : selectedDevice?.displayName.toLowerCase().includes("laptop") ? <LaptopIcon size={28} /> : <MonitorIcon size={28} />}</span><div><p className="eyebrow">{selectedDevice?.trustState === "local" ? "THIS DEVICE" : "DEVICE OBSERVATION"}</p><h1 id="device-name">{selectedDevice?.displayName || snapshot.device.hostName}</h1><p className="device-detail">{snapshot.device.hostName} · {snapshot.device.operatingSystem} · {snapshot.device.architecture} · {formatDuration(snapshot.device.uptimeSeconds)}</p></div></div>
          <div className="collection-time"><span>Last observation</span><strong>{formatDate(snapshot.collectedAt)}</strong></div>
        </section>
        <section className="summary-grid" aria-label="Security summary">
          <SummaryCard icon={<DefenderIcon />} accent="blue" title="Protection" label={snapshot.defender ? (defenderHealthy ? "Protected" : "Attention") : "Unavailable"} tone={snapshot.defender ? (defenderHealthy ? "healthy" : "attention") : "unknown"}>{snapshot.defender ? (defenderHealthy ? "Antivirus and real-time monitoring are active." : "One or more protection signals are off or unavailable.") : "Defender status was not returned."}</SummaryCard>
          <SummaryCard icon={<FirewallIcon />} accent="amber" title="Firewall" label={firewallsKnown ? (firewallsEnabled ? "Enabled" : "Attention") : "Unavailable"} tone={firewallsKnown ? (firewallsEnabled ? "healthy" : "danger") : "unknown"}>{firewallsKnown ? (firewallsEnabled ? `All ${snapshot.firewallProfiles.length} firewall profiles are enabled.` : "At least one firewall profile is disabled.") : "Firewall profile data was not returned."}</SummaryCard>
          <SummaryCard icon={<NetworkIcon />} accent="cyan" title="Network" label={`${established} connected`} tone="healthy">{established} established and {listening} listening TCP endpoints observed right now. These are not threat counts.</SummaryCard>
          <SummaryCard icon={<ActivityIcon />} accent="green" title="Monitor" label={runtime?.monitor.enabled ? `Every ${formatInterval(runtime.monitor.intervalSeconds)}` : "Manual"} tone={runtime?.monitor.lastCollectionError ? "attention" : runtime?.monitor.enabled ? "healthy" : "unknown"}>{runtime?.monitor.lastCollectionError || (runtime?.monitor.lastSuccessfulAt ? `Last automatic observation succeeded ${formatDate(runtime.monitor.lastSuccessfulAt)}.` : "Automatic monitoring is starting.")}</SummaryCard>
        </section>
        {!demoMode && <ActionCenter actions={actions} audit={audit} run={runAction} busy={actionBusy} available={runtime?.actionsAvailable === true} />}
        <ActivityPanel events={events} />
        {(snapshot.baselineChecks || []).length > 0 && <><FindingsPanel findings={snapshot.findings || []} checks={snapshot.baselineChecks || []} reviews={reviews} review={reviewFinding} /><BaselinePanel checks={snapshot.baselineChecks || []} collectedAt={snapshot.collectedAt} /></>}
        {snapshot.notices.length > 0 && <section className="panel notices-panel" aria-labelledby="notices-title"><PanelHeading eyebrow="COLLECTION NOTES" title="Some signals could not be verified" id="notices-title" icon={<AlertIcon />} accent="amber">A collection limitation is not automatically a security problem</PanelHeading><ul className="notices-list">{snapshot.notices.map((notice, index) => <li className="notice" key={`${notice.source}-${index}`}><strong>{notice.source}: </strong>{notice.message}</li>)}</ul></section>}
        <DefenderPanel defender={snapshot.defender} />
        <FirewallPanel profiles={snapshot.firewallProfiles} />
        <ConnectionsPanel connections={snapshot.connections} />
      </main>
      <footer><span>HAVEN milestone 0.6 · Authenticated Action Center</span><span>Observe continuously. Act deliberately.</span></footer>
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
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [demoMode, setDemoMode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const alertsSupported = typeof window !== "undefined" && "Notification" in window;
  const [alertsEnabled, setAlertsEnabled] = useState(() => alertsSupported && window.Notification.permission === "granted" && window.localStorage.getItem("haven.desktopAlerts") === "enabled");
  const lastNotifiedEvent = useRef<number>(typeof window === "undefined" ? -1 : Number(window.localStorage.getItem("haven.lastNotifiedEvent") ?? "-1"));

  const authenticate = useCallback(async (bootstrapCode?: string) => {
    if (bootstrapCode === undefined) await loginWithPasskey();
    else await registerPasskey(bootstrapCode);
    setAuthentication(await getAuthStatus());
    setSnapshot(null);
  }, []);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const collected = await collectSnapshot(signal);
      const [inventory, runtimeStatus, activity] = await Promise.all([listDevices(signal), getRuntimeStatus(signal), listEvents(undefined, signal)]);
      setSnapshot(collected);
      setDevices(inventory);
      setEvents(activity);
      setRuntime(runtimeStatus);
      setDemoMode(runtimeStatus.demoMode);
      setSelectedId(collected.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "");
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
      setSelectedId(deviceId);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The device observation could not be loaded.");
    } finally {
      setRefreshing(false);
    }
  }, []);

  const loadControls = useCallback(async (deviceId: string, signal?: AbortSignal) => {
    const [findingReviews, recentAudit, recentActions] = await Promise.all([
      deviceId ? listFindingReviews(deviceId, signal) : Promise.resolve([]),
      listAuditEvents(signal),
      listSecurityActions(signal),
    ]);
    setReviews(findingReviews);
    setAudit(recentAudit);
    setActions(recentActions);
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
    const label = kind === "defender-quick-scan" ? "run a Microsoft Defender quick scan" : "update Microsoft Defender security intelligence";
    if (!window.confirm(`Ask this Windows machine to ${label}?`)) return;
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
    if (!authentication?.authenticated || demoMode || !selectedId) return;
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
        const [latest, inventory, runtimeStatus, activity] = await Promise.all([
          getLatestSnapshot(controller.signal),
          listDevices(controller.signal),
          getRuntimeStatus(controller.signal),
          listEvents(undefined, controller.signal),
        ]);
        setDevices(inventory);
        setEvents(activity);
        setRuntime(runtimeStatus);
        if (selectedId === "" || selectedId === latest.device.deviceId || inventory.find((device) => device.id === selectedId)?.trustState === "local") {
          setSnapshot(latest);
          setSelectedId(latest.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || selectedId);
        }
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
  }, [authentication?.authenticated, selectedId]);

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

  if (!snapshot) {
    return <main className="loading-state"><div className="brand-mark"><HavenIcon /></div><p>{error || "Collecting security posture…"}</p>{error && <button className="refresh-button" onClick={() => void refresh()}>Try again</button>}</main>;
  }

  const selectedDevice = devices.find((device) => device.id === selectedId) || null;
  const selectedEvents = selectedId ? events.filter((event) => event.deviceId === selectedId) : events;
  return <Application snapshot={snapshot} devices={devices} events={selectedEvents} runtime={runtime} selectedDevice={selectedDevice} selectDevice={(id) => void selectDevice(id)} refresh={() => void refresh()} refreshing={refreshing} error={error} demoMode={demoMode} alertsEnabled={alertsEnabled} alertsSupported={alertsSupported} enableAlerts={() => void enableAlerts()} reviews={reviews} audit={audit} actions={actions} reviewFinding={(finding, state) => void reviewFinding(finding, state)} runAction={(kind) => void runAction(kind)} actionBusy={actionBusy} signOut={() => void signOut()} />;
}
