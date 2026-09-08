import { useEffect, useState } from "react";
import { type DesktopInstallStatus, isStandaloneApp } from "./desktop-install";
import { DeviceInventory } from "./device-inventory";
import { formatDate, formatInterval } from "./format";
import { AlertIcon, BellIcon, CheckIcon, ChipIcon, DefenderIcon, DevicesIcon, HavenIcon, HelpIcon, LockIcon, MonitorIcon, RefreshIcon, SettingsIcon, UpdateIcon } from "./icons";
import { PageIntro } from "./navigation";
import { PanelHeading } from "./panel-heading";
import type { AppRoute } from "./routing";
import type {
  ActionCapability,
  AuditEvent,
  DeviceRecord,
  PasskeyInfo,
  PushNotificationStatus,
  RuntimeStatus,
  SecurityAction,
  SecurityActionKind,
  SystemDiagnostics,
} from "./types";
import { StatusChip, type Tone } from "./ui";

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

function NotificationPanel({ status, supported, enabled, busy, enable, disable }: { status: PushNotificationStatus | null; supported: boolean; enabled: boolean; busy: boolean; enable: (label: string) => void; disable: () => void }) {
  const destinations = status?.destinations || [];
  const [label, setLabel] = useState("This browser");
  const health: Tone = !status?.available || !supported ? "unknown" : status.failedCount > 0 || (enabled && destinations.length === 0) ? "attention" : enabled ? "healthy" : "configured";
  return (
    <section className="panel notification-panel" aria-labelledby="notifications-title">
      <PanelHeading eyebrow="DURABLE DELIVERY" title="Background alerts" id="notifications-title" icon={<BellIcon />} accent="cyan">
        The HAVEN hub evaluates current evidence every {formatInterval(status?.evaluationPeriodSeconds || 60)}, even when this page is closed
      </PanelHeading>
      <div className="notification-summary">
        <StatusChip label={!status?.available ? "hub unavailable" : !supported ? "browser unsupported" : enabled ? "this browser enabled" : "this browser off"} tone={health} />
        <span>{destinations.length} destination{destinations.length === 1 ? "" : "s"} · {status?.pendingCount || 0} queued · {status?.failedCount || 0} failed</span>
      </div>
      {destinations.length > 0 && <div className="notification-destinations">{destinations.map((destination) => <article key={destination.id}><span className="passkey-icon"><BellIcon size={17} /></span><div><h3>{destination.label}</h3><p>{destination.lastSuccessAt ? `Last accepted by its push service ${formatDate(destination.lastSuccessAt)}` : "Ready for the next new medium or high alert"}{destination.failureCount > 0 ? ` · ${destination.failureCount} recent failure${destination.failureCount === 1 ? "" : "s"}` : ""}</p></div></article>)}</div>}
      {!enabled && <label className="auth-field notification-label-field"><span>Destination label</span><input value={label} maxLength={80} disabled={busy} onChange={(event) => setLabel(event.target.value)} autoComplete="off" /></label>}
      <button className="secondary-action" type="button" disabled={busy || !status?.available || !supported} onClick={enabled ? disable : () => enable(label)}>{busy ? "Updating…" : enabled ? "Disable on this browser" : "Enable on this browser"}</button>
      <p className="footnote">Enabling uses the browser vendor's push service. Delivery metadata leaves your network, but the payload is encrypted and contains only the device name, severity, and a prompt to open HAVEN—never the finding details. Existing alerts are baselined silently.</p>
    </section>
  );
}

function DesktopInstallPanel({ status, install }: { status: DesktopInstallStatus; install: () => Promise<void> }) {
  const native = status === "native";
  const installed = status === "installed";
  const available = status === "available";
  return (
    <section className="panel desktop-install-panel" aria-labelledby="desktop-install-title">
      <PanelHeading eyebrow="DESKTOP EXPERIENCE" title="Install HAVEN" id="desktop-install-title" icon={<MonitorIcon />} accent="green">
        Open the same private hub in a dedicated application window from your desktop or Start menu
      </PanelHeading>
      <div className="desktop-install-summary">
        <StatusChip label={native ? "native application" : installed ? "installed" : available ? "ready to install" : "browser install"} tone={native || installed ? "healthy" : available ? "configured" : "unknown"} />
        <p>{native ? "This window is the native HAVEN desktop application." : installed ? "This window is already running as the installed HAVEN web application." : available ? "This browser has verified that HAVEN can be installed as an application." : "Install availability is controlled by this browser. Its app or site menu may provide the install command."}</p>
      </div>
      {available && <button className="secondary-action" type="button" onClick={() => void install()}>Install HAVEN</button>}
      <p className="footnote">This client remains connected to <strong>{window.location.host}</strong>. {native ? "The sandboxed native shell grants this remotely delivered dashboard no Node.js, preload, IPC, filesystem, or shell capabilities." : "The browser-installed experience adds no privileged local service or native command bridge."} It adds no second database or credential store; passkeys and account-workspace locking remain unchanged.</p>
    </section>
  );
}

function diagnosticTone(state: SystemDiagnostics["checks"][number]["state"]): Tone {
	if (state === "pass") return "healthy";
	if (state === "configured") return "configured";
	if (state === "warning") return "attention";
	return "danger";
}

function SystemDiagnosticsPanel({ diagnostics, devices, desktopVersion }: { diagnostics: SystemDiagnostics | null; devices: DeviceRecord[]; desktopVersion: string | null }) {
	const enrolled = devices.filter((device) => device.trustState === "enrolled");
	const compatible = enrolled.filter((device) => device.agent?.compatibility === "current" || device.agent?.compatibility === "compatible").length;
	return (
		<section className="panel system-diagnostics-panel" aria-labelledby="system-diagnostics-title">
			<PanelHeading eyebrow="READ-ONLY OPERATIONS" title="System diagnostics" id="system-diagnostics-title" icon={<SettingsIcon />} accent="green">
				Evidence HAVEN can verify without repairing, enrolling, exporting private state, or changing deployment configuration
			</PanelHeading>
			{diagnostics ? <>
				<div className="diagnostic-release-grid" aria-label="Installed release summary">
					<div><span>Hub release</span><strong>{diagnostics.version}</strong><small>{diagnostics.revision === "development" ? "development revision" : diagnostics.revision.slice(0, 12)}</small></div>
					<div><span>Desktop client</span><strong>{desktopVersion || "Web console"}</strong><small>{desktopVersion ? "native isolated shell" : "no native version detected here"}</small></div>
					<div><span>Agent protocol</span><strong>{compatible}/{enrolled.length}</strong><small>enrolled agents compatible</small></div>
					<div><span>Doctor result</span><strong>{diagnostics.status === "not-ready" ? "Not ready" : diagnostics.status === "review" ? "Review" : "Ready"}</strong><small>{diagnostics.summary.passing} verified · {diagnostics.summary.advisory} advisory · {diagnostics.summary.failed} failed</small></div>
				</div>
				<div className="diagnostic-check-grid">
					{diagnostics.checks.map((check) => <article className={`diagnostic-check diagnostic-${check.state}`} key={check.id}>
						<div><span className="diagnostic-state-icon" aria-hidden="true">{check.state === "fail" ? <AlertIcon size={17} /> : check.state === "warning" ? <HelpIcon size={17} /> : <CheckIcon size={17} />}</span><span><small>{check.area}</small><strong>{check.title}</strong></span><StatusChip label={check.state} tone={diagnosticTone(check.state)} /></div>
						<p>{check.summary}</p>
						{check.guidance && <aside><strong>When relevant</strong>{check.guidance}</aside>}
					</article>)}
				</div>
				<p className="footnote">Generated {formatDate(diagnostics.generatedAt)}. Results deliberately omit filesystem paths, hostnames, addresses, device identities, certificate contents, account details, and secret values.</p>
			</> : <p className="empty-state">The authenticated hub did not return a diagnostic report.</p>}
		</section>
	);
}

function RecoveryModelPanel({ diagnostics }: { diagnostics: SystemDiagnostics | null }) {
	const recovery = diagnostics?.recovery;
  return (
    <section className="panel recovery-model-panel" aria-labelledby="recovery-model-title">
      <PanelHeading eyebrow="PORTABLE BY DESIGN" title="Recovery map" id="recovery-model-title" icon={<HavenIcon />} accent="cyan">
		Know exactly what a state restore preserves and what a clean initialization rebuilds
      </PanelHeading>
	  {recovery ? <>
		<p className="recovery-principle">{recovery.principle}</p>
		<div className="recovery-boundaries">
			<section><h3>Complete state restore preserves</h3><ul>{recovery.preserved.map((item) => <li key={item}><CheckIcon size={16} />{item}</li>)}</ul></section>
			<section><h3>Clean initialization rebuilds</h3><ul>{recovery.reinitialize.map((item) => <li key={item}><RefreshIcon size={16} />{item}</li>)}</ul></section>
		</div>
		<div className="recovery-checklist"><h3>Redacted recovery checklist</h3><ol>{recovery.checklist.map((item) => <li key={item}>{item}</li>)}</ol></div>
	  </> : <p className="empty-state">Recovery guidance is unavailable until hub diagnostics load.</p>}
    </section>
  );
}

function LifecyclePanel() {
	const guides = [
		{ title: "Windows agent", badge: "Task Scheduler", text: "Runs invisibly in the signed-in user's context. Repair by rerunning the installer script; re-enroll only when the local identity is lost or revoked.", command: "haven-agent doctor" },
		{ title: "Linux agent", badge: "systemd user timer", text: "Reports from a user timer without granting the agent root access. Repair the unit and timer before replacing a valid enrolled identity.", command: "haven-agent doctor" },
		{ title: "Hub", badge: "Container service", text: "Treat the complete private state directory as one continuity unit. Rebuild the image from source; never commit deployment secrets or state.", command: "haven-hub doctor" },
		{ title: "Desktop client", badge: "Optional workstation", text: "The Electron shell is a convenience client for one trusted workstation, not a hub or monitoring agent. Reinstalling it does not affect hub data.", command: "No enrollment required" },
	];
	return <section className="panel lifecycle-panel" aria-labelledby="lifecycle-title"><PanelHeading eyebrow="INSTALL · REPAIR · RE-ENROLL" title="Lifecycle guide" id="lifecycle-title" icon={<UpdateIcon />} accent="blue">Use the least disruptive recovery step that matches the failed layer</PanelHeading><div className="lifecycle-grid">{guides.map((guide) => <article key={guide.title}><div><h3>{guide.title}</h3><StatusChip label={guide.badge} tone="configured" /></div><p>{guide.text}</p><code>{guide.command}</code></article>)}</div><p className="footnote">Doctor commands are read-only and intentionally do not repair services, rotate certificates, create enrollments, contact third parties, or print private configuration values.</p></section>;
}

export function SystemRecoveryPage({ diagnostics, devices, desktopVersion, desktopInstallStatus, installDesktopApp, demoMode, notificationStatus, alertsSupported, alertsEnabled, actionBusy, enableAlerts, disableAlerts, passkeys, addOwnerPasskey, removeOwnerPasskey, runtime }: { diagnostics: SystemDiagnostics | null; devices: DeviceRecord[]; desktopVersion: string | null; desktopInstallStatus: DesktopInstallStatus; installDesktopApp: () => Promise<void>; demoMode: boolean; notificationStatus: PushNotificationStatus | null; alertsSupported: boolean; alertsEnabled: boolean; actionBusy: boolean; enableAlerts: (label: string) => void; disableAlerts: () => void; passkeys: PasskeyInfo[]; addOwnerPasskey: () => void; removeOwnerPasskey: (passkey: PasskeyInfo) => void; runtime: RuntimeStatus | null }) {
	return <>
		<PageIntro eyebrow="OPERATIONS AND CONTINUITY" title="System & Recovery">Verify how HAVEN is running, understand what a backup preserves, and choose the least disruptive repair path.</PageIntro>
		<SystemDiagnosticsPanel diagnostics={diagnostics} devices={devices} desktopVersion={desktopVersion} />
		<RecoveryModelPanel diagnostics={diagnostics} />
		<LifecyclePanel />
		<DesktopInstallPanel status={desktopInstallStatus} install={installDesktopApp} />
		{!demoMode ? <><NotificationPanel status={notificationStatus} supported={alertsSupported} enabled={alertsEnabled} busy={actionBusy} enable={enableAlerts} disable={disableAlerts} /><PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} /></> : <p className="demo-banner" role="status">Authentication and notification settings are unavailable in synthetic demo mode.</p>}
		<section className="panel about-panel" aria-labelledby="about-title"><PanelHeading eyebrow="APPLICATION" title="About HAVEN" id="about-title" icon={<HavenIcon />} accent="green">Private, explainable security visibility</PanelHeading><dl className="details-grid"><div><dt>Version</dt><dd>{runtime?.version || "development"}</dd></div><div><dt>Revision</dt><dd>{runtime?.revision && runtime.revision !== "development" ? runtime.revision.slice(0, 12) : "development"}</dd></div><div><dt>Collection</dt><dd>Read-only by default</dd></div><div><dt>Storage</dt><dd>Private SQLite hub</dd></div></dl></section>
	</>;
}

export function ActionCenter({ actions, audit, capabilities, run, busy }: { actions: SecurityAction[]; audit: AuditEvent[]; capabilities: ActionCapability[]; run: (kind: SecurityActionKind) => void; busy: boolean }) {
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

export function AwaitingAgents({ devices, runtime, diagnostics, notificationStatus, passkeys, actions, audit, error, selectDevice, addOwnerPasskey, removeOwnerPasskey, actionBusy, signOut, alertsSupported, alertsEnabled, enableAlerts, disableAlerts, desktopInstallStatus, desktopVersion, installDesktopApp, route, navigate }: { devices: DeviceRecord[]; runtime: RuntimeStatus | null; diagnostics: SystemDiagnostics | null; notificationStatus: PushNotificationStatus | null; passkeys: PasskeyInfo[]; actions: SecurityAction[]; audit: AuditEvent[]; error: string | null; selectDevice: (id: string) => void; addOwnerPasskey: () => void; removeOwnerPasskey: (passkey: PasskeyInfo) => void; actionBusy: boolean; signOut: () => void; alertsSupported: boolean; alertsEnabled: boolean; enableAlerts: (label: string) => void; disableAlerts: () => void; desktopInstallStatus: DesktopInstallStatus; desktopVersion: string | null; installDesktopApp: () => Promise<void>; route: AppRoute; navigate: (route: AppRoute) => void }) {
  const awaiting = devices.some((device) => device.status === "awaiting-first-report");
	const settings = route.page === "settings";
	useEffect(() => { document.title = isStandaloneApp() ? (settings ? "System & Recovery" : "Devices") : `${settings ? "System & Recovery" : "Devices"} — HAVEN`; }, [settings]);
	const follow = (event: React.MouseEvent<HTMLAnchorElement>, next: AppRoute) => { if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return; event.preventDefault(); navigate(next); };
  return <>
    <header className="topbar">
	  <a className="brand" href="/devices" aria-label="HAVEN home" onClick={(event) => follow(event, { page: "devices" })}><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
	  <nav className="app-navigation" aria-label="Setup navigation"><a href="/devices" aria-current={!settings ? "page" : undefined} onClick={(event) => follow(event, { page: "devices" })}><DevicesIcon />Devices</a><a href="/settings" aria-current={settings ? "page" : undefined} onClick={(event) => follow(event, { page: "settings" })}><SettingsIcon />System</a></nav>
      <div className="topbar-actions"><span className="local-pill" aria-label="Hub ready"><span className="local-dot" /><span className="local-label">Hub ready</span></span><button className="signout-button" type="button" onClick={signOut} aria-label="Lock HAVEN" title="Lock HAVEN"><LockIcon size={15} /><span className="topbar-action-label">Lock</span></button></div>
    </header>
    <main>
	  {settings ? <SystemRecoveryPage diagnostics={diagnostics} devices={devices} desktopVersion={desktopVersion} desktopInstallStatus={desktopInstallStatus} installDesktopApp={installDesktopApp} demoMode={false} notificationStatus={notificationStatus} alertsSupported={alertsSupported} alertsEnabled={alertsEnabled} actionBusy={actionBusy} enableAlerts={enableAlerts} disableAlerts={disableAlerts} passkeys={passkeys} addOwnerPasskey={addOwnerPasskey} removeOwnerPasskey={removeOwnerPasskey} runtime={runtime} /> : <><PageIntro eyebrow="TRUSTED INVENTORY" title="Devices">Enroll a native endpoint, then wait for its first authenticated observation.</PageIntro><DeviceInventory devices={devices} selectedId="" select={selectDevice} demoMode={false} />{error && <p className="inline-error" role="alert">{error}</p>}<section className="panel awaiting-panel"><PanelHeading eyebrow="NATIVE AGENTS" title={awaiting ? "Waiting for the first observation" : "No endpoints are enrolled yet"} id="awaiting-title" icon={<DevicesIcon />} accent="cyan">The production hub stores and explains observations; native agents collect them from each operating system</PanelHeading><div className="activity-empty"><strong>{awaiting ? "An enrolled agent has not reported yet." : "The hub is healthy and ready for its first trusted endpoint."}</strong><span>Once an enrolled endpoint reports, its verified protection, firewall, baseline, and connection signals will appear here. Container identities are never treated as household devices.</span></div></section><PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} /><ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={() => undefined} busy={actionBusy} /></>}
    </main>
    <footer><span>HAVEN {runtime?.version || "development"} · Agent enrollment</span><span>Observe continuously. Act deliberately.</span></footer>
  </>;
}
