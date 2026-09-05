import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HavenAPIError, addPasskey, collectSnapshot, getAuthStatus, getDevice, getLatestSnapshot, getNotificationStatus, getRuntimeStatus, listAccountProfiles, listAlerts, listAuditEvents, listDevices, listEvents, listExpectedServices, listFindingReviews, listManagedAppliances, listObservedListeners, listPasskeys, listSecurityActions, lockAccountNotebook, loginWithPasskey, logout, registerPasskey, registerPushDestination, removeAccountProfile, removeExpectedService, removePasskey, removePushDestination, requestSecurityAction, saveAccountProfile, saveExpectedService, saveExpectedServices, saveFindingReview, touchAccountNotebook, unlockAccountNotebook } from "./api";
import { AccountNotebook } from "./account-notebook";
import { suggestedBaseline } from "./baseline";
import { AuthenticationGate } from "./authentication-gate";
import { BrowserSecurityPanel } from "./browser-security";
import { DeviceInventory } from "./device-inventory";
import { type DesktopInstallStatus, isStandaloneApp, useDesktopInstall } from "./desktop-install";
import { AgentEvidencePanel, FleetPanel } from "./fleet-panel";
import { actionableFindings, visibleFindingLifecycles } from "./findings";
import { booleanValue, formatBytes, formatDate, formatDuration, formatInterval, formatPortBinding, formatRelativeTime, formatTimeRemaining, policyValue } from "./format";
import { ActivityIcon, AlertIcon, BellIcon, CheckIcon, ChipIcon, DefenderIcon, DevicesIcon, FirewallIcon, HavenIcon, HelpIcon, LaptopIcon, LockIcon, MonitorIcon, NetworkIcon, RefreshIcon, RemoteAccessIcon, ServerIcon, UpdateIcon, UsersIcon, WorkloadIcon } from "./icons";
import { componentHealthTone, coverageTone, healthStatusLabel, managedHealthTone, storageSetDetail, storageSetLabel } from "./appliance-health";
import { AppNavigation, DeviceNavigation, PageIntro } from "./navigation";
import { bindScopeLabel, endpoint, endpointScope, expectedServiceMatches, expectedServiceOwnerConstrained, isPrivateNetworkAddress, listenerOwnerSummary, liveNetworkRelationships, logicalListeners, networkServiceLabel, normalizeAddress, workloadAttribution, type LogicalListener, type NetworkDeviceObservation } from "./network";
import { decodeApplicationServerKey, normalizePushDestinationLabel, serializePushSubscription, supportsBackgroundPush } from "./push";
import { type AppRoute, type DeviceSection, useAppRoute } from "./routing";
import type {
  BaselineCheck,
  AccountAccessGrant,
  AccountProfile,
  AccountProfileInput,
  AuditEvent,
  ActionCapability,
  AuthStatus,
  BindScope,
  ContainerWorkload,
  DefenderStatus,
  DeviceRecord,
  ExpectedService,
  ExpectedServiceInput,
  FindingReview,
  FindingReviewState,
  FirewallProfileStatus,
  HavenAlert,
  LinuxBaseline,
  ManagedApplianceStatus,
  ManagedHealthStatus,
  NetworkConnection,
  ObservedListener,
  PasskeyInfo,
  PushNotificationStatus,
  RuntimeStatus,
  SecurityEvent,
  SecurityAction,
  SecurityActionKind,
  SecuritySnapshot,
  SecurityFinding,
  WorkloadInventory,
} from "./types";
import { StatusChip, type Accent, type Tone } from "./ui";


async function loadNetworkObservations(inventory: DeviceRecord[], demoMode: boolean, signal?: AbortSignal) {
  const visible = inventory.filter((device) => device.trustState !== "revoked");
  return Promise.all(visible.map(async (device): Promise<NetworkDeviceObservation> => {
    const [detail, expectedServices, listenerObservations] = await Promise.all([
      getDevice(device.id, signal),
      demoMode ? Promise.resolve([]) : listExpectedServices(device.id, signal),
      demoMode ? Promise.resolve([]) : listObservedListeners(device.id, signal),
    ]);
    return { device, snapshot: detail.snapshot, expectedServices, listenerObservations };
  }));
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

function ApplianceHealthPanel({ health }: { health: ManagedHealthStatus }) {
	const coverage = [
		["Disks + SMART", health.coverage.disks],
		["Storage sets", health.coverage.raid],
		["Temperature", health.coverage.temperature],
		["Capacity", health.coverage.capacity],
		["Firmware", health.coverage.firmware],
	] as const;
	const systemTemperatures = health.temperatures.filter((temperature) => temperature.kind !== "disk");
	return <section className="appliance-health" aria-label="Read-only NAS health">
		<div className="appliance-health-heading"><div><strong>Storage health</strong><small>Read-only evidence · checked {formatRelativeTime(health.lastCheckedAt)}</small></div><StatusChip label={healthStatusLabel(health.status)} tone={managedHealthTone(health.status)} /></div>
		<div className="appliance-health-system">
			<span><small>Model</small><strong>{health.system.model || "Not exposed"}</strong></span>
			<span><small>Firmware</small><strong>{health.system.firmwareVersion || "Not exposed"}</strong></span>
			<span><small>Kernel</small><strong>{health.system.kernelVersion || "Not exposed"}</strong></span>
			<span><small>Uptime</small><strong>{health.system.uptimeSeconds === undefined ? "Not exposed" : formatDuration(health.system.uptimeSeconds)}</strong></span>
		</div>
		<div className="appliance-coverage" aria-label="Health evidence coverage">{coverage.map(([label, state]) => <span key={label}><small>{label}</small><StatusChip label={state} tone={coverageTone(state)} /></span>)}</div>
		{health.errorClass && <p className="appliance-health-note">One read-only source was unavailable during this check. Available evidence remains visible and is not promoted to fully healthy.</p>}
		{health.disks.length > 0 && <div className="appliance-health-group"><h4>Physical disks</h4><ul>{health.disks.map((disk) => <li key={disk.name}><span><strong>{disk.name}{disk.model ? ` · ${disk.model}` : ""}</strong><small>{formatBytes(disk.capacityBytes)}{disk.temperatureC === undefined ? "" : ` · ${disk.temperatureC.toFixed(0)}°C`} · SMART {disk.smart}</small></span><StatusChip label={disk.state} tone={componentHealthTone(disk.state)} /></li>)}</ul></div>}
		{health.pools.length > 0 && <div className="appliance-health-group"><h4>Storage sets</h4><ul>{health.pools.map((pool) => <li key={pool.name}><span><strong>{pool.name} · {storageSetLabel(pool)}</strong><small>{storageSetDetail(pool)}</small></span><StatusChip label={pool.state} tone={componentHealthTone(pool.state)} /></li>)}</ul></div>}
		{health.volumes.length > 0 && <div className="appliance-health-group"><h4>Volume capacity</h4><ul>{health.volumes.map((volume) => {
			const width = Math.min(100, Math.max(0, volume.usedPercentage));
			return <li className="appliance-volume" key={volume.name}><span><strong>{volume.name}</strong><small>{volume.usedPercentage.toFixed(1)}% used · {formatBytes(volume.availableBytes)} available of {formatBytes(volume.capacityBytes)}</small><span className="capacity-track" aria-hidden="true"><span style={{ width: `${width}%` }} /></span></span><StatusChip label={volume.state} tone={componentHealthTone(volume.state)} /></li>;
		})}</ul></div>}
		{systemTemperatures.length > 0 && <div className="appliance-health-group"><h4>System temperature</h4><ul>{systemTemperatures.map((temperature) => <li key={`${temperature.kind}:${temperature.name}`}><span><strong>{temperature.name}</strong><small>{temperature.celsius.toFixed(1)}°C</small></span><StatusChip label={temperature.state} tone={componentHealthTone(temperature.state)} /></li>)}</ul></div>}
		{health.status === "partial" && <p className="appliance-health-note">No alert is inferred from missing coverage. HAVEN reports it as partly verified until the appliance exposes that signal.</p>}
	</section>;
}

type NetworkView = "overview" | "network" | "appliances";

function NetworkOverview({ devices, appliances, events, alerts, selectedId, selectDevice, demoMode, view }: { devices: NetworkDeviceObservation[]; appliances: ManagedApplianceStatus[]; events: SecurityEvent[]; alerts: HavenAlert[]; selectedId: string; selectDevice: (id: string) => void; demoMode: boolean; view: NetworkView }) {
	const summaries = useMemo(() => devices.map((entry) => {
		const snapshot = entry.snapshot;
		const listeners = logicalListeners(snapshot?.connections || []);
		const workloadInventory = snapshot?.linuxBaseline?.workloads ?? null;
		const unreviewed = listeners.filter((listener) => listener.bindScope !== "local" && !entry.expectedServices.some((service) => expectedServiceMatches(listener, service, workloadInventory)));
		const recentUnreviewed = unreviewed.filter((listener) => {
			const observation = entry.listenerObservations.find((item) => item.present && item.protocol === listener.protocol && item.port === listener.port && item.bindScope === listener.bindScope);
			return observation && Date.now() - new Date(observation.appearedAt).valueOf() < 24 * 60 * 60 * 1000;
		}).length;
		const findingAlerts = alerts.filter((alert) => alert.deviceId === entry.device.id && alert.kind === "finding");
		const highFindings = findingAlerts.filter((alert) => alert.severity === "high").length;
		const firewallKnown = !!snapshot && snapshot.firewallProfiles.length > 0;
		const firewallEnabled = firewallKnown && snapshot!.firewallProfiles.every((profile) => profile.enabled === true);
		const establishedConnections = (snapshot?.connections || []).filter((connection) => connection.state.toLowerCase() === "established").length;
		let tone: Tone = "healthy";
		let label = "observed healthy";
		if (!snapshot) { tone = "unknown"; label = "awaiting report"; }
		else if (!firewallKnown) { tone = "unknown"; label = "partly verified"; }
		else if (!firewallEnabled || highFindings > 0) { tone = "danger"; label = !firewallEnabled ? "firewall attention" : "high finding"; }
		else if (entry.device.status !== "current" || findingAlerts.length > 0 || unreviewed.length > 0) { tone = "attention"; label = entry.device.status !== "current" ? entry.device.status.replaceAll("-", " ") : unreviewed.length > 0 ? "service review" : "finding open"; }
		return { ...entry, listeners, unreviewed, recentUnreviewed, findingAlerts, firewallKnown, firewallEnabled, establishedConnections, tone, label };
	}), [alerts, devices]);
	const relationships = useMemo(() => liveNetworkRelationships(devices, appliances), [appliances, devices]);
	const recentChanges = useMemo(() => visibleFindingLifecycles(events, alerts).slice(0, 5), [alerts, events]);
	const reportingCount = summaries.filter((entry) => entry.device.status === "current" && entry.snapshot).length;
	const protectedFirewallCount = summaries.filter((entry) => entry.firewallEnabled).length;
	const knownFirewallCount = summaries.filter((entry) => entry.firewallKnown).length;
	const findingCount = summaries.reduce((count, entry) => count + entry.findingAlerts.length, 0);
	const unreviewedCount = summaries.reduce((count, entry) => count + entry.unreviewed.length, 0);
	const activeConnectionCount = summaries.reduce((count, entry) => count + entry.establishedConnections, 0);
	const observedAssetCount = new Set(relationships.filter((item) => item.peerKind === "observed").flatMap((item) => [item.sourceName, item.targetName].filter((name) => isPrivateNetworkAddress(name)))).size;
	const applianceReachableCount = appliances.filter((appliance) => appliance.lastCheckedAt && appliance.status !== "attention" && appliance.services.filter((service) => service.required).every((service) => service.reachable)).length;
	const applianceAttentionCount = appliances.filter((appliance) => appliance.status === "attention").length;
	const appliancePendingCount = appliances.filter((appliance) => appliance.status === "pending" || appliance.status === "rechecking").length;
	const applianceAlertCount = alerts.filter((alert) => alert.deviceId.startsWith("appliance:")).length;
	const applianceReviewCount = Math.max(applianceAttentionCount, applianceAlertCount);
	const urgent = summaries.some((entry) => entry.tone === "danger");
	const attention = summaries.some((entry) => entry.tone === "attention") || unreviewedCount > 0 || applianceReviewCount > 0;
	const assuranceTone: Tone = urgent ? "danger" : attention ? "attention" : summaries.some((entry) => entry.tone === "unknown") || appliancePendingCount > 0 ? "unknown" : "healthy";
	const assuranceLabel = urgent ? "Action recommended" : attention ? "Review available" : assuranceTone === "unknown" ? "Partly verified" : "Observed baseline steady";
	const attentionReasons = [
		findingCount > 0 ? `${findingCount} current finding${findingCount === 1 ? "" : "s"}` : "",
		unreviewedCount > 0 ? `${unreviewedCount} service review${unreviewedCount === 1 ? "" : "s"}` : "",
		reportingCount < summaries.length ? `${summaries.length - reportingCount} device${summaries.length - reportingCount === 1 ? "" : "s"} not current` : "",
		applianceReviewCount > 0 ? `${applianceReviewCount} appliance alert${applianceReviewCount === 1 ? "" : "s"}` : "",
	].filter(Boolean);
	const attentionItemCount = findingCount + unreviewedCount + summaries.length - reportingCount + applianceReviewCount;
	const visibleRelationships = relationships.slice(0, 12);

	return (
		<section className={`panel network-overview-panel network-view-${view}`} aria-labelledby={`${view}-view-title`}>
			<PanelHeading eyebrow={view === "appliances" ? "MANAGED APPLIANCES" : "HOME NETWORK"} title={view === "overview" ? "Security at a glance" : view === "network" ? "Network activity" : "Appliance health"} id={`${view}-view-title`} icon={view === "appliances" ? <ServerIcon /> : <NetworkIcon />} accent="cyan">
				{view === "appliances" ? "Health from explicitly configured private devices" : demoMode ? "Synthetic relationships across the demo inventory" : "Latest authenticated reports; live connection details are not retained as history"}
			</PanelHeading>
			{view === "overview" && <>
			<div className={`network-assurance ${assuranceTone}`}>
				<span className="network-assurance-icon">{urgent || attention ? <AlertIcon size={20} /> : <CheckIcon size={20} />}</span>
				<div><strong>{assuranceLabel}</strong><p>{urgent ? "At least one reporting device has a high finding or firewall problem." : attention ? `${attentionReasons.join(" · ")} ${attentionItemCount === 1 ? "remains" : "remain"} visible across monitored systems.` : assuranceTone === "unknown" ? "No urgent issue is derived, but one or more devices has incomplete current evidence." : "Every reporting device matches its reviewed baseline, and no required managed-appliance service is failing."}</p></div>
				<StatusChip label={assuranceLabel} tone={assuranceTone} />
			</div>
			<div className="network-metrics" aria-label="Network coverage summary">
				<article><span>Reporting now</span><strong>{reportingCount}/{summaries.length}</strong><small>enrolled devices current</small></article>
				<article><span>Protected firewalls</span><strong>{protectedFirewallCount}/{knownFirewallCount || summaries.length}</strong><small>{knownFirewallCount === summaries.length ? "verified devices" : `${summaries.length - knownFirewallCount} not verified`}</small></article>
				<article><span>Open findings</span><strong>{findingCount}</strong><small>across current posture</small></article>
				<article><span>Service reviews</span><strong>{unreviewedCount}</strong><small>non-local listeners</small></article>
				<article><span>Appliances reachable</span><strong>{applianceReachableCount}/{appliances.length}</strong><small>{appliances.length ? "required services reachable" : "none configured"}</small></article>
			</div>
			<section className="network-alert-watch" aria-labelledby="network-alerts-title">
				<div className="network-subheading"><div><p className="eyebrow">ACTIVE ALERTS</p><h3 id="network-alerts-title">What currently needs attention</h3></div><span>{alerts.length} active</span></div>
				<p className="network-privacy-note">Alerts come only from authenticated report freshness, evaluated posture findings, and owner-reviewed service baselines. An alert is a review prompt—not a claim that an attack occurred.</p>
				{alerts.length === 0 ? <p className="alert-watch-clear"><CheckIcon size={18} /><span><strong>No active alerts.</strong><small>Current reports match the reviewed baseline.</small></span></p> : <ol className="network-alert-list">{alerts.slice(0, 8).map((alert) => {
					const tone: Tone = alert.severity === "high" ? "danger" : alert.severity === "medium" ? "attention" : "configured";
					const endpointDevice = !alert.deviceId.startsWith("appliance:");
					return <li key={alert.id}><button type="button" onClick={() => { if (endpointDevice) selectDevice(alert.deviceId); }}><span className={`alert-watch-icon ${alert.severity}`}><AlertIcon size={17} /></span><span><strong>{alert.title}</strong><small>{alert.deviceName} · active since {formatRelativeTime(alert.startedAt)} · {alert.evidence}</small><em>{alert.summary}</em></span><StatusChip label={alert.severity} tone={tone} /></button></li>;
				})}</ol>}
				{alerts.length > 8 && <p className="network-overflow-note">Showing 8 of {alerts.length} current alerts.</p>}
			</section>
			<section className="network-subsection overview-changes" aria-labelledby="network-changes-title">
				<div className="network-subheading"><div><p className="eyebrow">CHANGE WATCH</p><h3 id="network-changes-title">Recent security changes</h3></div><span>latest lifecycle</span></div>
				{recentChanges.length === 0 ? <p className="activity-empty"><strong>No finding transitions yet.</strong><span>Routine unchanged reports remain quiet.</span></p> : <ol className="network-change-list">{recentChanges.map(({ event }) => {
					const resolved = event.kind === "resolved";
					const tone: Tone = resolved ? "healthy" : event.severity === "high" ? "danger" : event.severity === "medium" ? "attention" : "configured";
					return <li key={event.id}><span className={`network-change-mark ${resolved ? "resolved" : event.severity}`} /> <div><strong>{resolved ? `Resolved: ${event.title}` : event.title}</strong><small>{event.deviceName} · {formatRelativeTime(event.occurredAt)}</small></div><StatusChip label={resolved ? "resolved" : event.severity} tone={tone} /></li>;
				})}</ol>}
			</section>
			</>}
			{view === "network" && <>
				<section className="network-subsection" aria-labelledby="network-devices-title">
					<div className="network-subheading"><div><p className="eyebrow">ENROLLED DEVICES</p><h3 id="network-devices-title">Security coverage</h3></div><span>{summaries.length} trusted</span></div>
					<div className="network-device-grid">
						{summaries.map((entry) => <button className={`network-device-card ${selectedId === entry.device.id ? "selected" : ""}`} type="button" key={entry.device.id} onClick={() => selectDevice(entry.device.id)} aria-pressed={selectedId === entry.device.id} disabled={!entry.snapshot}>
							<div className="network-device-heading"><span className="device-icon">{entry.device.operatingSystem.toLowerCase().includes("server") ? <ServerIcon /> : entry.device.displayName.toLowerCase().includes("laptop") ? <LaptopIcon /> : <MonitorIcon />}</span><span><strong>{entry.device.displayName}</strong><small>{entry.device.operatingSystem || "Awaiting first report"}</small></span><StatusChip label={entry.label} tone={entry.tone} /></div>
							<dl><div><dt>Last report</dt><dd>{formatRelativeTime(entry.device.lastCollectedAt)}</dd></div><div><dt>Host firewall</dt><dd>{entry.firewallKnown ? entry.firewallEnabled ? "Protected" : "Attention" : "Not verified"}</dd></div><div><dt>Findings</dt><dd>{entry.findingAlerts.length}</dd></div><div><dt>Services</dt><dd>{entry.unreviewed.length > 0 ? `${entry.unreviewed.length} to review${entry.recentUnreviewed > 0 ? ` · ${entry.recentUnreviewed} new` : ""}` : `${entry.listeners.length} classified/local`}</dd></div></dl>
						</button>)}
					</div>
				</section>
			</>}
			{view === "appliances" &&
			<section className="network-appliances" aria-labelledby="managed-appliances-title">
				<div className="network-subheading"><div><p className="eyebrow">EXPLICITLY CONFIGURED · AGENTLESS</p><h3 id="managed-appliances-title">Managed appliances</h3></div><span>{appliances.length} monitored</span></div>
				<p className="network-privacy-note">The hub checks only addresses and ports declared in private deployment configuration. Optional health collection uses file-backed credentials, a pinned host key, and a fixed read-only command; credentials, filenames, shares, disk serials, and raw responses are never returned or retained.</p>
				{appliances.length === 0 ? <p className="activity-empty"><strong>No managed appliances configured.</strong><span>Network appliances remain observed-only until explicitly added by the owner.</span></p> : <div className="appliance-grid">{appliances.map((appliance) => {
					const tone: Tone = appliance.health ? managedHealthTone(appliance.health.status) : appliance.status === "healthy" || appliance.status === "observed" ? "healthy" : appliance.status === "attention" ? "attention" : appliance.status === "rechecking" ? "configured" : "unknown";
					const statusLabel = appliance.health ? healthStatusLabel(appliance.health.status) : appliance.status;
					return <article className="appliance-card" key={appliance.id}>
						<header><span className="device-icon"><ServerIcon /></span><span><strong>{appliance.displayName}</strong><small>{appliance.kind.toUpperCase()} · {appliance.address} · checked {formatRelativeTime(appliance.lastCheckedAt)}</small></span><StatusChip label={statusLabel} tone={tone} /></header>
						{appliance.health && <ApplianceHealthPanel health={appliance.health} />}
						<ul>{appliance.services.map((service) => {
							const serviceTone: Tone = service.reachable ? "healthy" : !service.lastCheckedAt ? "unknown" : service.required && service.consecutiveFailures >= 2 ? "attention" : "configured";
							return <li key={service.id}><span><strong>{service.name}</strong><small>{service.protocol} {service.port}{service.tls ? " · TLS" : ""}{service.required ? " · required" : " · visibility only"}</small>{service.certificate && <small>Certificate valid until {formatDate(service.certificate.notAfter)} · {service.certificate.nameValid ? "address matches" : "address does not match certificate name"}</small>}</span><StatusChip label={service.reachable ? "reachable" : !service.lastCheckedAt ? "pending" : "not reached"} tone={serviceTone} /></li>;
						})}</ul>
					</article>;
				})}</div>}
			</section>
			}
			{view === "network" &&
			<section className="network-flows" aria-labelledby="network-flows-title">
				<div className="network-subheading"><div><p className="eyebrow">LIVE RELATIONSHIPS</p><h3 id="network-flows-title">Who is talking to what</h3></div><span>{activeConnectionCount} endpoint-reported · {observedAssetCount} observed-only private asset{observedAssetCount === 1 ? "" : "s"}</span></div>
				<p className="network-privacy-note">This is not a LAN scan. An observed-only asset is a private endpoint contacted by an enrolled device; it is neither trusted nor enrolled automatically. Internet connections are grouped by source process and destination service to reduce noise.</p>
				{visibleRelationships.length === 0 ? <p className="activity-empty"><strong>No live relationships were returned.</strong><span>They will reappear after the next agent report and are never reconstructed from historical connection logs.</span></p> : <ol className="network-flow-list">{visibleRelationships.map((relationship) => {
					const service = networkServiceLabel(relationship.protocol, relationship.port);
					const label = relationship.peerKind === "enrolled" ? "enrolled" : relationship.peerKind === "managed" ? "managed" : relationship.peerKind === "observed" ? "observed only" : "external group";
					const tone: Tone = relationship.peerKind === "enrolled" ? "healthy" : relationship.peerKind === "managed" ? "configured" : relationship.peerKind === "observed" ? "configured" : "unknown";
					return <li key={relationship.key}><span className={`network-flow-icon ${relationship.peerKind}`}><NetworkIcon size={17} /></span><div><strong>{relationship.sourceName} <span aria-hidden="true">→</span> {relationship.targetName}</strong><small>{relationship.owners.join(", ")} · {relationship.protocol} {relationship.port}{service ? ` (${service})` : ""} · {relationship.connectionCount} connection{relationship.connectionCount === 1 ? "" : "s"}{relationship.peerKind === "external" && relationship.destinationCount > 1 ? ` to ${relationship.destinationCount} destinations` : ""}</small></div><StatusChip label={label} tone={tone} /></li>;
				})}</ol>}
				{relationships.length > visibleRelationships.length && <p className="network-overflow-note">Showing the 12 highest-context relationship groups; {relationships.length - visibleRelationships.length} additional external group{relationships.length - visibleRelationships.length === 1 ? " is" : "s are"} summarized out of this overview.</p>}
			</section>
			}
		</section>
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
	const [editingListenerKey, setEditingListenerKey] = useState<string | null>(null);
	const [listenerLabel, setListenerLabel] = useState("");
	const [listenerDurationHours, setListenerDurationHours] = useState(0);
	const listeners = useMemo(() => logicalListeners(connections), [connections]);
	useEffect(() => { setEditingListenerKey(null); setListenerLabel(""); setListenerDurationHours(0); }, [deviceId]);
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
	const beginExpected = (listener: LogicalListener, durationHours = 0) => {
		setEditingListenerKey(listener.key);
		setListenerLabel(`${listener.protocol} ${listener.port}`);
		setListenerDurationHours(durationHours);
	};
	const markExpected = (event: React.FormEvent, listener: LogicalListener) => {
		event.preventDefault();
		if (!listenerLabel.trim()) return;
		const expiresAt = listenerDurationHours > 0 ? new Date(Date.now() + listenerDurationHours * 60 * 60 * 1000).toISOString() : null;
		saveExpectation({ deviceId, label: listenerLabel.trim(), protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: workloadAttribution(listener, workloads).map(({ workload }) => workload.name), systemdUnits: listener.systemdUnits, expiresAt });
		setEditingListenerKey(null);
		setListenerLabel("");
		setListenerDurationHours(0);
	};
	const extendExpectation = (service: ExpectedService, durationHours = 8) => {
		saveExpectation({ deviceId: service.deviceId, label: service.label, protocol: service.protocol, port: service.port, portEnd: service.portEnd, bindScope: service.bindScope, processNames: service.processNames, workloadNames: service.workloadNames, systemdUnits: service.systemdUnits, expiresAt: new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString() });
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
		  const statusLabel = expectation?.expiresAt ? `temporary · ${formatTimeRemaining(expectation.expiresAt)}` : expectation ? "expected" : listener.bindScope === "local" ? recentlyAppeared ? "new · local only" : "local only" : recentlyAppeared ? "new · unreviewed" : "unreviewed";
		  const ownerConstraints = [...listener.processes, ...listener.systemdUnits, ...attributions.map(({ workload }) => workload.name)];
		  return <article className={`service-card ${expectation ? "expected" : listener.bindScope === "local" ? "local" : "review"}`} key={listener.key}>
			<div className="service-card-heading"><div><span className="protocol">{listener.protocol}</span><strong>Port {listener.port}</strong></div><StatusChip label={statusLabel} tone={expectation ? "healthy" : listener.bindScope === "local" ? "configured" : "attention"} /></div>
			<h3>{expectation?.label || (attributions.length === 1 ? attributions[0].workload.name : `${listener.protocol} service on port ${listener.port}`)}</h3>
			<dl><div><dt>Bind scope</dt><dd>{bindScopeLabel(listener.bindScope)}</dd></div><div><dt>State</dt><dd>{listener.state}</dd></div><div><dt>Addresses</dt><dd className="endpoint">{listener.addresses.join(", ") || "Not reported"}</dd></div>{listener.processes.length > 0 && <div><dt>Host process</dt><dd>{listener.processes.join(", ")}</dd></div>}{listener.systemdUnits.length > 0 && <div><dt>System service</dt><dd>{listener.systemdUnits.join(", ")}</dd></div>}{attributions.length > 0 && <><div><dt>Runtime owner</dt><dd>{attributions.map(({ workload }) => workload.name).join(", ")}</dd></div><div><dt>Docker mapping</dt><dd className="endpoint">{attributions.flatMap(({ bindings }) => bindings).map(formatPortBinding).join(", ")}</dd></div></>}</dl>
			<p>{observation ? `First observed ${formatDate(observation.firstSeenAt)} · continuously present since ${formatDate(observation.appearedAt)} · last confirmed ${formatRelativeTime(observation.lastSeenAt)}` : "Appearance history will begin with the next agent report."}{listener.rawCount > 1 ? ` · ${listener.rawCount} raw sockets grouped` : ""}</p>
			{expectation?.expiresAt && <p className="footnote"><strong>Temporary expectation.</strong> Expires in {formatTimeRemaining(expectation.expiresAt)} on {formatDate(expectation.expiresAt)}; this listener will require review again if it is still present.</p>}
			{expectation && !expectedServiceOwnerConstrained(expectation) && <p className="footnote"><strong>Port-only expectation.</strong> HAVEN checks this endpoint and bind scope, but any reported owner can satisfy the saved rule.</p>}
			{expectation ? <div className="listener-review-actions">{expectation.expiresAt && <button className="secondary-action" type="button" disabled={busy} onClick={() => extendExpectation(expectation)}>Extend 8 hours</button>}<button className="secondary-action" type="button" disabled={busy} onClick={() => removeExpectation(expectation)}>Remove expectation</button></div> : editingListenerKey === listener.key ? <form className="service-expectation-editor" onSubmit={(event) => markExpected(event, listener)}>
			  <label htmlFor={`listener-label-${listener.key}`}><span>Friendly label</span><input id={`listener-label-${listener.key}`} maxLength={80} autoFocus value={listenerLabel} onChange={(event) => setListenerLabel(event.target.value)} /></label>
			  <label htmlFor={`listener-duration-${listener.key}`}><span>Duration</span><select id={`listener-duration-${listener.key}`} value={listenerDurationHours} onChange={(event) => setListenerDurationHours(Number(event.target.value))}><option value={0}>Permanent</option><option value={1}>1 hour</option><option value={8}>8 hours</option><option value={24}>24 hours</option><option value={168}>7 days</option></select></label>
			  <small>Matches {listener.protocol} {listener.port}, {bindScopeLabel(listener.bindScope).toLowerCase()}{ownerConstraints.length ? `, and current owner${ownerConstraints.length === 1 ? "" : "s"}: ${ownerConstraints.join(", ")}` : ""}. Temporary expectations expire on the hub even when this browser is closed.</small>
			  <div><button type="submit" disabled={busy || !listenerLabel.trim()}>{busy ? "Saving…" : listenerDurationHours > 0 ? "Save temporary expectation" : "Save expectation"}</button><button className="secondary-action" type="button" disabled={busy} onClick={() => { setEditingListenerKey(null); setListenerLabel(""); setListenerDurationHours(0); }}>Cancel</button></div>
			</form> : <div className="listener-review-actions"><button className="secondary-action" type="button" disabled={busy} onClick={() => beginExpected(listener)}>Mark expected…</button><button className="secondary-action" type="button" disabled={busy} onClick={() => beginExpected(listener, 8)}>Expect temporarily…</button></div>}
		  </article>;
		})}
	  </div>}
	  {view === "active" && <div className="table-wrap compact-table"><table><thead><tr><th>Protocol</th><th>Local endpoint</th><th>Remote endpoint</th><th>Owner</th><th>State</th></tr></thead><tbody>{active.length === 0 ? <tr><td colSpan={5} className="empty-state">No established TCP connections were returned.</td></tr> : active.map((connection) => <tr key={`${connection.protocol}-${connection.processId}-${connection.localAddress}-${connection.localPort}-${connection.remoteAddress}-${connection.remotePort}`}><td className="protocol">{connection.protocol}</td><td className="endpoint">{endpoint(connection.localAddress, connection.localPort)}</td><td className="endpoint">{endpoint(connection.remoteAddress, connection.remotePort)}</td><td>{connection.processName || connection.systemdUnit || "Not attributed"}{connection.processId > 0 ? ` · PID ${connection.processId}` : ""}</td><td className="state">{connection.state}</td></tr>)}</tbody></table></div>}
	  <details className="expectation-registry">
		<summary>Manage expected-service registry ({expectedServices.length})</summary>
		<p>Expectations are local HAVEN metadata. They do not open ports or change firewall rules.</p>
		<form className="expectation-form" onSubmit={addManual}><label><span>Friendly label</span><input maxLength={80} value={manualLabel} onChange={(event) => setManualLabel(event.target.value)} placeholder="SSH" /></label><label><span>Protocol</span><select value={manualProtocol} onChange={(event) => setManualProtocol(event.target.value as "TCP" | "UDP")}><option>TCP</option><option>UDP</option></select></label><label><span>Port</span><input type="number" min={1} max={65535} value={manualPort} onChange={(event) => setManualPort(event.target.value)} placeholder="22" /></label><label><span>Expected bind</span><select value={manualScope} onChange={(event) => setManualScope(event.target.value as BindScope)}><option value="any">Any bind</option><option value="local">This host only</option><option value="private">Private address</option><option value="wildcard">All interfaces</option><option value="specific">Specific address</option></select></label><button type="submit" disabled={busy || !manualLabel.trim() || !manualPort}>Add expectation</button></form>
		{expectedServices.length > 0 && <ul className="registry-list">{expectedServices.map((service) => <li key={service.id}><span><strong>{service.label}</strong><small>{service.protocol} {service.portEnd > service.port ? `${service.port}–${service.portEnd}` : service.port} · {bindScopeLabel(service.bindScope)}{service.processNames?.length ? ` · processes: ${service.processNames.join(", ")}` : ""}{service.workloadNames?.length ? ` · workloads: ${service.workloadNames.join(", ")}` : ""}{service.systemdUnits?.length ? ` · services: ${service.systemdUnits.join(", ")}` : ""}{!expectedServiceOwnerConstrained(service) ? " · owner not constrained" : ""}{service.expiresAt ? ` · temporary, expires ${formatDate(service.expiresAt)}` : ""}</small></span><button type="button" disabled={busy} onClick={() => removeExpectation(service)}>Remove</button></li>)}</ul>}
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
  const ordered = actionableFindings(findings, reviews).sort((left, right) => ({ high: 0, medium: 1, low: 2 }[left.severity] - { high: 0, medium: 1, low: 2 }[right.severity]));
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
      <div className="topbar-actions"><span className="local-pill" aria-label="Hub ready"><span className="local-dot" /><span className="local-label">Hub ready</span></span><button className="signout-button" type="button" onClick={signOut} aria-label="Lock HAVEN" title="Lock HAVEN"><LockIcon size={15} /><span className="topbar-action-label">Lock</span></button></div>
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
    <footer><span>HAVEN {runtime?.version || "development"} · Agent enrollment</span><span>Observe continuously. Act deliberately.</span></footer>
  </>;
}

function ActivityPanel({ events, alerts }: { events: SecurityEvent[]; alerts: HavenAlert[] }) {
  const recent = useMemo(() => visibleFindingLifecycles(events, alerts).slice(0, 12), [alerts, events]);
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

interface ApplicationProps {
	snapshot: SecuritySnapshot;
	devices: DeviceRecord[];
	networkDevices: NetworkDeviceObservation[];
	appliances: ManagedApplianceStatus[];
	events: SecurityEvent[];
	networkEvents: SecurityEvent[];
	alerts: HavenAlert[];
	runtime: RuntimeStatus | null;
	notificationStatus: PushNotificationStatus | null;
	selectedDevice: DeviceRecord | null;
	selectDevice: (id: string) => void;
	refresh: () => void;
	refreshing: boolean;
	error: string | null;
	demoMode: boolean;
	alertsEnabled: boolean;
	alertsSupported: boolean;
	enableAlerts: (label?: string) => void;
	disableAlerts: () => void;
	reviews: FindingReview[];
	expectedServices: ExpectedService[];
	listenerObservations: ObservedListener[];
	audit: AuditEvent[];
	actions: SecurityAction[];
	passkeys: PasskeyInfo[];
	accountProfiles: AccountProfile[];
	accountUnlocked: boolean;
	desktopInstallStatus: DesktopInstallStatus;
	installDesktopApp: () => Promise<void>;
	reviewFinding: (finding: SecurityFinding, state: FindingReviewState) => void;
	saveServiceExpectation: (service: ExpectedServiceInput) => void;
	saveServiceExpectations: (services: ExpectedServiceInput[]) => void;
	removeServiceExpectation: (service: ExpectedService) => void;
	runAction: (kind: SecurityActionKind) => void;
	addOwnerPasskey: () => void;
	removeOwnerPasskey: (passkey: PasskeyInfo) => void;
	saveAccount: (profile: AccountProfileInput) => Promise<boolean>;
	removeAccount: (profile: AccountProfile) => void;
	unlockAccounts: () => void;
	lockAccounts: () => void;
	actionBusy: boolean;
	signOut: () => void;
	route: AppRoute;
	navigate: (route: AppRoute) => void;
}

function Application({ snapshot, devices, networkDevices, appliances, events, networkEvents, alerts, runtime, notificationStatus, selectedDevice, selectDevice, refresh, refreshing, error, demoMode, alertsEnabled, alertsSupported, enableAlerts, disableAlerts, reviews, expectedServices, listenerObservations, audit, actions, passkeys, accountProfiles, accountUnlocked, desktopInstallStatus, installDesktopApp, reviewFinding, saveServiceExpectation, saveServiceExpectations, removeServiceExpectation, runAction, addOwnerPasskey, removeOwnerPasskey, saveAccount, removeAccount, unlockAccounts, lockAccounts, actionBusy, signOut, route, navigate }: ApplicationProps) {
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
	const selectedDeviceId = selectedDevice?.id || snapshot.device.deviceId || "";
	const deviceSection: DeviceSection = route.page === "device" ? route.section || "overview" : "overview";
	const browserPageTitle = route.page === "device"
		? selectedDevice?.displayName || snapshot.device.hostName
		: route.page === "overview" ? "Overview" : `${route.page.charAt(0).toUpperCase()}${route.page.slice(1)}`;
	useEffect(() => {
		document.title = isStandaloneApp() ? browserPageTitle : `${browserPageTitle} — HAVEN`;
	}, [browserPageTitle]);
	const openDevice = (deviceId: string) => {
		navigate({ page: "device", deviceId, section: "overview" });
		selectDevice(deviceId);
	};
	const openOverview = (event: React.MouseEvent<HTMLAnchorElement>) => {
		if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
		event.preventDefault();
		navigate({ page: "overview" });
	};

	const deviceSummary = <>
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
	</>;

	let page: React.ReactNode;
	if (route.page === "overview") {
		page = <><PageIntro eyebrow="PERSONAL SECURITY OBSERVATORY" title="Home security overview">Current alerts, coverage, and meaningful changes across trusted devices and explicitly configured appliances.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} demoMode={demoMode} view="overview" /></>;
	} else if (route.page === "devices") {
		page = <><PageIntro eyebrow="TRUSTED INVENTORY" title="Devices">Choose an enrolled endpoint to inspect its posture and verify that its reporter is current, compatible, and collecting the expected evidence.</PageIntro><FleetPanel devices={devices} runtime={runtime} /><DeviceInventory devices={devices} selectedId={selectedDeviceId} select={openDevice} demoMode={demoMode} /></>;
	} else if (route.page === "network") {
		page = <><PageIntro eyebrow="LIVE OBSERVATION" title="Network">Current device coverage and relationship summaries without packet capture or retained remote endpoints.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} demoMode={demoMode} view="network" /></>;
	} else if (route.page === "appliances") {
		page = <><PageIntro eyebrow="READ-ONLY HEALTH" title="Appliances">Bounded reachability and health evidence from devices explicitly configured by the owner.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} demoMode={demoMode} view="appliances" /></>;
	} else if (route.page === "accounts") {
		page = <><PageIntro eyebrow="IDENTITY AND RECOVERY" title="Accounts">An informal, encrypted notebook for the security measures you have confirmed directly at each provider.</PageIntro><AccountNotebook profiles={accountProfiles} demoMode={demoMode} unlocked={accountUnlocked} busy={actionBusy} unlock={unlockAccounts} lock={lockAccounts} save={saveAccount} remove={removeAccount} /></>;
	} else if (route.page === "activity") {
		page = <><PageIntro eyebrow="EVENTS AND DECISIONS" title="Activity">Finding transitions, deliberate control requests, and privacy-bounded owner decisions.</PageIntro><ActivityPanel events={networkEvents} alerts={alerts} />{!demoMode && <ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={runAction} busy={actionBusy} />}</>;
	} else if (route.page === "settings") {
		page = <><PageIntro eyebrow="OWNER ACCESS" title="Settings">Manage installation, this browser's alert destination, and the passkeys that protect HAVEN.</PageIntro><DesktopInstallPanel status={desktopInstallStatus} install={installDesktopApp} />{!demoMode ? <><NotificationPanel status={notificationStatus} supported={alertsSupported} enabled={alertsEnabled} busy={actionBusy} enable={enableAlerts} disable={disableAlerts} /><PasskeyPanel passkeys={passkeys} add={addOwnerPasskey} remove={removeOwnerPasskey} busy={actionBusy} /></> : <p className="demo-banner" role="status">Authentication and notification settings are unavailable in synthetic demo mode.</p>}<section className="panel about-panel" aria-labelledby="about-title"><PanelHeading eyebrow="APPLICATION" title="About HAVEN" id="about-title" icon={<HavenIcon />} accent="green">Private, explainable security visibility</PanelHeading><dl className="details-grid"><div><dt>Version</dt><dd>{runtime?.version || "development"}</dd></div><div><dt>Revision</dt><dd>{runtime?.revision && runtime.revision !== "development" ? runtime.revision.slice(0, 12) : "development"}</dd></div><div><dt>Collection</dt><dd>Read-only by default</dd></div><div><dt>Storage</dt><dd>Private SQLite hub</dd></div></dl></section></>;
	} else {
		page = <>
			<div className="device-page-heading"><a href="/devices" onClick={(event) => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) { event.preventDefault(); navigate({ page: "devices" }); } }}>← All devices</a><DeviceNavigation deviceId={selectedDeviceId} current={deviceSection} navigate={navigate} /></div>
			{deviceSummary}
			{deviceSection === "overview" && <>{selectedDevice && <AgentEvidencePanel device={selectedDevice} runtime={runtime} />}<FindingsPanel findings={snapshot.findings || []} checks={snapshot.baselineChecks || []} reviews={reviews} review={reviewFinding} /></>}
			{deviceSection === "posture" && <>{(snapshot.baselineChecks || []).length > 0 && <BaselinePanel checks={snapshot.baselineChecks || []} collectedAt={snapshot.collectedAt} platform={isLinux ? "Linux" : "Windows"} />}{snapshot.notices.length > 0 && <section className="panel notices-panel" aria-labelledby="notices-title"><PanelHeading eyebrow="COLLECTION NOTES" title="Some signals could not be verified" id="notices-title" icon={<AlertIcon />} accent="amber">A collection limitation is not automatically a security problem</PanelHeading><ul className="notices-list">{snapshot.notices.map((notice, index) => <li className="notice" key={`${notice.source}-${index}`}><strong>{notice.source}: </strong>{notice.message}</li>)}</ul></section>}{isLinux && snapshot.linuxBaseline ? <LinuxPanel baseline={snapshot.linuxBaseline} /> : <DefenderPanel defender={snapshot.defender} />}<FirewallPanel profiles={snapshot.firewallProfiles} isLinux={isLinux} /></>}
			{deviceSection === "browsers" && <BrowserSecurityPanel status={snapshot.browserSecurity ?? null} />}
			{deviceSection === "services" && <>{isLinux && <WorkloadsPanel inventory={snapshot.linuxBaseline?.workloads ?? null} />}<ConnectionsPanel deviceId={selectedDeviceId} operatingSystem={snapshot.device.operatingSystem} connections={snapshot.connections} workloads={workloadInventory} expectedServices={expectedServices} observations={listenerObservations} saveExpectation={saveServiceExpectation} saveExpectations={saveServiceExpectations} removeExpectation={removeServiceExpectation} busy={actionBusy} /></>}
			{deviceSection === "history" && <ActivityPanel events={events} alerts={alerts} />}
		</>;
	}

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/" aria-label="HAVEN home" onClick={openOverview}><span className="brand-mark"><HavenIcon /></span><span><strong>HAVEN</strong><small>Personal Security Observatory</small></span></a>
        <AppNavigation current={route.page} navigate={navigate} />
        <div className="topbar-actions">
          <span className={`local-pill ${demoMode ? "demo-pill" : ""}`} aria-label={demoMode ? "Synthetic demo" : runtime?.localCollection ? "Local monitor" : "Agent hub"}><span className="local-dot" /><span className="local-label">{demoMode ? "Synthetic demo" : runtime?.localCollection ? "Local monitor" : "Agent hub"}</span></span>
          {!demoMode && alertsSupported && <button className={`desktop-alert-button ${alertsEnabled ? "enabled" : ""}`} type="button" onClick={alertsEnabled ? disableAlerts : () => enableAlerts()} disabled={actionBusy} aria-label={alertsEnabled ? "Disable background alerts on this browser" : "Enable background alerts on this browser"} title={alertsEnabled ? "Disable background alerts" : "Enable background alerts"}><BellIcon size={15} /><span className="topbar-action-label">{alertsEnabled ? "Push alerts on" : "Enable push"}</span></button>}
          {!demoMode && <button className="refresh-button" type="button" onClick={refresh} disabled={refreshing} aria-label={refreshing ? (runtime?.localCollection ? "Collecting security posture" : "Refreshing HAVEN view") : runtime?.localCollection ? "Collect security posture now" : "Refresh HAVEN view"} title={runtime?.localCollection ? "Collect security posture now" : "Refresh HAVEN view"}><RefreshIcon size={15} /><span className="topbar-action-label">{refreshing ? (runtime?.localCollection ? "Collecting…" : "Refreshing…") : runtime?.localCollection ? "Collect now" : "Refresh view"}</span></button>}
          {!demoMode && <button className="signout-button" type="button" onClick={signOut} aria-label="Lock HAVEN" title="Lock HAVEN"><LockIcon size={15} /><span className="topbar-action-label">Lock</span></button>}
        </div>
      </header>
      <main>
        {demoMode && <p className="demo-banner" role="status"><strong>Synthetic demo mode.</strong> Every device and observation on this page is invented. HAVEN is not showing or collecting data from this computer.</p>}
        {error && <p className="inline-error" role="alert">{error}</p>}
        {page}
      </main>
	  <footer><span>HAVEN {runtime?.version || "development"} · Navigable console</span><span>Observe continuously. Act deliberately.</span></footer>
    </>
  );
}

export function App() {
  const { route, navigate } = useAppRoute();
  const desktopInstall = useDesktopInstall();
  const [authentication, setAuthentication] = useState<AuthStatus | null>(null);
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [networkDevices, setNetworkDevices] = useState<NetworkDeviceObservation[]>([]);
  const [appliances, setAppliances] = useState<ManagedApplianceStatus[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [currentAlerts, setCurrentAlerts] = useState<HavenAlert[]>([]);
  const [reviews, setReviews] = useState<FindingReview[]>([]);
	const [expectedServices, setExpectedServices] = useState<ExpectedService[]>([]);
	const [listenerObservations, setListenerObservations] = useState<ObservedListener[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [actions, setActions] = useState<SecurityAction[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [accountProfiles, setAccountProfiles] = useState<AccountProfile[]>([]);
  const [accountAccess, setAccountAccess] = useState<AccountAccessGrant | null>(null);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
  const [notificationStatus, setNotificationStatus] = useState<PushNotificationStatus | null>(null);
  const [selectedId, setSelectedId] = useState(route.deviceId || "");
  const [demoMode, setDemoMode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [inventoryLoaded, setInventoryLoaded] = useState(false);
  const selectedIdRef = useRef(route.deviceId || "");
  const accountAccessRef = useRef<AccountAccessGrant | null>(null);
  const accountLastActivityRef = useRef(Date.now());
  const accountLastTouchRef = useRef(0);
  const alertsSupported = supportsBackgroundPush();
  const [alertsEnabled, setAlertsEnabled] = useState(false);

  const authenticate = useCallback(async (bootstrapCode?: string, label?: string) => {
    if (bootstrapCode === undefined) await loginWithPasskey();
    else await registerPasskey(bootstrapCode, label || "This device");
    setAuthentication(await getAuthStatus());
    setSnapshot(null);
  }, []);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
		const [initialInventory, runtimeStatus, activity, activeAlerts, pushStatus, managedAppliances] = await Promise.all([listDevices(signal), getRuntimeStatus(signal), listEvents(undefined, signal), listAlerts(signal), getNotificationStatus(signal), listManagedAppliances(signal)]);
		let accounts: AccountProfile[] | null = null;
		try {
			if (runtimeStatus.demoMode) accounts = await listAccountProfiles("", signal);
			else if (accountAccessRef.current) accounts = await listAccountProfiles(accountAccessRef.current.token, signal);
		} catch (reason) {
			if (!(reason instanceof HavenAPIError) || reason.status !== 403) throw reason;
			accountAccessRef.current = null;
			setAccountAccess(null);
			accounts = [];
		}
      let inventory = initialInventory;
      let observed: { id: string; snapshot: SecuritySnapshot } | null;
      if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
        const collected = await collectSnapshot(signal);
        inventory = await listDevices(signal);
        observed = { id: collected.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: collected };
      } else {
        observed = await latestEnrolledObservation(inventory, selectedIdRef.current, signal);
      }
      const networkObservations = await loadNetworkObservations(inventory, runtimeStatus.demoMode, signal);
      setSnapshot(observed?.snapshot || null);
      setDevices(inventory);
      setNetworkDevices(networkObservations);
      setAppliances(managedAppliances);
      setEvents(activity);
      setCurrentAlerts(activeAlerts);
      setRuntime(runtimeStatus);
      setNotificationStatus(pushStatus);
		if (accounts !== null) setAccountProfiles(accounts);
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

	const refreshView = useCallback(async () => {
		try {
			await refresh();
			if (!demoMode && selectedIdRef.current) await loadControls(selectedIdRef.current);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "HAVEN could not refresh its control metadata.");
		}
	}, [demoMode, loadControls, refresh]);

	const clearAccountAccess = useCallback(() => {
		accountAccessRef.current = null;
		setAccountAccess(null);
		setAccountProfiles([]);
	}, []);

	const unlockAccounts = useCallback(async () => {
		setActionBusy(true);
		try {
			const access = await unlockAccountNotebook();
			const profiles = await listAccountProfiles(access.token);
			accountAccessRef.current = access;
			accountLastActivityRef.current = Date.now();
			accountLastTouchRef.current = Date.now();
			setAccountAccess(access);
			setAccountProfiles(profiles);
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account notebook could not be unlocked.");
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

	const lockAccounts = useCallback(async () => {
		const token = accountAccessRef.current?.token || "";
		clearAccountAccess();
		if (token) {
			try { await lockAccountNotebook(token); } catch { /* The local view is already locked; the server grant will expire. */ }
		}
	}, [clearAccountAccess]);

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
      await Promise.all([loadControls(selectedId), listAlerts().then(setCurrentAlerts)]);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The finding review could not be saved.");
    }
  }, [loadControls, selectedId]);

	const saveServiceExpectation = useCallback(async (service: ExpectedServiceInput) => {
		setActionBusy(true);
		try {
			await saveExpectedService(service);
			const saved = await listExpectedServices(service.deviceId);
			setExpectedServices(saved);
			setNetworkDevices((current) => current.map((entry) => entry.device.id === service.deviceId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
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
			setNetworkDevices((current) => current.map((entry) => entry.device.id === selectedId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
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
			const saved = await listExpectedServices(service.deviceId);
			setExpectedServices(saved);
			setNetworkDevices((current) => current.map((entry) => entry.device.id === service.deviceId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
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

	const saveAccount = useCallback(async (profile: AccountProfileInput) => {
		setActionBusy(true);
		try {
			const token = accountAccessRef.current?.token;
			if (!token) throw new Error("Unlock the account notebook before editing it.");
			await saveAccountProfile(profile, token);
			setAccountProfiles(await listAccountProfiles(token));
			setAudit(await listAuditEvents());
			setError(null);
			return true;
		} catch (reason) {
			if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account profile could not be saved.");
			return false;
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

	const removeAccount = useCallback(async (profile: AccountProfile) => {
		if (!window.confirm(`Remove “${profile.provider} · ${profile.label}” from HAVEN? This deletes the encrypted notebook entry; it does not change the provider account.`)) return;
		setActionBusy(true);
		try {
			const token = accountAccessRef.current?.token;
			if (!token) throw new Error("Unlock the account notebook before editing it.");
			await removeAccountProfile(profile.id, token);
			setAccountProfiles(await listAccountProfiles(token));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account profile could not be removed.");
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

  const signOut = useCallback(async () => {
    try { await logout(); } finally {
      setAuthentication((current) => current ? { ...current, authenticated: false } : current);
      setSnapshot(null);
      setDevices([]);
      setNetworkDevices([]);
      setAppliances([]);
      setEvents([]);
      setCurrentAlerts([]);
      setReviews([]);
	  setExpectedServices([]);
	  setListenerObservations([]);
      setAudit([]);
      setActions([]);
      setPasskeys([]);
		setAccountProfiles([]);
		accountAccessRef.current = null;
		setAccountAccess(null);
      setNotificationStatus(null);
      setAlertsEnabled(false);
      setInventoryLoaded(false);
    }
  }, []);

  const enableAlerts = useCallback(async (requestedLabel = "This browser") => {
    if (!alertsSupported) {
      setError("This browser does not support service-worker background notifications.");
      return;
    }
    if (!notificationStatus?.available || !notificationStatus.vapidPublicKey) {
      setError("The HAVEN hub has not advertised background-notification support.");
      return;
    }
    setActionBusy(true);
    try {
      const label = normalizePushDestinationLabel(requestedLabel);
      const permission = await window.Notification.requestPermission();
      if (permission !== "granted") throw new Error("Background notifications remain blocked. Change this site's notification permission in the browser to enable them.");
      const registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
      await navigator.serviceWorker.ready;
      const existing = await registration.pushManager.getSubscription();
      const subscription = existing || await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: decodeApplicationServerKey(notificationStatus.vapidPublicKey) });
      await registerPushDestination(serializePushSubscription(subscription), label);
      setNotificationStatus(await getNotificationStatus());
      setAlertsEnabled(true);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "This browser could not be enabled for background alerts.");
    } finally {
      setActionBusy(false);
    }
  }, [alertsSupported, notificationStatus?.available, notificationStatus?.vapidPublicKey]);

  const disableAlerts = useCallback(async () => {
    if (!alertsSupported) return;
    setActionBusy(true);
    try {
      const registration = await navigator.serviceWorker.getRegistration("/");
      const subscription = await registration?.pushManager.getSubscription();
      if (subscription) {
        await removePushDestination(subscription.endpoint);
        await subscription.unsubscribe();
      }
      setNotificationStatus(await getNotificationStatus());
      setAlertsEnabled(false);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Background alerts could not be disabled on this browser.");
    } finally {
      setActionBusy(false);
    }
  }, [alertsSupported]);

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
    if (!authentication?.authenticated || !alertsSupported || !notificationStatus?.available) return;
    let active = true;
    void navigator.serviceWorker.getRegistration("/").then((registration) => registration?.pushManager.getSubscription()).then((subscription) => {
      if (active) setAlertsEnabled(window.Notification.permission === "granted" && Boolean(subscription));
    }).catch(() => { if (active) setAlertsEnabled(false); });
    return () => { active = false; };
  }, [alertsSupported, authentication?.authenticated, notificationStatus?.available]);

	useEffect(() => {
		if (!accountAccess || demoMode) return;
		const token = accountAccess.token;
		const recordActivity = () => {
			const now = Date.now();
			const current = accountAccessRef.current;
			if (!current || now >= new Date(current.expiresAt).getTime() || now >= new Date(current.absoluteExpiresAt).getTime()) {
				void lockAccounts();
				return;
			}
			accountLastActivityRef.current = now;
		};
		const checkAccess = async () => {
			if (accountAccessRef.current?.token !== token) return;
			const now = Date.now();
			if (now >= new Date(accountAccessRef.current.expiresAt).getTime() || now >= new Date(accountAccess.absoluteExpiresAt).getTime() || now-accountLastActivityRef.current >= accountAccess.idleTimeoutSeconds*1000) {
				await lockAccounts();
				return;
			}
			if (document.visibilityState !== "visible" || now-accountLastActivityRef.current > 5*60_000 || now-accountLastTouchRef.current < 4*60_000) return;
			accountLastTouchRef.current = now;
			try {
				const refreshed = await touchAccountNotebook(token);
				if (accountAccessRef.current?.token === token) {
					accountAccessRef.current = refreshed;
					setAccountAccess(refreshed);
				}
			} catch (reason) {
				if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
				else setError(reason instanceof Error ? reason.message : "Private account access could not be refreshed.");
			}
		};
		window.addEventListener("pointerdown", recordActivity, { passive: true });
		window.addEventListener("keydown", recordActivity);
		window.addEventListener("touchstart", recordActivity, { passive: true });
		window.addEventListener("focus", checkAccess);
		document.addEventListener("visibilitychange", checkAccess);
		const interval = window.setInterval(() => void checkAccess(), 30_000);
		return () => {
			window.removeEventListener("pointerdown", recordActivity);
			window.removeEventListener("keydown", recordActivity);
			window.removeEventListener("touchstart", recordActivity);
			window.removeEventListener("focus", checkAccess);
			document.removeEventListener("visibilitychange", checkAccess);
			window.clearInterval(interval);
		};
	}, [accountAccess?.absoluteExpiresAt, accountAccess?.idleTimeoutSeconds, accountAccess?.token, clearAccountAccess, demoMode, lockAccounts]);

  useEffect(() => {
    if (!authentication?.authenticated || !inventoryLoaded || demoMode) return;
    const controller = new AbortController();
    void loadControls(selectedId, controller.signal).catch((reason) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not be loaded.");
    });
    return () => controller.abort();
	}, [authentication?.authenticated, demoMode, inventoryLoaded, loadControls, selectedId]);

  useEffect(() => {
    if (!authentication?.authenticated || !inventoryLoaded || route.page !== "device" || !route.deviceId || route.deviceId === selectedIdRef.current) return;
    void selectDevice(route.deviceId);
  }, [authentication?.authenticated, inventoryLoaded, route.deviceId, route.page, selectDevice]);

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
		const [inventory, runtimeStatus, activity, activeAlerts, pushStatus, managedAppliances] = await Promise.all([listDevices(controller.signal), getRuntimeStatus(controller.signal), listEvents(undefined, controller.signal), listAlerts(controller.signal), getNotificationStatus(controller.signal), listManagedAppliances(controller.signal)]);
        let observed: { id: string; snapshot: SecuritySnapshot } | null;
        if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
          const latest = await getLatestSnapshot(controller.signal);
          observed = { id: latest.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: latest };
        } else {
          observed = await latestEnrolledObservation(inventory, selectedIdRef.current, controller.signal);
        }
        const networkObservations = await loadNetworkObservations(inventory, runtimeStatus.demoMode, controller.signal);
        setDevices(inventory);
        setNetworkDevices(networkObservations);
        setAppliances(managedAppliances);
        setEvents(activity);
        setCurrentAlerts(activeAlerts);
        setRuntime(runtimeStatus);
        setNotificationStatus(pushStatus);
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
	return <Application snapshot={snapshot} devices={devices} networkDevices={networkDevices} appliances={appliances} events={selectedEvents} networkEvents={events} alerts={currentAlerts} runtime={runtime} notificationStatus={notificationStatus} selectedDevice={selectedDevice} selectDevice={(id) => void selectDevice(id)} refresh={() => void refreshView()} refreshing={refreshing} error={error} demoMode={demoMode} alertsEnabled={alertsEnabled} alertsSupported={alertsSupported} enableAlerts={(label) => void enableAlerts(label)} disableAlerts={() => void disableAlerts()} reviews={reviews} expectedServices={expectedServices} listenerObservations={listenerObservations} audit={audit} actions={actions} passkeys={passkeys} accountProfiles={accountProfiles} accountUnlocked={demoMode || accountAccess !== null} desktopInstallStatus={desktopInstall.status} installDesktopApp={async () => { try { await desktopInstall.install(); setError(null); } catch (reason) { setError(reason instanceof Error ? reason.message : "HAVEN could not open the browser installation prompt."); } }} reviewFinding={(finding, state) => void reviewFinding(finding, state)} saveServiceExpectation={(service) => void saveServiceExpectation(service)} saveServiceExpectations={(services) => void saveServiceBaseline(services)} removeServiceExpectation={(service) => void removeServiceExpectation(service)} runAction={(kind) => void runAction(kind)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} saveAccount={saveAccount} removeAccount={(profile) => void removeAccount(profile)} unlockAccounts={() => void unlockAccounts()} lockAccounts={() => void lockAccounts()} actionBusy={actionBusy} signOut={() => void signOut()} route={route} navigate={navigate} />;
}
