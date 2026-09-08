import { useMemo } from "react";
import { componentHealthTone, coverageTone, healthStatusLabel, managedHealthTone, storageSetDetail, storageSetLabel } from "./appliance-health";
import { visibleFindingLifecycles } from "./findings";
import { formatBytes, formatDate, formatDuration, formatRelativeTime } from "./format";
import { AlertIcon, CheckIcon, LaptopIcon, MonitorIcon, NetworkIcon, ServerIcon } from "./icons";
import { isPrivateNetworkAddress, liveNetworkRelationships, logicalListeners, expectedServiceMatches, networkServiceLabel, type NetworkDeviceObservation } from "./network";
import { PanelHeading } from "./panel-heading";
import type { HavenAlert, ManagedApplianceStatus, ManagedHealthStatus, SecurityEvent } from "./types";
import { StatusChip, type Tone } from "./ui";

function ApplianceHealthPanel({ health, runDeepCheck, busy }: { health: ManagedHealthStatus; runDeepCheck?: () => void; busy?: boolean }) {
	const coverage = [
		["Disks + SMART", health.coverage.disks],
		["Storage sets", health.coverage.raid],
		["Temperature", health.coverage.temperature],
		["Capacity", health.coverage.capacity],
		["Firmware", health.coverage.firmware],
	] as const;
	const systemTemperatures = health.temperatures.filter((temperature) => temperature.kind !== "disk");
	return <section className="appliance-health" aria-label="Read-only NAS health">
		<div className="appliance-health-heading"><div><strong>Storage health</strong><small>Latest health evidence checked {formatRelativeTime(health.lastCheckedAt)}</small></div><StatusChip label={healthStatusLabel(health.status)} tone={managedHealthTone(health.status)} /></div>
		{health.deepCheckAvailable && <div className="appliance-deep-check"><span><strong>Deep disk health</strong><small>{health.lastDeepCheckedAt ? `Last checked ${formatRelativeTime(health.lastDeepCheckedAt)}` : "Not checked yet"} · runs only when requested</small></span><button type="button" onClick={runDeepCheck} disabled={busy}>{busy ? "Checking…" : "Run deep check"}</button></div>}
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

export function NetworkOverview({ devices, appliances, events, alerts, selectedId, selectDevice, runApplianceDeepCheck, deepCheckBusy, demoMode, view }: { devices: NetworkDeviceObservation[]; appliances: ManagedApplianceStatus[]; events: SecurityEvent[]; alerts: HavenAlert[]; selectedId: string; selectDevice: (id: string) => void; runApplianceDeepCheck: (appliance: ManagedApplianceStatus) => void; deepCheckBusy: string | null; demoMode: boolean; view: NetworkView }) {
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
						{appliance.health && <ApplianceHealthPanel health={appliance.health} runDeepCheck={() => runApplianceDeepCheck(appliance)} busy={deepCheckBusy === appliance.id} />}
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
