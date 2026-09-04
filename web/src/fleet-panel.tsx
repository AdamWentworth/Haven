import { ActivityIcon, CheckIcon, ChipIcon, DevicesIcon } from "./icons";
import { capabilityLabel, fleetPresentation, fleetSummary } from "./fleet";
import { formatDate, formatRelativeTime } from "./format";
import type { DeviceRecord, RuntimeStatus } from "./types";
import { StatusChip } from "./ui";

export function FleetPanel({ devices, runtime }: { devices: DeviceRecord[]; runtime: RuntimeStatus | null }) {
	const summary = fleetSummary(devices);
	const synthetic = devices.some((device) => device.trustState === "synthetic");
	return <section className="panel fleet-panel" aria-labelledby="fleet-title">
		<div className="section-heading"><div className="heading-identity"><span className="section-icon cyan"><DevicesIcon /></span><div><p className="eyebrow">FLEET OPERATIONS</p><h2 id="fleet-title">Agent lifecycle</h2></div></div><p>Build drift is maintenance evidence—not a threat finding.</p></div>
		<div className="fleet-metrics">
			<div><span className="fleet-metric-icon green"><ActivityIcon /></span><strong>{summary.reporting}/{summary.total}</strong><small>reporting now</small></div>
			<div><span className="fleet-metric-icon blue"><CheckIcon /></span><strong>{summary.verified}/{summary.total}</strong><small>exact build verified</small></div>
			<div><span className="fleet-metric-icon amber"><ChipIcon /></span><strong>{summary.maintenance}</strong><small>maintenance reviews</small></div>
			<div><span className="fleet-metric-icon cyan"><DevicesIcon /></span><strong>{summary.limited}</strong><small>with collection notes</small></div>
		</div>
		<p className="fleet-explainer">{synthetic ? "Synthetic fixtures exercise the fleet layout but deliberately make no claim about installed agent builds." : <>Agents authenticate with their existing device certificate and declare only bounded version, platform, installation kind, capability, and collection-limitation facts. The hub compares those facts with {runtime ? `HAVEN ${runtime.version}` : "its own build"}; it does not remotely execute updates.</>}</p>
	</section>;
}

export function AgentEvidencePanel({ device, runtime }: { device: DeviceRecord; runtime: RuntimeStatus | null }) {
	const presentation = fleetPresentation(device);
	const agent = device.agent;
	const synthetic = device.trustState === "synthetic";
	const local = device.trustState === "local";
	return <section className="panel agent-evidence-panel" aria-labelledby="agent-evidence-title">
		<div className="section-heading"><div className="heading-identity"><span className="section-icon blue"><ChipIcon /></span><div><p className="eyebrow">{synthetic ? "SYNTHETIC EVIDENCE" : local ? "LOCAL COLLECTOR" : "AUTHENTICATED REPORTER"}</p><h2 id="agent-evidence-title">Agent evidence</h2></div></div><StatusChip label={presentation.label} tone={presentation.tone} /></div>
		<p className="fleet-explainer">{presentation.detail}. Reporter maintenance remains separate from endpoint posture and security alerts.</p>
		<dl className="details-grid agent-details">
			<div><dt>Agent release</dt><dd>{agent ? agent.version : synthetic ? "Synthetic fixture" : local ? "Hub-integrated" : "Pre-0.14"}</dd></div>
			<div><dt>Agent revision</dt><dd className="monospace-value">{agent ? shortRevision(agent.revision) : "Not reported"}</dd></div>
			<div><dt>Hub release</dt><dd>{runtime?.version || "Unavailable"}</dd></div>
			<div><dt>Installation</dt><dd>{agent ? installationLabel(agent.installation) : "Not reported"}</dd></div>
			<div><dt>Protocol schema</dt><dd>{agent ? agent.schemaVersion : synthetic || local ? "Not applicable" : "Compatible legacy"}</dd></div>
			<div><dt>Last contact</dt><dd title={device.lastSeenAt ? formatDate(device.lastSeenAt) : undefined}>{formatRelativeTime(device.lastSeenAt)}</dd></div>
		</dl>
		<div className="capability-section"><h3>Evidence capabilities</h3>{agent?.capabilities.length ? <ul className="capability-list">{agent.capabilities.map((capability) => <li key={capability}>{capabilityLabel(capability)}</li>)}</ul> : <p>{synthetic ? "Synthetic fixtures do not assert reporter capabilities." : local ? "Local development collection is part of the hub process." : "No capability manifest was included by this reporter."}</p>}<small>{agent ? `${agent.collectionNotices} collection notice${agent.collectionNotices === 1 ? "" : "s"} accompanied the latest report.` : synthetic || local ? "No endpoint maintenance action applies." : "Update this endpoint agent to receive build and capability evidence."}</small></div>
	</section>;
}

function shortRevision(revision: string) {
	return revision === "development" ? revision : revision.slice(0, 12);
}

function installationLabel(value: string) {
	const labels: Record<string, string> = { "windows-task": "Windows scheduled task", "systemd-user": "systemd user timer", interactive: "Interactive/manual" };
	return labels[value] || value;
}
