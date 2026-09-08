import { useCallback, useEffect, useMemo, useState } from "react";
import { suggestedBaseline } from "./baseline";
import { actionableFindings, visibleFindingLifecycles } from "./findings";
import { booleanValue, formatBytes, formatDate, formatPortBinding, formatRelativeTime, formatTimeRemaining, policyValue } from "./format";
import { ActivityIcon, AlertIcon, CheckIcon, ChipIcon, DefenderIcon, FirewallIcon, HelpIcon, LockIcon, NetworkIcon, RemoteAccessIcon, ServerIcon, UpdateIcon, UsersIcon, WorkloadIcon } from "./icons";
import { bindScopeLabel, endpoint, endpointScope, expectedServiceMatches, expectedServiceOwnerConstrained, logicalListeners, workloadAttribution, type LogicalListener } from "./network";
import { PanelHeading } from "./panel-heading";
import type {
  BaselineCheck,
  BindScope,
  ContainerWorkload,
  DefenderStatus,
  ExpectedService,
  ExpectedServiceInput,
  FindingReview,
  FindingReviewState,
  FirewallProfileStatus,
  HavenAlert,
  LinuxBaseline,
  NetworkConnection,
  ObservedListener,
  SecurityEvent,
  SecurityFinding,
  WorkloadInventory,
} from "./types";
import { StatusChip, type Accent, type Tone } from "./ui";

export function SummaryCard({
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

export function DefenderPanel({ defender }: { defender: DefenderStatus | null }) {
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

export function LinuxPanel({ baseline }: { baseline: LinuxBaseline }) {
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

export function WorkloadsPanel({ inventory }: { inventory: WorkloadInventory | null }) {
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



export function FirewallPanel({ profiles, isLinux }: { profiles: FirewallProfileStatus[]; isLinux: boolean }) {
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

export function ConnectionsPanel({ deviceId, operatingSystem, connections, workloads, expectedServices, observations, saveExpectation, saveExpectations, removeExpectation, busy }: { deviceId: string; operatingSystem: string; connections: NetworkConnection[]; workloads: WorkloadInventory | null; expectedServices: ExpectedService[]; observations: ObservedListener[]; saveExpectation: (service: ExpectedServiceInput) => void; saveExpectations: (services: ExpectedServiceInput[]) => void; removeExpectation: (service: ExpectedService) => void; busy: boolean }) {
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

export function FindingsPanel({ findings, checks, reviews, review }: { findings: SecurityFinding[]; checks: BaselineCheck[]; reviews: FindingReview[]; review: (finding: SecurityFinding, state: FindingReviewState) => void }) {
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


export function ActivityPanel({ events, alerts }: { events: SecurityEvent[]; alerts: HavenAlert[] }) {
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

export function BaselinePanel({ checks, collectedAt, platform }: { checks: BaselineCheck[]; collectedAt: string; platform: string }) {
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
