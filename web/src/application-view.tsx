import { useEffect } from "react";
import { AccountNotebook } from "./account-notebook";
import { BrowserSecurityPanel } from "./browser-security";
import { DeviceInventory } from "./device-inventory";
import { ActivityPanel, BaselinePanel, ConnectionsPanel, DefenderPanel, FindingsPanel, FirewallPanel, LinuxPanel, SummaryCard, WorkloadsPanel } from "./device-panels";
import { type DesktopInstallStatus, isStandaloneApp } from "./desktop-install";
import { AgentEvidencePanel, FleetPanel } from "./fleet-panel";
import { formatDate, formatDuration, formatInterval, formatRelativeTime } from "./format";
import { ActivityIcon, AlertIcon, BellIcon, ChipIcon, DefenderIcon, FirewallIcon, HavenIcon, LaptopIcon, LockIcon, MonitorIcon, NetworkIcon, RefreshIcon, ServerIcon } from "./icons";
import { AppNavigation, DeviceNavigation, PageIntro } from "./navigation";
import { NetworkOverview } from "./network-overview";
import { PanelHeading } from "./panel-heading";
import { expectedServiceMatches, logicalListeners, type NetworkDeviceObservation } from "./network";
import type { AppRoute, DeviceSection } from "./routing";
import { ActionCenter, SystemRecoveryPage } from "./system-recovery";
import type {
  AccountProfile,
  AccountProfileInput,
  AuditEvent,
  BrowserSiteReview,
  BrowserSiteReviewInput,
  BrowserSiteReviewKey,
  DeviceRecord,
  ExpectedService,
  ExpectedServiceInput,
  FindingReview,
  FindingReviewState,
  HavenAlert,
  ManagedApplianceStatus,
  ObservedListener,
  PasskeyInfo,
  PushNotificationStatus,
  RuntimeStatus,
  SecurityAction,
  SecurityActionKind,
  SecurityEvent,
  SecurityFinding,
  SecuritySnapshot,
  SystemDiagnostics,
} from "./types";



interface ApplicationProps {
	snapshot: SecuritySnapshot;
	devices: DeviceRecord[];
	networkDevices: NetworkDeviceObservation[];
	appliances: ManagedApplianceStatus[];
	events: SecurityEvent[];
	networkEvents: SecurityEvent[];
	alerts: HavenAlert[];
	runtime: RuntimeStatus | null;
	diagnostics: SystemDiagnostics | null;
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
	browserSiteReviews: BrowserSiteReview[];
	expectedServices: ExpectedService[];
	listenerObservations: ObservedListener[];
	audit: AuditEvent[];
	actions: SecurityAction[];
	passkeys: PasskeyInfo[];
	accountProfiles: AccountProfile[];
	accountUnlocked: boolean;
	desktopInstallStatus: DesktopInstallStatus;
	desktopVersion: string | null;
	installDesktopApp: () => Promise<void>;
	reviewFinding: (finding: SecurityFinding, state: FindingReviewState) => void;
	classifyBrowserSite: (review: BrowserSiteReviewInput) => void;
	resetBrowserSite: (review: BrowserSiteReviewKey) => void;
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
	runApplianceDeepCheck: (appliance: ManagedApplianceStatus) => void;
	deepCheckBusy: string | null;
	actionBusy: boolean;
	signOut: () => void;
	route: AppRoute;
	navigate: (route: AppRoute) => void;
}

export function Application({ snapshot, devices, networkDevices, appliances, events, networkEvents, alerts, runtime, diagnostics, notificationStatus, selectedDevice, selectDevice, refresh, refreshing, error, demoMode, alertsEnabled, alertsSupported, enableAlerts, disableAlerts, reviews, browserSiteReviews, expectedServices, listenerObservations, audit, actions, passkeys, accountProfiles, accountUnlocked, desktopInstallStatus, desktopVersion, installDesktopApp, reviewFinding, classifyBrowserSite, resetBrowserSite, saveServiceExpectation, saveServiceExpectations, removeServiceExpectation, runAction, addOwnerPasskey, removeOwnerPasskey, saveAccount, removeAccount, unlockAccounts, lockAccounts, runApplianceDeepCheck, deepCheckBusy, actionBusy, signOut, route, navigate }: ApplicationProps) {
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
		: route.page === "overview" ? "Overview" : route.page === "settings" ? "System & Recovery" : `${route.page.charAt(0).toUpperCase()}${route.page.slice(1)}`;
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
		page = <><PageIntro eyebrow="PERSONAL SECURITY OBSERVATORY" title="Home security overview">Current alerts, coverage, and meaningful changes across trusted devices and explicitly configured appliances.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} runApplianceDeepCheck={runApplianceDeepCheck} deepCheckBusy={deepCheckBusy} demoMode={demoMode} view="overview" /></>;
	} else if (route.page === "devices") {
		page = <><PageIntro eyebrow="TRUSTED INVENTORY" title="Devices">Choose an enrolled endpoint to inspect its posture and verify that its reporter is current, compatible, and collecting the expected evidence.</PageIntro><FleetPanel devices={devices} runtime={runtime} /><DeviceInventory devices={devices} selectedId={selectedDeviceId} select={openDevice} demoMode={demoMode} /></>;
	} else if (route.page === "network") {
		page = <><PageIntro eyebrow="LIVE OBSERVATION" title="Network">Current device coverage and relationship summaries without packet capture or retained remote endpoints.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} runApplianceDeepCheck={runApplianceDeepCheck} deepCheckBusy={deepCheckBusy} demoMode={demoMode} view="network" /></>;
	} else if (route.page === "appliances") {
		page = <><PageIntro eyebrow="READ-ONLY HEALTH" title="Appliances">Bounded reachability and health evidence from devices explicitly configured by the owner.</PageIntro><NetworkOverview devices={networkDevices} appliances={appliances} events={networkEvents} alerts={alerts} selectedId={selectedDeviceId} selectDevice={openDevice} runApplianceDeepCheck={runApplianceDeepCheck} deepCheckBusy={deepCheckBusy} demoMode={demoMode} view="appliances" /></>;
	} else if (route.page === "accounts") {
		page = <><PageIntro eyebrow="IDENTITY AND RECOVERY" title="Accounts">An informal, encrypted notebook for the security measures you have confirmed directly at each provider.</PageIntro><AccountNotebook profiles={accountProfiles} demoMode={demoMode} unlocked={accountUnlocked} busy={actionBusy} unlock={unlockAccounts} lock={lockAccounts} save={saveAccount} remove={removeAccount} /></>;
	} else if (route.page === "activity") {
		page = <><PageIntro eyebrow="EVENTS AND DECISIONS" title="Activity">Finding transitions, deliberate control requests, and privacy-bounded owner decisions.</PageIntro><ActivityPanel events={networkEvents} alerts={alerts} />{!demoMode && <ActionCenter actions={actions} audit={audit} capabilities={runtime?.actionCapabilities || []} run={runAction} busy={actionBusy} />}</>;
	} else if (route.page === "settings") {
		page = <SystemRecoveryPage diagnostics={diagnostics} devices={devices} desktopVersion={desktopVersion} desktopInstallStatus={desktopInstallStatus} installDesktopApp={installDesktopApp} demoMode={demoMode} notificationStatus={notificationStatus} alertsSupported={alertsSupported} alertsEnabled={alertsEnabled} actionBusy={actionBusy} enableAlerts={enableAlerts} disableAlerts={disableAlerts} passkeys={passkeys} addOwnerPasskey={addOwnerPasskey} removeOwnerPasskey={removeOwnerPasskey} runtime={runtime} />;
	} else {
		page = <>
			<div className="device-page-heading"><a href="/devices" onClick={(event) => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) { event.preventDefault(); navigate({ page: "devices" }); } }}>← All devices</a><DeviceNavigation deviceId={selectedDeviceId} current={deviceSection} navigate={navigate} /></div>
			{deviceSummary}
			{deviceSection === "overview" && <>{selectedDevice && <AgentEvidencePanel device={selectedDevice} runtime={runtime} />}<FindingsPanel findings={snapshot.findings || []} checks={snapshot.baselineChecks || []} reviews={reviews} review={reviewFinding} /></>}
			{deviceSection === "posture" && <>{(snapshot.baselineChecks || []).length > 0 && <BaselinePanel checks={snapshot.baselineChecks || []} collectedAt={snapshot.collectedAt} platform={isLinux ? "Linux" : "Windows"} />}{snapshot.notices.length > 0 && <section className="panel notices-panel" aria-labelledby="notices-title"><PanelHeading eyebrow="COLLECTION NOTES" title="Some signals could not be verified" id="notices-title" icon={<AlertIcon />} accent="amber">A collection limitation is not automatically a security problem</PanelHeading><ul className="notices-list">{snapshot.notices.map((notice, index) => <li className="notice" key={`${notice.source}-${index}`}><strong>{notice.source}: </strong>{notice.message}</li>)}</ul></section>}{isLinux && snapshot.linuxBaseline ? <LinuxPanel baseline={snapshot.linuxBaseline} /> : <DefenderPanel defender={snapshot.defender} />}<FirewallPanel profiles={snapshot.firewallProfiles} isLinux={isLinux} /></>}
			{deviceSection === "browsers" && <BrowserSecurityPanel status={snapshot.browserSecurity ?? null} deviceId={selectedDeviceId} reviews={browserSiteReviews} editable={!demoMode} busy={actionBusy} classifySite={classifyBrowserSite} resetSite={resetBrowserSite} />}
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
