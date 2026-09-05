import { siBrave, siFirefoxbrowser, siGooglechrome, type SimpleIcon } from "simple-icons";
import { AlertIcon, BrowserIcon, CheckIcon, HelpIcon } from "./icons";
import type { BrowserExtension, BrowserExtensionChange, BrowserInstallation, BrowserProtectionStatus, BrowserSecurityStatus } from "./types";
import { StatusChip, type Tone } from "./ui";

const browserIcons: Record<string, SimpleIcon> = {
	brave: siBrave,
	chrome: siGooglechrome,
	firefox: siFirefoxbrowser,
};

const permissionLabels: Record<string, string> = {
	bookmarks: "Bookmarks",
	browsingdata: "Browsing data",
	clipboardread: "Read clipboard",
	cookies: "Cookies",
	debugger: "Browser debugger",
	downloads: "Downloads",
	history: "Browsing history",
	management: "Manage extensions",
	nativemessaging: "Native applications",
	pagecapture: "Capture pages",
	privacy: "Privacy settings",
	proxy: "Proxy settings",
	scripting: "Run scripts",
	sessions: "Recent sessions",
	tabs: "Tab details",
	topsites: "Top sites",
	webauthenticationproxy: "Authentication requests",
	webnavigation: "Navigation events",
	webrequest: "Web requests",
	webrequestblocking: "Block web requests",
};

function BrowserMark({ browser }: { browser: BrowserInstallation }) {
	const key = browser.id.replace(/-snap$/, "");
	const icon = browserIcons[key];
	if (!icon) return <span className="browser-mark generic"><BrowserIcon size={21} /></span>;
	return <span className="browser-mark" style={{ color: `#${icon.hex}` }} aria-hidden="true"><svg viewBox="0 0 24 24" role="img"><path fill="currentColor" d={icon.path} /></svg></span>;
}

function protectionTone(state: BrowserProtectionStatus["state"]): Tone {
	if (state === "enabled" || state === "clear") return "healthy";
	if (state === "audit" || state === "default") return "configured";
	if (state === "disabled" || state === "attention") return "attention";
	return "unknown";
}

function protectionLabel(state: BrowserProtectionStatus["state"]) {
	if (state === "audit") return "Audit only";
	if (state === "default") return "Browser default";
	if (state === "clear") return "No recent failures";
	if (state === "attention") return "Review evidence";
	return state.charAt(0).toUpperCase() + state.slice(1);
}

function protectionDetail(protection: BrowserProtectionStatus) {
	if (protection.id === "chrome-cookie-verification-events" && protection.state === "attention") return `${protection.eventCount || 0} Chrome verification event${protection.eventCount === 1 ? "" : "s"} observed in the last 7 days. This can indicate incompatibility or an attempted bypass; it is not proof of malware.`;
	if (protection.id === "chrome-cookie-verification-events" && protection.state === "clear") return "No Chrome cookie-protection verification failures were observed in the last 7 days.";
	if (protection.id === "chrome-app-bound-encryption" && protection.state === "default") return "No overriding policy was found; Chrome controls this protection with its platform default.";
	if (protection.id === "chrome-device-bound-sessions" && protection.state === "default") return "No overriding policy was found. Provider support and rollout still determine which eligible sessions are device-bound.";
	return "";
}

function siteAccessLabel(access: BrowserExtension["siteAccess"]) {
	if (access === "all-sites") return "All sites";
	if (access === "specific-sites") return "Specific sites";
	return "No site access declared";
}

function permissionLabel(permission: string) {
	return permissionLabels[permission.toLowerCase()] || permission;
}

function changeTitle(change: BrowserExtensionChange) {
	if (change.kind === "installed") return `${change.extensionName} was installed`;
	if (change.kind === "enabled") return `${change.extensionName} was enabled`;
	return `${change.extensionName} gained capabilities`;
}

function changeDetail(change: BrowserExtensionChange) {
	const details: string[] = [];
	if (change.siteAccess === "all-sites") details.push("access to all sites");
	else if (change.siteAccess === "specific-sites") details.push("access to specific sites");
	if (change.addedPermissions.length > 0) details.push(change.addedPermissions.map(permissionLabel).join(", "));
	return details.length > 0 ? details.join(" · ") : "No broad or sensitive capability was declared.";
}

function ExtensionRow({ extension }: { extension: BrowserExtension }) {
	const permissions = extension.sensitivePermissions.map(permissionLabel);
	const optionalPermissions = extension.optionalSensitivePermissions.map(permissionLabel);
	const optionalAccess = extension.optionalSiteAccess === "none-declared" ? "" : ` · optionally requests ${siteAccessLabel(extension.optionalSiteAccess).toLowerCase()}`;
	return <li className={`browser-extension ${extension.state === "disabled" ? "disabled" : ""}`}>
		<div className="browser-extension-heading"><div><strong>{extension.name}</strong><small>{extension.version || "Version not exposed"} · {extension.state}{extension.profileCount > 1 ? ` in ${extension.profileCount} profiles` : ""}</small></div><StatusChip label={siteAccessLabel(extension.siteAccess)} tone={extension.siteAccess === "all-sites" ? "attention" : extension.siteAccess === "specific-sites" ? "configured" : "unknown"} /></div>
		{optionalAccess && <p className="browser-extension-access">Required access: {siteAccessLabel(extension.siteAccess).toLowerCase()}{optionalAccess}</p>}
		{(permissions.length > 0 || optionalPermissions.length > 0) && <div className="browser-capabilities" aria-label={`${extension.name} sensitive capabilities`}>
			{permissions.map((permission) => <span key={`required-${permission}`}>{permission}</span>)}
			{optionalPermissions.map((permission) => <span className="optional" key={`optional-${permission}`}>{permission} · optional</span>)}
		</div>}
	</li>;
}

export function BrowserSecurityPanel({ status }: { status: BrowserSecurityStatus | null }) {
	if (!status || status.coverage === "unavailable") {
		return <section className="panel browser-security-panel" aria-labelledby="browser-security-title">
			<div className="section-heading"><div className="heading-identity"><span className="section-icon cyan"><BrowserIcon /></span><div><p className="eyebrow">BROWSER &amp; SESSION EXPOSURE</p><h2 id="browser-security-title">Browser security</h2></div></div><p>Live, privacy-bounded evidence</p></div>
			<p className="activity-empty"><strong>Browser inventory is unavailable.</strong><span>The reporter could not verify supported browser metadata for this user session.</span></p>
		</section>;
	}
	const profileCount = status.browsers.reduce((total, browser) => total + browser.profileCount, 0);
	const extensionCount = status.browsers.reduce((total, browser) => total + browser.extensions.length, 0);
	const broadAccessCount = status.browsers.reduce((total, browser) => total + browser.extensions.filter((extension) => extension.siteAccess === "all-sites" || extension.optionalSiteAccess === "all-sites").length, 0);
	return <section className="panel browser-security-panel" aria-labelledby="browser-security-title">
		<div className="section-heading"><div className="heading-identity"><span className="section-icon cyan"><BrowserIcon /></span><div><p className="eyebrow">BROWSER &amp; SESSION EXPOSURE</p><h2 id="browser-security-title">Browser security</h2></div></div><p>Live, privacy-bounded evidence</p></div>
		<p className="browser-privacy"><CheckIcon size={17} /><span><strong>Private by design.</strong> HAVEN never reads or stores cookies, history, passwords, page contents, form data, raw extension IDs, or site patterns. Routine inventory stays live-only; privacy-reduced summaries of meaningful extension changes can appear in Security Activity.</span></p>
		<div className="browser-metrics" aria-label="Browser exposure summary"><div><small>Browsers</small><strong>{status.browsers.length}</strong></div><div><small>Profiles</small><strong>{profileCount}</strong></div><div><small>Extensions</small><strong>{extensionCount}</strong></div><div><small>Broad site access</small><strong>{broadAccessCount}</strong></div></div>
		{status.coverage === "partial" && <p className="browser-coverage-note"><HelpIcon size={17} /><span>Some browser metadata could not be read. Counts include only what the agent verified.</span></p>}
		{status.protections.length > 0 && <div className="browser-protections"><h3>System web protections</h3><div>{status.protections.map((protection) => <article key={protection.id}><div><strong>{protection.name}</strong>{protection.source && <small>{protection.source}</small>}{protectionDetail(protection) && <p>{protectionDetail(protection)}</p>}</div><StatusChip label={protectionLabel(protection.state)} tone={protectionTone(protection.state)} /></article>)}</div></div>}
		{status.changes && status.changes.length > 0 && <div className="browser-changes"><div><h3>Meaningful extension changes</h3><StatusChip label={`${status.changes.length} to review`} tone="attention" /></div><p>Compared with this endpoint&apos;s last accepted local baseline.</p><ul>{status.changes.map((change) => <li key={change.id}><AlertIcon size={17} /><span><strong>{changeTitle(change)}</strong><small>{changeDetail(change)}</small></span></li>)}</ul></div>}
		<div className="browser-grid">
			{status.browsers.length === 0 ? <p className="activity-empty"><strong>No supported browser profiles observed.</strong><span>This is an inventory result, not a security failure.</span></p> : status.browsers.map((browser) => <article className="browser-card" key={browser.id}>
				<div className="browser-card-heading"><div><BrowserMark browser={browser} /><div><h3>{browser.name}</h3><p>{browser.version || "Version not exposed"} · {browser.profileCount} profile{browser.profileCount === 1 ? "" : "s"}</p></div></div><StatusChip label={`${browser.extensions.length} extension${browser.extensions.length === 1 ? "" : "s"}`} tone="configured" /></div>
				{browser.extensions.length === 0 ? <p className="browser-empty">No user extensions were observed.</p> : <ul className="browser-extension-list">{browser.extensions.map((extension) => <ExtensionRow extension={extension} key={extension.fingerprint} />)}</ul>}
			</article>)}
		</div>
		<p className="browser-boundary"><HelpIcon size={16} /><span>Declared access describes an extension&apos;s capability—not proof that it is malicious, that optional access was granted, or that a browser version is current. Session-defense signals do not enumerate provider sessions or inspect cookie contents. Review unfamiliar names directly in the browser before removing anything.</span></p>
	</section>;
}
