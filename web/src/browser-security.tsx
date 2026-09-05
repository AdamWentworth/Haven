import { useMemo, useState } from "react";
import { siBrave, siFirefoxbrowser, siGooglechrome, type SimpleIcon } from "simple-icons";
import { AlertIcon, BrowserIcon, CheckIcon, HelpIcon } from "./icons";
import type { BrowserCookieSite, BrowserExtension, BrowserExtensionChange, BrowserInstallation, BrowserProfile, BrowserProtectionStatus, BrowserSecurityStatus } from "./types";
import { StatusChip, type Tone } from "./ui";
import { cookieSessionSignal, cookieSiteReview, filterCookieSites, groupCookieSites, sortCookieSites, type CookieSessionSignalLevel, type CookieSiteSort } from "./cookie-review";

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

function readableCookieDate(value?: string) {
	if (!value) return "Not available";
	const parsed = new Date(value);
	if (!Number.isFinite(parsed.getTime())) return "Not available";
	return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(parsed);
}

function CookieSiteRow({ site, showSessionSignal = false }: { site: BrowserCookieSite; showSessionSignal?: boolean }) {
	const review = cookieSiteReview(site);
	const sessionSignal = cookieSessionSignal(site);
	const reviewTone: Tone = review.state === "dormant" ? "attention" : review.state === "recent" ? "configured" : "unknown";
	return <li className="browser-cookie-site">
		<div className="browser-cookie-site-heading"><div><strong>{site.domain}</strong><small>Last cookie access {readableCookieDate(site.lastAccessedAt)}</small></div><div className="browser-cookie-signals">{showSessionSignal && <StatusChip label={sessionSignal.label} tone={sessionSignal.level === "limited" ? "unknown" : "configured"} />}<StatusChip label={review.label} tone={reviewTone} /></div></div>
		<div className="browser-cookie-counts" aria-label={`${site.domain} cookie metadata`}>
			<span><strong>{site.cookieCount}</strong> total</span>
			<span><strong>{site.sessionCookieCount}</strong> session-scoped</span>
			<span><strong>{site.persistentCookieCount}</strong> persistent</span>
			<span><strong>{site.secureCookieCount}/{site.cookieCount}</strong> Secure</span>
			<span><strong>{site.httpOnlyCookieCount}/{site.cookieCount}</strong> HTTP-only</span>
		</div>
		{review.candidate && <p>If you do not recognize or use this site in this profile, sign out at the site and clear its site data in Chrome.</p>}
		{site.latestExpiryAt && <small className="browser-cookie-expiry">Latest persistent-cookie expiry: {readableCookieDate(site.latestExpiryAt)}</small>}
	</li>;
}

const cookieGroupCopy: Record<CookieSessionSignalLevel, { title: string; description: string }> = {
	stronger: { title: "Likely sign-in related", description: "Session-scoped, Secure, and HTTP-only cookies are all present. This is the strongest local hint HAVEN can derive, not confirmation that you are signed in." },
	possible: { title: "May include sign-in state", description: "Secure and HTTP-only cookies are present, but no session-scoped cookie was observed. These may support a login or ordinary site operation." },
	limited: { title: "Other site data", description: "No strong aggregate session pattern was observed. These may be preferences, analytics, ordinary site operation, or a login represented elsewhere." },
};

function CookieProfileReview({ profile }: { profile: BrowserProfile }) {
	const [query, setQuery] = useState("");
	const [view, setView] = useState<"session-groups" | "cleanup">("session-groups");
	const [sort, setSort] = useState<CookieSiteSort>("recent");
	const [showAll, setShowAll] = useState(false);
	const reviewCount = useMemo(() => profile.sites.filter((site) => cookieSiteReview(site).candidate).length, [profile.sites]);
	const matching = useMemo(() => profile.sites.filter((site) => site.domain.includes(query.trim().toLowerCase())), [profile.sites, query]);
	const groups = useMemo(() => groupCookieSites(matching).map((group) => ({ ...group, sites: sortCookieSites(group.sites, sort) })), [matching, sort]);
	const cleanupSites = useMemo(() => sortCookieSites(filterCookieSites(matching, "cleanup"), "cleanup"), [matching]);
	const unavailable = profile.cookieStatus === "unavailable";
	return <details className="browser-cookie-profile" open>
		<summary><div><strong>{profile.name}</strong><small>{unavailable ? "Cookie metadata unavailable this run" : `${profile.cookieCount} cookie${profile.cookieCount === 1 ? "" : "s"} across ${profile.sites.length} site${profile.sites.length === 1 ? "" : "s"}`}</small></div><StatusChip label={unavailable ? "Unavailable this run" : reviewCount > 0 ? `${reviewCount} to review` : "No old site data"} tone={unavailable ? "unknown" : reviewCount > 0 ? "attention" : "healthy"} /></summary>
		{unavailable ? <p className="browser-empty">Chrome may be holding this active profile&apos;s cookie database exclusively. This is a collection limitation—not a security problem. HAVEN will retry on the next report; closing Chrome before a report lets the agent try while every profile is idle.</p> : <>
			<div className="browser-cookie-view-switch" role="group" aria-label={`${profile.name} site-data view`}><button type="button" aria-pressed={view === "session-groups"} onClick={() => { setView("session-groups"); setShowAll(false); }}>Session groups</button><button type="button" aria-pressed={view === "cleanup"} onClick={() => { setView("cleanup"); setShowAll(false); }}>Cleanup review <span>{reviewCount}</span></button></div>
			<div className="browser-cookie-controls">
				<label><span>Search domains <small>optional</small></span><input value={query} onChange={(event) => { setQuery(event.target.value); setShowAll(false); }} placeholder="Leave blank to see every group" /></label>
				{view === "session-groups" && <label><span>Sort within groups</span><select value={sort} onChange={(event) => setSort(event.target.value as CookieSiteSort)}><option value="recent">Most recently accessed</option><option value="cookie-count">Most cookies</option><option value="domain">Domain A–Z</option></select></label>}
			</div>
			{profile.cookieStatus === "partial" && <p className="browser-coverage-note"><HelpIcon size={17} /><span>This profile is a bounded partial view. HAVEN reports the verified rows and never copies the cookie database.</span></p>}
			{view === "session-groups" ? <div className="browser-cookie-groups">{groups.map((group) => {
				const copy = cookieGroupCopy[group.level];
				const visible = showAll || query.trim() ? group.sites : group.sites.slice(0, 12);
				return <section className={`browser-cookie-group ${group.level}`} key={group.level} aria-labelledby={`${profile.fingerprint}-${group.level}`}><div className="browser-cookie-group-heading"><div><h4 id={`${profile.fingerprint}-${group.level}`}>{copy.title}</h4><p>{copy.description}</p></div><StatusChip label={`${group.sites.length} site${group.sites.length === 1 ? "" : "s"}`} tone={group.level === "limited" ? "unknown" : "configured"} /></div>{visible.length === 0 ? <p className="browser-empty">No sites in this group.</p> : <ul className="browser-cookie-site-list">{visible.map((site) => <CookieSiteRow site={site} key={site.domain} />)}</ul>}</section>;
			})}</div> : <section className="browser-cookie-group cleanup" aria-labelledby={`${profile.fingerprint}-cleanup`}><div className="browser-cookie-group-heading"><div><h4 id={`${profile.fingerprint}-cleanup`}>Old or undated site data</h4><p>Sites not accessed for at least 90 days, or whose access date could not be verified. Review before clearing anything you still recognize or use.</p></div><StatusChip label={`${cleanupSites.length} candidate${cleanupSites.length === 1 ? "" : "s"}`} tone={cleanupSites.length > 0 ? "attention" : "healthy"} /></div>{cleanupSites.length === 0 ? <p className="browser-empty">No cleanup candidates in this profile.</p> : <ul className="browser-cookie-site-list">{(showAll || query.trim() ? cleanupSites : cleanupSites.slice(0, 20)).map((site) => <CookieSiteRow site={site} showSessionSignal key={site.domain} />)}</ul>}</section>}
			{!showAll && !query.trim() && ((view === "session-groups" && groups.some((group) => group.sites.length > 12)) || (view === "cleanup" && cleanupSites.length > 20)) && <button type="button" className="browser-cookie-show-all" onClick={() => setShowAll(true)}>Show every site in this view</button>}
		</>}
	</details>;
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
	const cookieSiteCount = status.browsers.reduce((total, browser) => total + (browser.profiles || []).reduce((profileTotal, profile) => profileTotal + profile.sites.length, 0), 0);
	return <section className="panel browser-security-panel" aria-labelledby="browser-security-title">
		<div className="section-heading"><div className="heading-identity"><span className="section-icon cyan"><BrowserIcon /></span><div><p className="eyebrow">BROWSER &amp; SESSION EXPOSURE</p><h2 id="browser-security-title">Browser security</h2></div></div><p>Live, privacy-bounded evidence</p></div>
		<p className="browser-privacy"><CheckIcon size={17} /><span><strong>Values stay private.</strong> HAVEN reads only aggregate Chrome cookie metadata for this requested review. It never selects or transmits cookie names, values, encrypted values, paths, passwords, page contents, form data, raw extension IDs, or extension site patterns. Browser inventory stays live-only and disappears from the hub after a restart until the next report.</span></p>
		<div className="browser-metrics" aria-label="Browser exposure summary"><div><small>Browsers</small><strong>{status.browsers.length}</strong></div><div><small>Profiles</small><strong>{profileCount}</strong></div><div><small>Cookie sites</small><strong>{cookieSiteCount}</strong></div><div><small>Extensions</small><strong>{extensionCount}</strong></div><div><small>Broad site access</small><strong>{broadAccessCount}</strong></div></div>
		{status.coverage === "partial" && <p className="browser-coverage-note"><HelpIcon size={17} /><span>Some browser metadata could not be read. Counts include only what the agent verified; an active Chrome profile may temporarily lock its cookie database.</span></p>}
		{status.protections.length > 0 && <div className="browser-protections"><h3>System web protections</h3><div>{status.protections.map((protection) => <article key={protection.id}><div><strong>{protection.name}</strong>{protection.source && <small>{protection.source}</small>}{protectionDetail(protection) && <p>{protectionDetail(protection)}</p>}</div><StatusChip label={protectionLabel(protection.state)} tone={protectionTone(protection.state)} /></article>)}</div></div>}
		{status.changes && status.changes.length > 0 && <div className="browser-changes"><div><h3>Meaningful extension changes</h3><StatusChip label={`${status.changes.length} to review`} tone="attention" /></div><p>Compared with this endpoint&apos;s last accepted local baseline.</p><ul>{status.changes.map((change) => <li key={change.id}><AlertIcon size={17} /><span><strong>{changeTitle(change)}</strong><small>{changeDetail(change)}</small></span></li>)}</ul></div>}
		<div className="browser-grid">
			{status.browsers.length === 0 ? <p className="activity-empty"><strong>No supported browser profiles observed.</strong><span>This is an inventory result, not a security failure.</span></p> : status.browsers.map((browser) => <article className={`browser-card${browser.profiles && browser.profiles.length > 0 ? " browser-card-wide" : ""}`} key={browser.id}>
				<div className="browser-card-heading"><div><BrowserMark browser={browser} /><div><h3>{browser.name}</h3><p>{browser.version || "Version not exposed"} · {browser.profileCount} profile{browser.profileCount === 1 ? "" : "s"}</p></div></div><StatusChip label={`${browser.extensions.length} extension${browser.extensions.length === 1 ? "" : "s"}`} tone="configured" /></div>
				{browser.id === "chrome" && browser.profiles && browser.profiles.length > 0 && <div className="browser-cookie-review"><div className="browser-cookie-review-heading"><div><h3>Chrome profile site data</h3><p>Domains and aggregate cookie attributes—not authentication credentials</p></div><StatusChip label={`${browser.profiles.length} profile${browser.profiles.length === 1 ? "" : "s"}`} tone="configured" /></div><p className="browser-cookie-guidance"><HelpIcon size={16} /><span>A cookie can support a login, preferences, analytics, or site operation. Chrome&apos;s last-access timestamp is only a review hint, so HAVEN marks old entries as candidates—not confirmed sessions—and never claims that clearing one is required.</span></p>{browser.profiles.map((profile) => <CookieProfileReview profile={profile} key={profile.fingerprint} />)}</div>}
				{browser.extensions.length === 0 ? <p className="browser-empty">No user extensions were observed.</p> : <ul className="browser-extension-list">{browser.extensions.map((extension) => <ExtensionRow extension={extension} key={extension.fingerprint} />)}</ul>}
			</article>)}
		</div>
		<p className="browser-boundary"><HelpIcon size={16} /><span>Cookie presence cannot prove that a provider session is authenticated: login state may use several storage mechanisms and providers can revoke sessions without immediately removing every local cookie. Declared extension access is likewise a capability, not proof of malicious behavior. Confirm unfamiliar sites in Chrome or at the provider before signing out or clearing data.</span></p>
	</section>;
}
