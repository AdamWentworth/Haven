import { useMemo, useState } from "react";
import { siBrave, siFirefoxbrowser, siGooglechrome, type SimpleIcon } from "simple-icons";
import { AlertIcon, BrowserIcon, CheckIcon, HelpIcon } from "./icons";
import type { BrowserCookieSite, BrowserExtension, BrowserExtensionChange, BrowserInstallation, BrowserProfile, BrowserProtectionStatus, BrowserSecurityStatus, BrowserSiteReview, BrowserSiteReviewInput, BrowserSiteReviewKey, BrowserSiteReviewState } from "./types";
import { StatusChip, type Tone } from "./ui";
import { buildCookieCleanupQueue, cookieSessionSignal, cookieSiteReview, groupCookieSites, sortCookieSites, type CookieSessionSignalLevel, type CookieSiteSort } from "./cookie-review";

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

const siteReviewCopy: Record<BrowserSiteReviewState, { label: string; tone: Tone }> = {
	"signed-in-keep": { label: "Signed in — keep", tone: "healthy" },
	"recognized-ordinary": { label: "Recognized — ordinary", tone: "configured" },
	"clear-candidate": { label: "Clear candidate", tone: "attention" },
	"review-later": { label: "Review later", tone: "unknown" },
};

interface CookieSiteRowProps {
	deviceId: string;
	browserId: string;
	profileFingerprint: string;
	site: BrowserCookieSite;
	review?: BrowserSiteReview;
	showSessionSignal?: boolean;
	editable: boolean;
	busy: boolean;
	classify: (review: BrowserSiteReviewInput) => void;
	reset: (review: BrowserSiteReviewKey) => void;
}

function CookieSiteRow({ deviceId, browserId, profileFingerprint, site, review, showSessionSignal = false, editable, busy, classify, reset }: CookieSiteRowProps) {
	const ageReview = cookieSiteReview(site);
	const sessionSignal = cookieSessionSignal(site);
	const ageTone: Tone = ageReview.state === "dormant" ? "attention" : ageReview.state === "recent" ? "configured" : "unknown";
	const key = { deviceId, browserId, profileFingerprint, domain: site.domain };
	const saved = review?.state ? siteReviewCopy[review.state] : null;
	return <li className={`browser-cookie-site ${review?.state || "unreviewed"}`}>
		<div className="browser-cookie-site-heading"><div><strong>{site.domain}</strong><small>Last cookie access {readableCookieDate(site.lastAccessedAt)}</small></div><div className="browser-cookie-signals">{saved && <StatusChip label={saved.label} tone={saved.tone} />}{showSessionSignal && <StatusChip label={sessionSignal.label} tone={sessionSignal.level === "limited" ? "unknown" : "configured"} />}<StatusChip label={ageReview.label} tone={ageTone} /></div></div>
		<div className="browser-cookie-counts" aria-label={`${site.domain} cookie metadata`}>
			<span><strong>{site.cookieCount}</strong> total</span>
			<span><strong>{site.sessionCookieCount}</strong> session-scoped</span>
			<span><strong>{site.persistentCookieCount}</strong> persistent</span>
			<span><strong>{site.secureCookieCount}/{site.cookieCount}</strong> Secure</span>
			<span><strong>{site.httpOnlyCookieCount}/{site.cookieCount}</strong> HTTP-only</span>
		</div>
		{editable && <div className="browser-cookie-classification"><label><span className="sr-only">Classification for {site.domain}</span><select aria-label={`Classification for ${site.domain}`} value={review?.state || ""} disabled={busy} onChange={(event) => {
			const state = event.target.value as BrowserSiteReviewState | "";
			if (state) classify({ ...key, state });
			else reset(key);
		}}><option value="">Unreviewed</option><option value="signed-in-keep">Signed in — keep</option><option value="recognized-ordinary">Recognized — ordinary</option><option value="clear-candidate">Clear candidate</option><option value="review-later">Review later</option></select></label></div>}
		{ageReview.candidate && review?.state !== "signed-in-keep" && review?.state !== "review-later" && <p>If you do not recognize or use this site in this profile, verify it before placing it in the cleanup queue.</p>}
		{site.latestExpiryAt && <small className="browser-cookie-expiry">Latest persistent-cookie expiry: {readableCookieDate(site.latestExpiryAt)}</small>}
	</li>;
}

const cookieGroupCopy: Record<CookieSessionSignalLevel, { title: string; description: string }> = {
	stronger: { title: "Likely sign-in related", description: "Session-scoped, Secure, and HTTP-only cookies are all present. This is the strongest local hint HAVEN can derive, not confirmation that you are signed in." },
	possible: { title: "May include sign-in state", description: "Secure and HTTP-only cookies are present, but no session-scoped cookie was observed. These may support a login or ordinary site operation." },
	limited: { title: "Other site data", description: "No strong aggregate session pattern was observed. These may be preferences, analytics, ordinary site operation, or a login represented elsewhere." },
};

interface CookieProfileReviewProps {
	deviceId: string;
	browserId: string;
	profile: BrowserProfile;
	reviews: BrowserSiteReview[];
	editable: boolean;
	busy: boolean;
	classify: (review: BrowserSiteReviewInput) => void;
	reset: (review: BrowserSiteReviewKey) => void;
}

function CookieProfileReview({ deviceId, browserId, profile, reviews, editable, busy, classify, reset }: CookieProfileReviewProps) {
	const [query, setQuery] = useState("");
	const [view, setView] = useState<"session-groups" | "cleanup">("session-groups");
	const [sort, setSort] = useState<CookieSiteSort>("recent");
	const [showAll, setShowAll] = useState(false);
	const profileReviews = useMemo(() => reviews.filter((review) => review.browserId === browserId && review.profileFingerprint === profile.fingerprint), [browserId, profile.fingerprint, reviews]);
	const reviewsByDomain = useMemo(() => Object.fromEntries(profileReviews.map((review) => [review.domain, review])), [profileReviews]);
	const reviewStates = useMemo(() => Object.fromEntries(profileReviews.map((review) => [review.domain, review.state])), [profileReviews]);
	const matching = useMemo(() => profile.sites.filter((site) => site.domain.includes(query.trim().toLowerCase())), [profile.sites, query]);
	const groups = useMemo(() => groupCookieSites(matching).map((group) => ({ ...group, sites: sortCookieSites(group.sites, sort) })), [matching, sort]);
	const cleanup = useMemo(() => buildCookieCleanupQueue(matching, reviewStates), [matching, reviewStates]);
	const reviewCount = cleanup.ready.length + cleanup.suggested.length;
	const classifiedCount = profile.sites.filter((site) => Boolean(reviewsByDomain[site.domain])).length;
	const excludedCount = profile.sites.filter((site) => reviewsByDomain[site.domain]?.state === "signed-in-keep" || reviewsByDomain[site.domain]?.state === "review-later").length;
	const unavailable = profile.cookieStatus === "unavailable";
	return <details className="browser-cookie-profile" open>
		<summary><div><strong>{profile.name}</strong><small>{unavailable ? "Cookie metadata unavailable this run" : `${profile.cookieCount} cookie${profile.cookieCount === 1 ? "" : "s"} across ${profile.sites.length} site${profile.sites.length === 1 ? "" : "s"}`}</small></div><StatusChip label={unavailable ? "Unavailable this run" : `${classifiedCount} classified · ${profile.sites.length - classifiedCount} unreviewed`} tone={unavailable ? "unknown" : classifiedCount === profile.sites.length ? "healthy" : "configured"} /></summary>
		{unavailable ? <p className="browser-empty">Chrome may be holding this active profile&apos;s cookie database exclusively. This is a collection limitation—not a security problem. HAVEN will retry on the next report; closing Chrome before a report lets the agent try while every profile is idle.</p> : <>
			<div className="browser-cookie-view-switch" role="group" aria-label={`${profile.name} site-data view`}><button type="button" aria-pressed={view === "session-groups"} onClick={() => { setView("session-groups"); setShowAll(false); }}>Review &amp; classify</button><button type="button" aria-pressed={view === "cleanup"} onClick={() => { setView("cleanup"); setShowAll(false); }}>Cleanup queue <span>{reviewCount}</span></button></div>
			<div className="browser-cookie-controls">
				<label><span>Search domains <small>optional</small></span><input value={query} onChange={(event) => { setQuery(event.target.value); setShowAll(false); }} placeholder="Leave blank to see every group" /></label>
				{view === "session-groups" && <label><span>Sort within groups</span><select value={sort} onChange={(event) => setSort(event.target.value as CookieSiteSort)}><option value="recent">Most recently accessed</option><option value="cookie-count">Most cookies</option><option value="domain">Domain A–Z</option></select></label>}
			</div>
			{profile.cookieStatus === "partial" && <p className="browser-coverage-note"><HelpIcon size={17} /><span>This profile is a bounded partial view. HAVEN reports the verified rows and never copies the cookie database.</span></p>}
			{view === "session-groups" ? <div className="browser-cookie-groups">{groups.map((group) => {
				const copy = cookieGroupCopy[group.level];
				const visible = showAll || query.trim() ? group.sites : group.sites.slice(0, 12);
				return <section className={`browser-cookie-group ${group.level}`} key={group.level} aria-labelledby={`${profile.fingerprint}-${group.level}`}><div className="browser-cookie-group-heading"><div><h4 id={`${profile.fingerprint}-${group.level}`}>{copy.title}</h4><p>{copy.description}</p></div><StatusChip label={`${group.sites.length} site${group.sites.length === 1 ? "" : "s"}`} tone={group.level === "limited" ? "unknown" : "configured"} /></div>{visible.length === 0 ? <p className="browser-empty">No sites in this group.</p> : <ul className="browser-cookie-site-list">{visible.map((site) => <CookieSiteRow deviceId={deviceId} browserId={browserId} profileFingerprint={profile.fingerprint} site={site} review={reviewsByDomain[site.domain]} editable={editable} busy={busy} classify={classify} reset={reset} key={site.domain} />)}</ul>}</section>;
			})}</div> : <div className="browser-cleanup-queue"><p className="browser-cleanup-guidance"><strong>Guided cleanup only.</strong> Open this Chrome profile&apos;s site-data settings, search the domain, and remove it there. HAVEN never deletes browser data itself. Signed-in sites and items marked Review later are excluded from this queue{excludedCount > 0 ? ` (${excludedCount} excluded)` : ""}.</p>{([{
				id: "ready", title: "Ready to clear", description: "Sites you deliberately marked as cleanup candidates, regardless of age.", sites: cleanup.ready, tone: "attention" as Tone,
			}, {
				id: "suggested", title: "Suggested review", description: "Unprotected sites whose cookie access is at least 90 days old or could not be dated.", sites: cleanup.suggested, tone: "unknown" as Tone,
			}] as const).map((group) => <section className="browser-cookie-group cleanup" aria-labelledby={`${profile.fingerprint}-cleanup-${group.id}`} key={group.id}><div className="browser-cookie-group-heading"><div><h4 id={`${profile.fingerprint}-cleanup-${group.id}`}>{group.title}</h4><p>{group.description}</p></div><StatusChip label={`${group.sites.length} site${group.sites.length === 1 ? "" : "s"}`} tone={group.tone} /></div>{group.sites.length === 0 ? <p className="browser-empty">No sites in this part of the queue.</p> : <ul className="browser-cookie-site-list">{(showAll || query.trim() ? group.sites : group.sites.slice(0, 20)).map((site) => <CookieSiteRow deviceId={deviceId} browserId={browserId} profileFingerprint={profile.fingerprint} site={site} review={reviewsByDomain[site.domain]} showSessionSignal editable={editable} busy={busy} classify={classify} reset={reset} key={site.domain} />)}</ul>}</section>)}</div>}
			{!showAll && !query.trim() && ((view === "session-groups" && groups.some((group) => group.sites.length > 12)) || (view === "cleanup" && (cleanup.ready.length > 20 || cleanup.suggested.length > 20))) && <button type="button" className="browser-cookie-show-all" onClick={() => setShowAll(true)}>Show every site in this view</button>}
		</>}
	</details>;
}

interface BrowserSecurityPanelProps {
	status: BrowserSecurityStatus | null;
	deviceId?: string;
	reviews?: BrowserSiteReview[];
	editable?: boolean;
	busy?: boolean;
	classifySite?: (review: BrowserSiteReviewInput) => void;
	resetSite?: (review: BrowserSiteReviewKey) => void;
}

export function BrowserSecurityPanel({ status, deviceId = "", reviews = [], editable = false, busy = false, classifySite = () => {}, resetSite = () => {} }: BrowserSecurityPanelProps) {
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
		<p className="browser-privacy"><CheckIcon size={17} /><span><strong>Values stay private.</strong> HAVEN reads only aggregate Chrome cookie metadata for this requested review. It never selects or transmits cookie names, values, encrypted values, paths, passwords, page contents, form data, raw extension IDs, or extension site patterns. Live inventory disappears after a hub restart; only your encrypted domain-level classifications persist.</span></p>
		<div className="browser-metrics" aria-label="Browser exposure summary"><div><small>Browsers</small><strong>{status.browsers.length}</strong></div><div><small>Profiles</small><strong>{profileCount}</strong></div><div><small>Cookie sites</small><strong>{cookieSiteCount}</strong></div><div><small>Extensions</small><strong>{extensionCount}</strong></div><div><small>Broad site access</small><strong>{broadAccessCount}</strong></div></div>
		{status.coverage === "partial" && <p className="browser-coverage-note"><HelpIcon size={17} /><span>Some browser metadata could not be read. Counts include only what the agent verified; an active Chrome profile may temporarily lock its cookie database.</span></p>}
		{status.protections.length > 0 && <div className="browser-protections"><h3>System web protections</h3><div>{status.protections.map((protection) => <article key={protection.id}><div><strong>{protection.name}</strong>{protection.source && <small>{protection.source}</small>}{protectionDetail(protection) && <p>{protectionDetail(protection)}</p>}</div><StatusChip label={protectionLabel(protection.state)} tone={protectionTone(protection.state)} /></article>)}</div></div>}
		{status.changes && status.changes.length > 0 && <div className="browser-changes"><div><h3>Meaningful extension changes</h3><StatusChip label={`${status.changes.length} to review`} tone="attention" /></div><p>Compared with this endpoint&apos;s last accepted local baseline.</p><ul>{status.changes.map((change) => <li key={change.id}><AlertIcon size={17} /><span><strong>{changeTitle(change)}</strong><small>{changeDetail(change)}</small></span></li>)}</ul></div>}
		<div className="browser-grid">
			{status.browsers.length === 0 ? <p className="activity-empty"><strong>No supported browser profiles observed.</strong><span>This is an inventory result, not a security failure.</span></p> : status.browsers.map((browser) => <article className={`browser-card${browser.profiles && browser.profiles.length > 0 ? " browser-card-wide" : ""}`} key={browser.id}>
				<div className="browser-card-heading"><div><BrowserMark browser={browser} /><div><h3>{browser.name}</h3><p>{browser.version || "Version not exposed"} · {browser.profileCount} profile{browser.profileCount === 1 ? "" : "s"}</p></div></div><StatusChip label={`${browser.extensions.length} extension${browser.extensions.length === 1 ? "" : "s"}`} tone="configured" /></div>
				{browser.id === "chrome" && browser.profiles && browser.profiles.length > 0 && <div className="browser-cookie-review"><div className="browser-cookie-review-heading"><div><h3>Chrome profile site data</h3><p>Domains and aggregate cookie attributes—not authentication credentials</p></div><StatusChip label={`${browser.profiles.length} profile${browser.profiles.length === 1 ? "" : "s"}`} tone="configured" /></div><p className="browser-cookie-guidance"><HelpIcon size={16} /><span>Classify the domain as a whole rather than guessing what individual cookies do. Signed in — keep only protects a site from HAVEN cleanup suggestions; it does not make its cookies immune to malware. Chrome&apos;s last-access timestamp remains a review hint—not proof of a login.</span></p>{browser.profiles.map((profile) => <CookieProfileReview deviceId={deviceId} browserId={browser.id} profile={profile} reviews={reviews} editable={editable} busy={busy} classify={classifySite} reset={resetSite} key={profile.fingerprint} />)}</div>}
				{browser.extensions.length === 0 ? <p className="browser-empty">No user extensions were observed.</p> : <ul className="browser-extension-list">{browser.extensions.map((extension) => <ExtensionRow extension={extension} key={extension.fingerprint} />)}</ul>}
			</article>)}
		</div>
		<p className="browser-boundary"><HelpIcon size={16} /><span>Cookie presence cannot prove that a provider session is authenticated: login state may use several storage mechanisms and providers can revoke sessions without immediately removing every local cookie. Declared extension access is likewise a capability, not proof of malicious behavior. Confirm unfamiliar sites in Chrome or at the provider before signing out or clearing data.</span></p>
	</section>;
}
