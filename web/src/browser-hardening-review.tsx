import { AlertIcon, CheckIcon, HelpIcon, LockIcon } from "./icons";
import { evaluateBrowserHardening, type BrowserExtensionExposure, type BrowserHardeningCheckState } from "./browser-hardening";
import type { BrowserSecurityStatus } from "./types";
import { StatusChip, type Tone } from "./ui";

function checkTone(state: BrowserHardeningCheckState): Tone {
	return state === "verified" ? "healthy" : state === "review" ? "attention" : "unknown";
}

function outcomeTone(outcome: ReturnType<typeof evaluateBrowserHardening>["outcome"]): Tone {
	return outcome === "protected" ? "healthy" : outcome === "review" ? "attention" : "unknown";
}

function exposureDetail(exposure: BrowserExtensionExposure) {
	const details: string[] = [];
	if (exposure.requiredAllSites) details.push("required access to all sites");
	if (exposure.requiredCapabilities.length > 0) details.push(exposure.requiredCapabilities.join(", "));
	if (exposure.optionalAllSites) details.push("optional access to all sites");
	if (exposure.optionalCapabilities.length > 0) details.push(`${exposure.optionalCapabilities.join(", ")} (optional)`);
	return details.join(" · ");
}

export function BrowserHardeningReviewPanel({ status }: { status: BrowserSecurityStatus }) {
	const review = evaluateBrowserHardening(status);
	return <section className={`browser-hardening ${review.outcome}`} aria-labelledby="browser-hardening-title">
		<div className="browser-hardening-heading">
			<div><p className="eyebrow">BOUNDED REVIEW</p><h3 id="browser-hardening-title">Browser hardening</h3><p>{review.summary}</p></div>
			<StatusChip label={review.title} tone={outcomeTone(review.outcome)} />
		</div>
		<p className="browser-hardening-rule"><LockIcon size={17} /><span><strong>Logged-in sites and cookie counts do not affect this result.</strong> Staying signed in is a usability choice, not a failed security check. There is no cookie-count target to chase.</span></p>
		<div className="browser-hardening-grid">
			<article className="browser-hardening-card">
				<div className="browser-hardening-card-heading"><div><CheckIcon size={18} /><h4>Browser defenses</h4></div><StatusChip label={review.checks.some((check) => check.state === "review") ? "Review item" : review.coveragePartial ? "Partial evidence" : "Verified"} tone={review.checks.some((check) => check.state === "review") ? "attention" : review.coveragePartial ? "unknown" : "healthy"} /></div>
				{review.checks.length === 0 ? <p className="browser-hardening-empty">No supported protection evidence was returned.</p> : <ul className="browser-hardening-checks">{review.checks.map((check) => <li key={check.id}><div><strong>{check.name}</strong><small>{check.source || "Reporter evidence"}</small><p>{check.detail}</p></div><StatusChip label={check.label} tone={checkTone(check.state)} /></li>)}</ul>}
			</article>
			<article className="browser-hardening-card" id="extension-exposure-review">
				<div className="browser-hardening-card-heading"><div><HelpIcon size={18} /><h4>Extension exposure</h4></div><StatusChip label={`${review.higherAccessExtensions.length} higher access`} tone={review.higherAccessExtensions.length > 0 ? "configured" : "healthy"} /></div>
				<p><strong>{review.extensionCount}</strong> extensions observed; <strong>{review.requiredAllSitesCount}</strong> currently declare access to all sites{review.optionalAllSitesCount > 0 ? ` and ${review.optionalAllSitesCount} optionally request it` : ""}. Broad access is capability—not a malware verdict.</p>
				{review.higherAccessExtensions.length === 0 ? <p className="browser-hardening-empty">No enabled higher-access extension capability was observed.</p> : <details><summary>Review higher-access extensions once</summary><p>Keep only extensions you recognize and still use. After that one-time review, HAVEN watches for meaningful capability changes; ordinary cookie totals do not require repeated checking.</p><ul>{review.higherAccessExtensions.map((extension, index) => <li key={`${extension.browserName}-${extension.extensionName}-${index}`}><strong>{extension.extensionName}</strong><small>{extension.browserName} · {exposureDetail(extension)}</small></li>)}</ul></details>}
			</article>
			<article className="browser-hardening-card incident-card">
				<div className="browser-hardening-card-heading"><div><AlertIcon size={18} /><h4>If a real incident signal appears</h4></div><StatusChip label="Use only on a concrete trigger" tone="configured" /></div>
				<p className="incident-trigger">A provider warning you do not recognize, an unexplained extension change, failed cookie-protection verification, or confirmed malware is a trigger. A normal logged-in session is not.</p>
				<ol><li><strong>Contain.</strong><span>Disconnect the affected device if suspicious activity is ongoing.</span></li><li><strong>Use a known-clean device.</strong><span>Revoke provider sessions, then secure the primary email and password manager first.</span></li><li><strong>Investigate.</strong><span>Remove the suspect extension or software and run the platform&apos;s trusted malware scans.</span></li><li><strong>Recover.</strong><span>If an information stealer is confirmed, reimage the affected device and rotate credentials from the clean device.</span></li></ol>
			</article>
		</div>
	</section>;
}
