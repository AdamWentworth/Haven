import type { BrowserExtension, BrowserProtectionStatus, BrowserSecurityStatus } from "./types";

export type BrowserHardeningOutcome = "protected" | "review" | "limited";
export type BrowserHardeningCheckState = "verified" | "review" | "unavailable";

export interface BrowserHardeningCheck {
	id: string;
	name: string;
	source?: string;
	state: BrowserHardeningCheckState;
	label: string;
	detail: string;
}

export interface BrowserExtensionExposure {
	browserName: string;
	extensionName: string;
	state: BrowserExtension["state"];
	requiredAllSites: boolean;
	optionalAllSites: boolean;
	requiredCapabilities: string[];
	optionalCapabilities: string[];
}

export interface BrowserHardeningReview {
	outcome: BrowserHardeningOutcome;
	title: string;
	summary: string;
	checks: BrowserHardeningCheck[];
	extensionCount: number;
	requiredAllSitesCount: number;
	optionalAllSitesCount: number;
	higherAccessExtensions: BrowserExtensionExposure[];
	meaningfulChangeCount: number;
	coveragePartial: boolean;
}

const capabilityLabels: Record<string, string> = {
	browsingdata: "browsing data",
	clipboardread: "clipboard reads",
	cookies: "cookie access",
	debugger: "browser debugging",
	history: "browsing history",
	management: "extension management",
	nativemessaging: "native applications",
	privacy: "privacy settings",
	proxy: "proxy settings",
	sessions: "recent sessions",
	webrequest: "web requests",
	webrequestblocking: "web-request blocking",
};

function protectionDetail(protection: BrowserProtectionStatus) {
	if (protection.id === "chrome-cookie-verification-events") {
		if (protection.state === "clear") return "No Chrome cookie-protection verification failures were observed in the last 7 days.";
		if (protection.state === "attention") return `${protection.eventCount || 0} Chrome verification event${protection.eventCount === 1 ? "" : "s"} observed in the last 7 days. This can reflect incompatibility or an attempted bypass; it is not proof of malware.`;
		return "Windows could not verify recent Chrome cookie-protection events.";
	}
	if (protection.id === "chrome-app-bound-encryption" && protection.state === "default") return "No overriding policy was found. Chrome controls App-Bound Encryption with its platform default.";
	if (protection.id === "chrome-device-bound-sessions" && protection.state === "default") return "No overriding policy was found. Provider support and rollout still determine which eligible Google sessions are device-bound.";
	if (protection.state === "enabled") return "The reported protection is enabled.";
	if (protection.state === "audit") return "The protection is observing activity but is not enforcing its blocking mode.";
	if (protection.state === "disabled") return "The reported protection is explicitly disabled.";
	return "The reporter could not verify this protection.";
}

function evaluateProtection(protection: BrowserProtectionStatus): BrowserHardeningCheck {
	if (protection.state === "enabled" || protection.state === "clear" || protection.state === "default") {
		return { ...protection, state: "verified", label: protection.state === "default" ? "Browser default" : protection.state === "clear" ? "No recent failures" : "Enabled", detail: protectionDetail(protection) };
	}
	if (protection.state === "disabled" || protection.state === "audit" || protection.state === "attention") {
		return { ...protection, state: "review", label: protection.state === "audit" ? "Audit only" : protection.state === "attention" ? "Review evidence" : "Disabled", detail: protectionDetail(protection) };
	}
	return { ...protection, state: "unavailable", label: "Not verified", detail: protectionDetail(protection) };
}

function capabilityLabel(value: string) {
	return capabilityLabels[value.toLowerCase()] || value;
}

function extensionExposure(browserName: string, extension: BrowserExtension): BrowserExtensionExposure | null {
	if (extension.state === "disabled") return null;
	const requiredAllSites = extension.siteAccess === "all-sites";
	const optionalAllSites = extension.optionalSiteAccess === "all-sites";
	const requiredCapabilities = extension.sensitivePermissions.map(capabilityLabel);
	const optionalCapabilities = extension.optionalSensitivePermissions.map(capabilityLabel);
	if (!requiredAllSites && !optionalAllSites && requiredCapabilities.length === 0 && optionalCapabilities.length === 0) return null;
	return { browserName, extensionName: extension.name, state: extension.state, requiredAllSites, optionalAllSites, requiredCapabilities, optionalCapabilities };
}

export function evaluateBrowserHardening(status: BrowserSecurityStatus | null): BrowserHardeningReview {
	if (!status || status.coverage === "unavailable") {
		return {
			outcome: "limited",
			title: "Hardening evidence unavailable",
			summary: "The reporter did not return enough supported browser evidence for this review.",
			checks: [], extensionCount: 0, requiredAllSitesCount: 0, optionalAllSitesCount: 0,
			higherAccessExtensions: [], meaningfulChangeCount: 0, coveragePartial: true,
		};
	}

	const checks = status.protections.map(evaluateProtection);
	const extensions = status.browsers.flatMap((browser) => browser.extensions.map((extension) => ({ browserName: browser.name, extension })));
	const higherAccessExtensions = extensions.map(({ browserName, extension }) => extensionExposure(browserName, extension)).filter((item): item is BrowserExtensionExposure => item !== null);
	const requiredAllSitesCount = extensions.filter(({ extension }) => extension.state !== "disabled" && extension.siteAccess === "all-sites").length;
	const optionalAllSitesCount = extensions.filter(({ extension }) => extension.state !== "disabled" && extension.optionalSiteAccess === "all-sites").length;
	const meaningfulChangeCount = status.changes?.length || 0;
	const needsReview = checks.some((check) => check.state === "review") || meaningfulChangeCount > 0;
	const coveragePartial = status.coverage === "partial" || checks.length === 0 || checks.some((check) => check.state === "unavailable");
	const outcome: BrowserHardeningOutcome = needsReview ? "review" : coveragePartial ? "limited" : "protected";
	const title = outcome === "review" ? "A concrete browser item needs review" : outcome === "limited" ? "Core evidence is partly unavailable" : "Core browser protections verified";
	const summary = outcome === "review"
		? "HAVEN observed a disabled or non-enforcing protection, verification evidence, or a meaningful extension change. Review the exact item below."
		: outcome === "limited"
			? "No concrete failure was reported, but HAVEN could not verify every supported hardening signal."
			: "No disabled supported protection, cookie-verification failure, or unexplained extension capability change was reported.";
	return { outcome, title, summary, checks, extensionCount: extensions.length, requiredAllSitesCount, optionalAllSitesCount, higherAccessExtensions, meaningfulChangeCount, coveragePartial };
}
