import type { BrowserCookieSite } from "./types";

export type CookieSiteFilter = "all" | "session-signals" | "cleanup";
export type CookieSiteSort = "session-signals" | "cleanup" | "recent" | "cookie-count" | "domain";
export type CookieSessionSignalLevel = "stronger" | "possible" | "limited";

export interface CookieSessionSignal {
	level: CookieSessionSignalLevel;
	label: string;
	rank: number;
}

export interface CookieAgeReview {
	candidate: boolean;
	label: string;
	state: "recent" | "dormant" | "unknown";
}

const dormantCookieAge = 90 * 24 * 60 * 60 * 1000;

function cookieTimestamp(value?: string) {
	if (!value) return null;
	const timestamp = new Date(value).getTime();
	return Number.isFinite(timestamp) ? timestamp : null;
}

export function cookieSiteReview(site: BrowserCookieSite, now = Date.now()): CookieAgeReview {
	const timestamp = cookieTimestamp(site.lastAccessedAt);
	if (timestamp === null) return { candidate: true, label: "Review date unavailable", state: "unknown" };
	if (now - timestamp >= dormantCookieAge) return { candidate: true, label: "No access 90+ days", state: "dormant" };
	return { candidate: false, label: "Recently accessed", state: "recent" };
}

export function cookieSessionSignal(site: BrowserCookieSite): CookieSessionSignal {
	const protectedCookiePresent = site.secureCookieCount > 0 && site.httpOnlyCookieCount > 0;
	if (site.sessionCookieCount > 0 && protectedCookiePresent) {
		return { level: "stronger", label: "Stronger session signal", rank: 3 };
	}
	if (protectedCookiePresent) {
		return { level: "possible", label: "Possible session signal", rank: 2 };
	}
	return { level: "limited", label: "Limited session signal", rank: 1 };
}

export function filterCookieSites(sites: BrowserCookieSite[], filter: CookieSiteFilter, now = Date.now()) {
	if (filter === "session-signals") return sites.filter((site) => cookieSessionSignal(site).level !== "limited");
	if (filter === "cleanup") return sites.filter((site) => cookieSiteReview(site, now).candidate);
	return [...sites];
}

export function sortCookieSites(sites: BrowserCookieSite[], sort: CookieSiteSort, now = Date.now()) {
	return [...sites].sort((left, right) => {
		if (sort === "domain") return left.domain.localeCompare(right.domain);
		if (sort === "cookie-count") return right.cookieCount - left.cookieCount || left.domain.localeCompare(right.domain);

		const leftTimestamp = cookieTimestamp(left.lastAccessedAt);
		const rightTimestamp = cookieTimestamp(right.lastAccessedAt);
		if (sort === "recent") {
			return (rightTimestamp ?? Number.NEGATIVE_INFINITY) - (leftTimestamp ?? Number.NEGATIVE_INFINITY) || left.domain.localeCompare(right.domain);
		}
		if (sort === "cleanup") {
			const leftReview = cookieSiteReview(left, now);
			const rightReview = cookieSiteReview(right, now);
			if (leftReview.candidate !== rightReview.candidate) return leftReview.candidate ? -1 : 1;
			return (leftTimestamp ?? Number.NEGATIVE_INFINITY) - (rightTimestamp ?? Number.NEGATIVE_INFINITY) || left.domain.localeCompare(right.domain);
		}

		const signalDifference = cookieSessionSignal(right).rank - cookieSessionSignal(left).rank;
		return signalDifference || (rightTimestamp ?? Number.NEGATIVE_INFINITY) - (leftTimestamp ?? Number.NEGATIVE_INFINITY) || right.cookieCount - left.cookieCount || left.domain.localeCompare(right.domain);
	});
}
