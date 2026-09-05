import { describe, expect, it } from "vitest";
import { buildCookieCleanupQueue, cookieSessionSignal, cookieSiteReview, filterCookieSites, groupCookieSites, sortCookieSites } from "./cookie-review";
import type { BrowserCookieSite } from "./types";

function site(domain: string, overrides: Partial<BrowserCookieSite> = {}): BrowserCookieSite {
	return {
		domain,
		cookieCount: 1,
		sessionCookieCount: 0,
		persistentCookieCount: 1,
		secureCookieCount: 0,
		httpOnlyCookieCount: 0,
		lastAccessedAt: "2026-09-01T00:00:00Z",
		...overrides,
	};
}

const now = new Date("2026-09-05T00:00:00Z").getTime();

describe("cookie review evidence", () => {
	it("uses only aggregate attributes for conservative session-signal tiers", () => {
		expect(cookieSessionSignal(site("strong.example", { sessionCookieCount: 1, secureCookieCount: 1, httpOnlyCookieCount: 1 })).level).toBe("stronger");
		expect(cookieSessionSignal(site("possible.example", { secureCookieCount: 1, httpOnlyCookieCount: 1 })).level).toBe("possible");
		expect(cookieSessionSignal(site("limited.example", { secureCookieCount: 1 })).level).toBe("limited");
	});

	it("keeps age-based cleanup review separate from session relevance", () => {
		const oldProtected = site("old.example", { sessionCookieCount: 1, secureCookieCount: 1, httpOnlyCookieCount: 1, lastAccessedAt: "2026-01-01T00:00:00Z" });
		expect(cookieSessionSignal(oldProtected).level).toBe("stronger");
		expect(cookieSiteReview(oldProtected, now)).toMatchObject({ candidate: true, state: "dormant" });
	});

	it("filters and sorts without mutating the collected evidence", () => {
		const original = [
			site("limited.example", { cookieCount: 50 }),
			site("possible.example", { secureCookieCount: 1, httpOnlyCookieCount: 1 }),
			site("strong.example", { sessionCookieCount: 1, secureCookieCount: 1, httpOnlyCookieCount: 1 }),
		];
		const snapshot = [...original];
		expect(filterCookieSites(original, "session-signals", now).map((entry) => entry.domain)).toEqual(["possible.example", "strong.example"]);
		expect(sortCookieSites(original, "session-signals", now).map((entry) => entry.domain)).toEqual(["strong.example", "possible.example", "limited.example"]);
		expect(original).toEqual(snapshot);
	});

	it("automatically groups every site without requiring a search query", () => {
		const groups = groupCookieSites([
			site("limited.example"),
			site("strong.example", { sessionCookieCount: 1, secureCookieCount: 1, httpOnlyCookieCount: 1 }),
			site("possible.example", { secureCookieCount: 1, httpOnlyCookieCount: 1 }),
		]);
		expect(groups.map((group) => [group.level, group.sites.map((entry) => entry.domain)])).toEqual([
			["stronger", ["strong.example"]],
			["possible", ["possible.example"]],
			["limited", ["limited.example"]],
		]);
	});

	it("puts unknown and oldest evidence first for cleanup review", () => {
		const sorted = sortCookieSites([
			site("recent.example"),
			site("old.example", { lastAccessedAt: "2025-01-01T00:00:00Z" }),
			site("unknown.example", { lastAccessedAt: undefined }),
		], "cleanup", now);
		expect(sorted.map((entry) => entry.domain)).toEqual(["unknown.example", "old.example", "recent.example"]);
	});

	it("excludes protected and deferred sites while prioritizing deliberate cleanup choices", () => {
		const queue = buildCookieCleanupQueue([
			site("protected.example", { lastAccessedAt: "2025-01-01T00:00:00Z" }),
			site("deferred.example", { lastAccessedAt: "2025-01-01T00:00:00Z" }),
			site("ready.example"),
			site("old.example", { lastAccessedAt: "2025-01-01T00:00:00Z" }),
			site("recent.example"),
		], {
			"protected.example": "signed-in-keep",
			"deferred.example": "review-later",
			"ready.example": "clear-candidate",
		}, now);
		expect(queue.ready.map((entry) => entry.domain)).toEqual(["ready.example"]);
		expect(queue.suggested.map((entry) => entry.domain)).toEqual(["old.example"]);
	});
});
