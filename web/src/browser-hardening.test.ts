import { describe, expect, it } from "vitest";
import { evaluateBrowserHardening } from "./browser-hardening";
import type { BrowserExtension, BrowserSecurityStatus } from "./types";

const extension: BrowserExtension = {
	fingerprint: "0123456789abcdef01234567",
	name: "Example Helper",
	version: "1.0.0",
	state: "installed",
	profileCount: 1,
	siteAccess: "all-sites",
	optionalSiteAccess: "none-declared",
	sensitivePermissions: ["cookies", "tabs"],
	optionalSensitivePermissions: [],
};

function observed(): BrowserSecurityStatus {
	return {
		coverage: "observed",
		protections: [
			{ id: "defender-pua", name: "Potentially unwanted app protection", state: "enabled", source: "Microsoft Defender preferences" },
			{ id: "chrome-app-bound-encryption", name: "Chrome App-Bound Encryption policy", state: "default", source: "Chrome policy" },
			{ id: "chrome-device-bound-sessions", name: "Chrome device-bound Google sessions", state: "default", source: "Chrome policy" },
			{ id: "chrome-cookie-verification-events", name: "Chrome cookie-protection verification", state: "clear", source: "Windows Application event log", eventCount: 0 },
		],
		browsers: [{ id: "chrome", name: "Google Chrome", profileCount: 1, extensions: [extension], profiles: [] }],
	};
}

describe("browser hardening review", () => {
	it("treats enabled, clear, and browser-default protection evidence as verified", () => {
		const review = evaluateBrowserHardening(observed());
		expect(review.outcome).toBe("protected");
		expect(review.checks.every((check) => check.state === "verified")).toBe(true);
		expect(review.requiredAllSitesCount).toBe(1);
		expect(review.higherAccessExtensions[0]).toMatchObject({ extensionName: "Example Helper", requiredAllSites: true, requiredCapabilities: ["cookie access", "tabs"] });
	});

	it("requires review only for concrete protection evidence or a meaningful extension change", () => {
		for (const state of ["disabled", "audit"] as const) {
			const nonEnforcing = observed();
			nonEnforcing.protections[0] = { ...nonEnforcing.protections[0], state };
			expect(evaluateBrowserHardening(nonEnforcing)).toMatchObject({ outcome: "review", meaningfulChangeCount: 0 });
		}
		const verificationFailure = observed();
		verificationFailure.protections[3] = { ...verificationFailure.protections[3], state: "attention", eventCount: 1 };
		expect(evaluateBrowserHardening(verificationFailure).outcome).toBe("review");

		const changed = observed();
		changed.changes = [{ id: "abcdef0123456789abcdef01", browserId: "chrome", fingerprint: extension.fingerprint, extensionName: extension.name, kind: "permissions-expanded", siteAccess: "all-sites", addedPermissions: ["cookies"] }];
		expect(evaluateBrowserHardening(changed)).toMatchObject({ outcome: "review", meaningfulChangeCount: 1 });
	});

	it("keeps unknown evidence distinct from a failed protection", () => {
		const partial = observed();
		partial.protections[0] = { ...partial.protections[0], state: "unknown" };
		const review = evaluateBrowserHardening(partial);
		expect(review.outcome).toBe("limited");
		expect(review.checks[0]).toMatchObject({ state: "unavailable", label: "Not verified" });
	});

	it("does not let logged-in site hints or cookie volume affect the hardening result", () => {
		const empty = observed();
		const full = observed();
		full.browsers[0].profiles = [{
			fingerprint: "abcdef0123456789abcdef01",
			name: "Personal",
			cookieStatus: "observed",
			cookieCount: 999,
			sites: [{ domain: "accounts.example.com", cookieCount: 999, sessionCookieCount: 300, persistentCookieCount: 699, secureCookieCount: 999, httpOnlyCookieCount: 999 }],
		}];
		expect(evaluateBrowserHardening(full)).toEqual(evaluateBrowserHardening(empty));
	});

	it("does not describe declared extension capability as malicious behavior", () => {
		const review = evaluateBrowserHardening(observed());
		expect(JSON.stringify(review)).not.toMatch(/malicious|malware|threat/i);
	});

	it("separates optional access and excludes disabled extensions from active exposure", () => {
		const status = observed();
		status.browsers[0].extensions = [{ ...extension, siteAccess: "none-declared", optionalSiteAccess: "all-sites", sensitivePermissions: [], optionalSensitivePermissions: ["cookies"] }, { ...extension, fingerprint: "abcdef0123456789abcdef01", name: "Disabled Helper", state: "disabled" }];
		const review = evaluateBrowserHardening(status);
		expect(review).toMatchObject({ extensionCount: 2, requiredAllSitesCount: 0, optionalAllSitesCount: 1 });
		expect(review.higherAccessExtensions).toHaveLength(1);
		expect(review.higherAccessExtensions[0]).toMatchObject({ extensionName: "Example Helper", optionalAllSites: true, optionalCapabilities: ["cookie access"] });
	});
});
