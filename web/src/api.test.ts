// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import type { AccountProfileInput, BrowserSiteReviewInput, ExpectedService, ExpectedServiceInput } from "./types";

function response(body: unknown, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: vi.fn().mockResolvedValue(body),
	} as unknown as Response;
}

describe("HAVEN API client", () => {
	beforeEach(() => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response([])));
		document.cookie = "haven_csrf=test-token; path=/";
	});

	afterEach(() => vi.unstubAllGlobals());

	it("uses no-store reads and safely encodes identifiers", async () => {
		const signal = new AbortController().signal;
		await Promise.all([
			api.getLatestSnapshot(signal),
			api.listDevices(signal),
			api.listManagedAppliances(signal),
			api.listAccountProfiles("account-access", signal),
			api.listBrowserSiteReviews("device/one", signal),
			api.getDevice("device/one", signal),
			api.getRuntimeStatus(signal),
			api.listEvents("device one", signal),
			api.listAlerts(signal),
			api.getNotificationStatus(signal),
			api.getAuthStatus(signal),
			api.listPasskeys(signal),
			api.listFindingReviews("device/one", signal),
			api.listExpectedServices("device/one", signal),
			api.listObservedListeners("device/one", signal),
			api.listAuditEvents(signal),
			api.listSecurityActions(signal),
		]);

		const requests = vi.mocked(fetch).mock.calls;
		expect(requests).toHaveLength(17);
		expect(requests.every(([, options]) => options?.cache === "no-store" && options.signal === signal)).toBe(true);
		expect(requests.map(([url]) => url)).toContain("/api/devices/device%2Fone");
		expect(requests.map(([url]) => url)).toContain("/api/events?limit=60&deviceId=device+one");
		expect(requests.map(([url]) => url)).toContain("/api/browser-site-reviews?deviceId=device%2Fone");
		const accountRequest = requests.find(([url]) => url === "/api/account-profiles");
		expect(new Headers(accountRequest?.[1]?.headers).get("X-HAVEN-Account-Access")).toBe("account-access");
	});

	it("adds anti-forgery protection to mutations and supports empty responses", async () => {
		const fetchMock = vi.mocked(fetch);
		fetchMock.mockResolvedValue(response({}, 200));
		await api.registerPushDestination({ endpoint: "https://push.example.test/id", expirationTime: null, keys: { auth: "auth", p256dh: "key" } }, "Browser");
		await api.removePushDestination("https://push.example.test/id");
		await api.saveFindingReview({ deviceId: "device", findingId: "finding", state: "acknowledged", note: "reviewed", snoozedUntil: null });
		const browserReview = { deviceId: "device", browserId: "chrome", profileFingerprint: "abcdef0123456789abcdef01", domain: "example.test", state: "signed-in-keep" } as BrowserSiteReviewInput;
		await api.saveBrowserSiteReview(browserReview);
		await api.removeBrowserSiteReview(browserReview);
		const service = { deviceId: "device", protocol: "TCP", port: 443, portEnd: 443, bindScope: "private", label: "HTTPS" } as ExpectedServiceInput;
		await api.saveExpectedService(service);
		await api.saveExpectedServices("device", [service]);
		await api.removeExpectedService({ id: "service/one", deviceId: "device" } as ExpectedService);
		const account = { provider: "Google", label: "Personal", category: "email", twoStepStatus: "unknown", factors: [], passwordStatus: "unknown", recoveryStatus: "unknown", backupCodesStatus: "unknown", sessionStatus: "unknown", sessionChecks: [] } as AccountProfileInput;
		await api.saveAccountProfile(account, "account-access");
		await api.removeAccountProfile("account/one", "account-access");
		await api.touchAccountNotebook("account-access");
		await api.lockAccountNotebook("account-access");

		for (const [, options] of fetchMock.mock.calls) {
			expect(options?.method).toBe("POST");
			expect(new Headers(options?.headers).get("X-HAVEN-CSRF")).toBe("test-token");
			expect(options?.credentials).toBe("same-origin");
		}
		const accountMutations = fetchMock.mock.calls.filter(([url]) => String(url).startsWith("/api/account-"));
		expect(accountMutations.every(([, options]) => new Headers(options?.headers).get("X-HAVEN-Account-Access") === "account-access")).toBe(true);
		expect(fetchMock.mock.calls.map(([url]) => url)).toContain("/api/expected-services/service%2Fone/remove");
		expect(fetchMock.mock.calls.map(([url]) => url)).toContain("/api/account-profiles/account%2Fone/remove");
		expect(fetchMock.mock.calls.map(([url]) => url)).toContain("/api/browser-site-reviews/remove");

		fetchMock.mockResolvedValueOnce(response(null, 204));
		await expect(api.logout()).resolves.toBeUndefined();
	});

	it("surfaces both structured mutation failures and read failures", async () => {
		vi.mocked(fetch).mockResolvedValueOnce(response({ error: "Owner confirmation expired." }, 403));
		await expect(api.saveFindingReview({ deviceId: "device", findingId: "finding", state: "acknowledged", note: "", snoozedUntil: null })).rejects.toThrow("Owner confirmation expired.");

		vi.mocked(fetch).mockResolvedValueOnce(response({}, 503));
		await expect(api.listDevices()).rejects.toThrow("HTTP 503");
	});

	it("collects a fresh snapshot through the protected mutation endpoint", async () => {
		vi.mocked(fetch).mockResolvedValueOnce(response({ collectedAt: "2026-09-04T08:00:00Z" }));
		await api.collectSnapshot();
		const [url, options] = vi.mocked(fetch).mock.calls[0];
		expect(url).toBe("/api/security/snapshot");
		expect(options?.method).toBe("POST");
		expect(new Headers(options?.headers).get("X-HAVEN-CSRF")).toBe("test-token");
	});

	it("converts a passkey assertion to the hub's portable JSON contract", async () => {
		class TestAssertionResponse {
			authenticatorData = Uint8Array.from([1]).buffer;
			clientDataJSON = Uint8Array.from([2]).buffer;
			signature = Uint8Array.from([3]).buffer;
			userHandle = null;
		}
		class TestCredential {
			id = "credential-id";
			rawId = Uint8Array.from([4]).buffer;
			type = "public-key";
			response = new TestAssertionResponse();
			getClientExtensionResults() { return {}; }
		}
		vi.stubGlobal("AuthenticatorAssertionResponse", TestAssertionResponse);
		vi.stubGlobal("PublicKeyCredential", TestCredential);
		Object.defineProperty(navigator, "credentials", { configurable: true, value: { get: vi.fn().mockResolvedValue(new TestCredential()) } });
		vi.mocked(fetch)
			.mockResolvedValueOnce(response({ ceremonyId: "ceremony", publicKey: { challenge: "AQ", allowCredentials: [{ id: "Ag", type: "public-key" }] } }))
			.mockResolvedValueOnce(response({ authenticated: true }));

		await expect(api.loginWithPasskey()).resolves.toEqual({ authenticated: true });
		const [, finish] = vi.mocked(fetch).mock.calls[1];
		expect(new Headers(finish?.headers).get("X-HAVEN-Ceremony")).toBe("ceremony");
		expect(JSON.parse(String(finish?.body))).toMatchObject({ id: "credential-id", rawId: "BA", response: { authenticatorData: "AQ", signature: "Aw", userHandle: null } });
	});

	it("uses fresh passkey reauthorization to unlock the private account scope", async () => {
		class TestAssertionResponse {
			authenticatorData = Uint8Array.from([1]).buffer;
			clientDataJSON = Uint8Array.from([2]).buffer;
			signature = Uint8Array.from([3]).buffer;
			userHandle = null;
		}
		class TestCredential {
			id = "credential-id";
			rawId = Uint8Array.from([4]).buffer;
			type = "public-key";
			response = new TestAssertionResponse();
			getClientExtensionResults() { return {}; }
		}
		vi.stubGlobal("AuthenticatorAssertionResponse", TestAssertionResponse);
		vi.stubGlobal("PublicKeyCredential", TestCredential);
		Object.defineProperty(navigator, "credentials", { configurable: true, value: { get: vi.fn().mockResolvedValue(new TestCredential()) } });
		const access = { token: "account-access", expiresAt: "2026-09-04T18:15:00Z", absoluteExpiresAt: "2026-09-05T02:00:00Z", idleTimeoutSeconds: 900 };
		vi.mocked(fetch)
			.mockResolvedValueOnce(response({ ceremonyId: "reauth-ceremony", publicKey: { challenge: "AQ", allowCredentials: [{ id: "Ag", type: "public-key" }] } }))
			.mockResolvedValueOnce(response({ reauthorizationToken: "single-use-grant" }))
			.mockResolvedValueOnce(response(access));

		await expect(api.unlockAccountNotebook()).resolves.toEqual(access);
		const calls = vi.mocked(fetch).mock.calls;
		expect(calls.map(([url]) => url)).toEqual(["/api/auth/reauthorize/begin", "/api/auth/reauthorize/finish", "/api/account-access/unlock"]);
		expect(JSON.parse(String(calls[0][1]?.body))).toEqual({ scope: "account-notebook:unlock" });
		expect(new Headers(calls[2][1]?.headers).get("X-HAVEN-Reauthorization")).toBe("single-use-grant");
	});
});
