import { describe, expect, it } from "vitest";
import { accountSummary, dateInputValue, emptyAccountProfile, factorLabel, providerSessionURL, reviewedAtFromInput, sessionCheckLabel, statusLabel } from "./account-security";
import type { AccountProfile } from "./types";

function profile(overrides: Partial<AccountProfile> = {}): AccountProfile {
	return {
		...emptyAccountProfile(), id: "acct-test", provider: "Google", label: "Personal",
		status: "good", suggestions: [], createdAt: "2026-09-01T00:00:00Z", updatedAt: "2026-09-01T00:00:00Z",
		...overrides,
	};
}

describe("account security presentation", () => {
	it("summarizes owner-reported profiles without inventing alerts", () => {
		const summary = accountSummary([
			profile(),
			profile({ id: "attention", status: "attention", suggestions: [{ id: "mfa", priority: "high", title: "Enable two-step verification", summary: "Do so at the provider." }] }),
			profile({ id: "incomplete", status: "incomplete", suggestions: [{ id: "review", priority: "low", title: "Review", summary: "Check later." }] }),
		]);
		expect(summary).toEqual({ total: 3, good: 1, attention: 1, incomplete: 1, suggestions: 2 });
	});

	it("uses plain-language labels and stable date conversion", () => {
		expect(statusLabel("disabled")).toBe("Not enabled");
		expect(statusLabel("recognized")).toBe("All recognized");
		expect(factorLabel("security-key")).toBe("Security key");
		expect(sessionCheckLabel("third-party-access")).toBe("Third-party account access reviewed");
		expect(providerSessionURL(" Google ")).toBe("https://myaccount.google.com/device-activity");
		expect(providerSessionURL("Unknown provider")).toBeNull();
		expect(dateInputValue("2026-09-04T12:00:00Z")).toBe("2026-09-04");
		expect(dateInputValue("not-a-date")).toBe("");
		expect(reviewedAtFromInput("2026-09-04")).toBe("2026-09-04T12:00:00.000Z");
		expect(reviewedAtFromInput("")).toBeNull();
	});
});
