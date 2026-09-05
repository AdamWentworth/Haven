// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserSecurityPanel } from "./browser-security";
import type { BrowserSecurityStatus } from "./types";

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});

const observed: BrowserSecurityStatus = {
	coverage: "observed",
	protections: [
		{ id: "defender-pua", name: "Potentially unwanted app protection", state: "enabled", source: "Microsoft Defender preferences" },
		{ id: "defender-network", name: "Defender Network Protection", state: "audit", source: "Microsoft Defender preferences" },
		{ id: "chrome-app-bound-encryption", name: "Chrome App-Bound Encryption policy", state: "default", source: "Chrome policy" },
		{ id: "chrome-cookie-verification-events", name: "Chrome cookie-protection verification", state: "attention", source: "Windows Application event log", eventCount: 2 },
	],
	changes: [{ id: "abcdef0123456789abcdef01", browserId: "chrome", fingerprint: "0123456789abcdef01234567", extensionName: "Password Helper", kind: "permissions-expanded", siteAccess: "all-sites", addedPermissions: ["cookies"] }],
	browsers: [{
		id: "chrome",
		name: "Google Chrome",
		version: "140.0.1",
		profileCount: 2,
		profiles: [{
			fingerprint: "abcdef0123456789abcdef01",
			name: "Personal",
			cookieStatus: "observed",
			cookieCount: 3,
			sites: [
				{ domain: "facebook.com", cookieCount: 2, sessionCookieCount: 1, persistentCookieCount: 1, secureCookieCount: 2, httpOnlyCookieCount: 2, lastAccessedAt: "2020-01-01T00:00:00Z", latestExpiryAt: "2027-01-01T00:00:00Z" },
				{ domain: "recent.example.com", cookieCount: 1, sessionCookieCount: 0, persistentCookieCount: 1, secureCookieCount: 1, httpOnlyCookieCount: 1, lastAccessedAt: "2026-09-04T00:00:00Z", latestExpiryAt: "2027-01-01T00:00:00Z" },
			],
		}, {
			fingerprint: "fedcba9876543210fedcba98",
			name: "Work",
			cookieStatus: "unavailable",
			cookieCount: 0,
			sites: [],
		}],
		extensions: [{
			fingerprint: "0123456789abcdef01234567",
			name: "Password Helper",
			version: "1.2.3",
			state: "installed",
			profileCount: 2,
			siteAccess: "all-sites",
			optionalSiteAccess: "specific-sites",
			sensitivePermissions: ["cookies", "history"],
			optionalSensitivePermissions: ["downloads"],
		}],
	}],
};

describe("browser security panel", () => {
	it("explains privacy-reduced browser and extension capability evidence", async () => {
		render(<BrowserSecurityPanel status={observed} />);
		expect(screen.getByRole("heading", { name: "Browser security" })).toBeInTheDocument();
		expect(screen.getByText("Google Chrome")).toBeInTheDocument();
		expect(screen.getByText("Password Helper")).toBeInTheDocument();
		expect(screen.getAllByText("All sites").length).toBeGreaterThan(0);
		expect(screen.getByText("Cookies")).toBeInTheDocument();
		expect(screen.getByText("Downloads · optional")).toBeInTheDocument();
		expect(screen.getByText("Audit only")).toBeInTheDocument();
		expect(screen.getByText("Browser default")).toBeInTheDocument();
		expect(screen.getByText("Review evidence")).toBeInTheDocument();
		expect(screen.getByText(/2 Chrome verification events observed/)).toBeInTheDocument();
		expect(screen.getByText("Password Helper gained capabilities")).toBeInTheDocument();
		expect(screen.getByText("Chrome profile site data")).toBeInTheDocument();
		expect(screen.getByText("Personal")).toBeInTheDocument();
		expect(screen.getByText("facebook.com")).toBeInTheDocument();
		expect(screen.getByText("No access 90+ days")).toBeInTheDocument();
		expect(screen.getByText("Work")).toBeInTheDocument();
		expect(screen.getByText("Unavailable this run")).toBeInTheDocument();
		expect(screen.getByText(/collection limitation—not a security problem/i)).toBeInTheDocument();
		expect(screen.getByText(/cookie presence cannot prove that a provider session is authenticated/i)).toBeInTheDocument();
		expect(screen.getByText(/never selects or transmits cookie names, values, encrypted values, paths/i)).toBeInTheDocument();
		expect(document.body).not.toHaveTextContent("0123456789abcdef01234567");
		expect(document.body).not.toHaveTextContent("private-session-token");
		const result = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
		expect(result.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious")).toEqual([]);
	});

	it("distinguishes unavailable evidence from a security failure", () => {
		render(<BrowserSecurityPanel status={{ coverage: "unavailable", browsers: [], protections: [] }} />);
		expect(screen.getByText("Browser inventory is unavailable.")).toBeInTheDocument();
		expect(screen.getByText(/could not verify supported browser metadata/i)).toBeInTheDocument();
	});

	it("filters a profile to conservative cleanup candidates without calling them authenticated sessions", async () => {
		vi.spyOn(Date, "now").mockReturnValue(new Date("2026-09-04T00:01:00Z").getTime());
		const user = userEvent.setup();
		render(<BrowserSecurityPanel status={observed} />);
		expect(screen.getByText("recent.example.com")).toBeInTheDocument();
		await user.selectOptions(screen.getByRole("combobox", { name: "Show" }), "cleanup");
		expect(screen.getByText("facebook.com")).toBeInTheDocument();
		expect(screen.queryByText("recent.example.com")).not.toBeInTheDocument();
		expect(screen.getByRole("combobox", { name: "Sort by" })).toHaveValue("session-signals");
		expect(screen.getByText(/neither proves that you are currently signed in/i)).toBeInTheDocument();
	});
});
