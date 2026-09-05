// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it } from "vitest";
import { BrowserSecurityPanel } from "./browser-security";
import type { BrowserSecurityStatus } from "./types";

afterEach(cleanup);

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
		expect(screen.getByText("All sites")).toBeInTheDocument();
		expect(screen.getByText("Cookies")).toBeInTheDocument();
		expect(screen.getByText("Downloads · optional")).toBeInTheDocument();
		expect(screen.getByText("Audit only")).toBeInTheDocument();
		expect(screen.getByText("Browser default")).toBeInTheDocument();
		expect(screen.getByText("Review evidence")).toBeInTheDocument();
		expect(screen.getByText(/2 Chrome verification events observed/)).toBeInTheDocument();
		expect(screen.getByText("Password Helper gained capabilities")).toBeInTheDocument();
		expect(screen.getByText(/routine inventory stays live-only/i)).toBeInTheDocument();
		expect(screen.getByText(/do not enumerate provider sessions or inspect cookie contents/i)).toBeInTheDocument();
		expect(screen.getByText(/never reads or stores cookies, history, passwords/i)).toBeInTheDocument();
		expect(document.body).not.toHaveTextContent("0123456789abcdef01234567");
		const result = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
		expect(result.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious")).toEqual([]);
	});

	it("distinguishes unavailable evidence from a security failure", () => {
		render(<BrowserSecurityPanel status={{ coverage: "unavailable", browsers: [], protections: [] }} />);
		expect(screen.getByText("Browser inventory is unavailable.")).toBeInTheDocument();
		expect(screen.getByText(/could not verify supported browser metadata/i)).toBeInTheDocument();
	});
});
