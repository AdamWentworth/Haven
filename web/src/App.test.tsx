// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import axe from "axe-core";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import type { AuthStatus, DeviceRecord, RuntimeStatus, SecuritySnapshot } from "./types";

const fixtures = vi.hoisted(() => {
	const device: DeviceRecord = {
		id: "device-a",
		displayName: "ADAM-TEST",
		hostName: "adam-test",
		operatingSystem: "Microsoft Windows 10 Pro",
		architecture: "amd64",
		trustState: "enrolled",
		status: "current",
		enrolledAt: "2026-09-01T00:00:00Z",
		lastSeenAt: "2026-09-04T08:00:00Z",
		lastCollectedAt: "2026-09-04T08:00:00Z",
		certificateExpiresAt: "2027-09-01T00:00:00Z",
		revokedAt: null,
		agent: { schemaVersion: 2, version: "0.15.0", revision: "test-revision", platform: "windows", installation: "windows-task", capabilities: ["host-firewall", "network-observation", "windows-defender", "windows-posture"], collectionNotices: 0, compatibility: "current" },
	};
	const snapshot: SecuritySnapshot = {
		collectedAt: "2026-09-04T08:00:00Z",
		device: { deviceId: device.id, hostName: device.hostName, operatingSystem: device.operatingSystem, architecture: device.architecture, uptimeSeconds: 3600 },
		defender: { antivirusEnabled: true, realTimeProtectionEnabled: true, behaviorMonitorEnabled: true, downloadProtectionEnabled: true, tamperProtected: true, signatureUpdatedAt: "2026-09-04T07:00:00Z", lastQuickScanAt: null, lastFullScanAt: null },
		windowsBaseline: null,
		linuxBaseline: null,
		browserSecurity: {
			coverage: "observed",
			protections: [{ id: "defender-pua", name: "Potentially unwanted app protection", state: "enabled", source: "Microsoft Defender preferences" }],
			browsers: [{ id: "chrome", name: "Google Chrome", version: "140", profileCount: 1, extensions: [] }],
		},
		baselineChecks: [{ id: "defender", category: "Protection", title: "Microsoft Defender", status: "pass", summary: "Protection is active." }],
		findings: [],
		firewallProfiles: [{ name: "Private", enabled: true }],
		connections: [],
		notices: [],
	};
	const auth: AuthStatus = { configured: true, authenticated: true, origin: "https://haven.example.test", useConfiguredOrigin: false };
	const runtime: RuntimeStatus = {
		status: "ready",
		service: "HAVEN",
		version: "0.15.0",
		revision: "test-revision",
		agentIngestion: "mutual-tls",
		demoMode: false,
		localCollection: false,
		deviceFreshnessAllowanceSeconds: 35 * 60,
		actionCapabilities: [],
		monitor: { enabled: false, intervalSeconds: 0, lastAttemptAt: null, lastSuccessfulAt: null },
		timestamp: "2026-09-04T08:00:00Z",
	};
	return { auth, device, runtime, snapshot };
});

const api = vi.hoisted(() => ({
	HavenAPIError: class HavenAPIError extends Error { constructor(message: string, readonly status: number) { super(message); } },
	addPasskey: vi.fn(), collectSnapshot: vi.fn(), getAuthStatus: vi.fn(), getDevice: vi.fn(), getLatestSnapshot: vi.fn(), getNotificationStatus: vi.fn(), getRuntimeStatus: vi.fn(), listAccountProfiles: vi.fn(), listAlerts: vi.fn(), listAuditEvents: vi.fn(), listDevices: vi.fn(), listEvents: vi.fn(), listExpectedServices: vi.fn(), listFindingReviews: vi.fn(), listManagedAppliances: vi.fn(), listObservedListeners: vi.fn(), listPasskeys: vi.fn(), listSecurityActions: vi.fn(), lockAccountNotebook: vi.fn(), loginWithPasskey: vi.fn(), logout: vi.fn(), registerPasskey: vi.fn(), registerPushDestination: vi.fn(), removeAccountProfile: vi.fn(), removeExpectedService: vi.fn(), removePasskey: vi.fn(), removePushDestination: vi.fn(), requestSecurityAction: vi.fn(), saveAccountProfile: vi.fn(), saveExpectedService: vi.fn(), saveExpectedServices: vi.fn(), saveFindingReview: vi.fn(), touchAccountNotebook: vi.fn(), unlockAccountNotebook: vi.fn(), revokeDevice: vi.fn(),
}));

vi.mock("./api", () => api);

beforeEach(() => {
	window.history.replaceState(null, "", "/");
	Object.defineProperty(window, "scrollTo", { value: vi.fn(), configurable: true });
	api.getAuthStatus.mockResolvedValue(fixtures.auth);
	api.listDevices.mockResolvedValue([fixtures.device]);
	api.getRuntimeStatus.mockResolvedValue(fixtures.runtime);
	api.listEvents.mockResolvedValue([]);
	api.listAlerts.mockResolvedValue([]);
	api.getNotificationStatus.mockResolvedValue({ available: false, vapidPublicKey: "", destinations: [], pendingCount: 0, failedCount: 0, lastSuccessAt: null, lastFailureAt: null, evaluationPeriodSeconds: 60 });
	api.listManagedAppliances.mockResolvedValue([]);
	api.listAccountProfiles.mockResolvedValue([]);
	api.unlockAccountNotebook.mockResolvedValue({ token: "account-access", expiresAt: "2026-09-04T08:15:00Z", absoluteExpiresAt: "2026-09-04T16:00:00Z", idleTimeoutSeconds: 900 });
	api.touchAccountNotebook.mockResolvedValue({ token: "account-access", expiresAt: "2026-09-04T08:15:00Z", absoluteExpiresAt: "2026-09-04T16:00:00Z", idleTimeoutSeconds: 900 });
	api.lockAccountNotebook.mockResolvedValue(undefined);
	api.getDevice.mockResolvedValue({ device: fixtures.device, snapshot: fixtures.snapshot });
	api.listExpectedServices.mockResolvedValue([]);
	api.listObservedListeners.mockResolvedValue([]);
	api.listFindingReviews.mockResolvedValue([]);
	api.listAuditEvents.mockResolvedValue([]);
	api.listSecurityActions.mockResolvedValue([]);
	api.listPasskeys.mockResolvedValue([{ id: "passkey-a", label: "Test passkey", createdAt: "2026-09-01T00:00:00Z", lastUsedAt: null }]);
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

describe("HAVEN routed console", () => {
	it("moves from the concise overview into a device and its posture without reloading", async () => {
		const user = userEvent.setup();
		render(<App />);

		expect(await screen.findByRole("heading", { name: "Home security overview" })).toBeInTheDocument();
		expect(screen.queryByRole("heading", { name: "Owner passkeys" })).not.toBeInTheDocument();
		expect(screen.getByLabelText("Agent hub")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Refresh HAVEN view" })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Lock HAVEN" })).toBeInTheDocument();

		await user.click(screen.getByRole("link", { name: "Devices" }));
		expect(await screen.findByRole("heading", { name: "Devices", level: 1 })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Agent lifecycle" })).toBeInTheDocument();
		expect(screen.getByText("exact build verified")).toBeInTheDocument();
		expect(window.location.pathname).toBe("/devices");

		await user.click(screen.getByRole("button", { name: /ADAM-TEST/ }));
		expect(await screen.findByRole("heading", { name: "ADAM-TEST" })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Agent evidence" })).toBeInTheDocument();
		expect(screen.getByText("Windows scheduled task")).toBeInTheDocument();
		expect(window.location.pathname).toBe("/devices/device-a/overview");

		await user.click(screen.getByRole("link", { name: "Posture" }));
		expect(await screen.findByRole("heading", { name: "Posture checks" })).toBeInTheDocument();
		expect(window.location.pathname).toBe("/devices/device-a/posture");

		await user.click(screen.getByRole("link", { name: "Browsers" }));
		expect(await screen.findByRole("heading", { name: "Browser security" })).toBeInTheDocument();
		expect(screen.getByText("Google Chrome")).toBeInTheDocument();
		expect(window.location.pathname).toBe("/devices/device-a/browsers");
	});

	it("keeps owner credentials on the dedicated settings page", async () => {
		const user = userEvent.setup();
		render(<App />);
		await screen.findByRole("heading", { name: "Home security overview" });

		await user.click(screen.getByRole("link", { name: "Settings" }));
		expect(await screen.findByRole("heading", { name: "Owner passkeys" })).toBeInTheDocument();
		expect(document.title).toBe("Settings — HAVEN");
		expect(screen.getByRole("heading", { name: "Install HAVEN" })).toBeInTheDocument();
		expect(screen.getByText(/no privileged local service/i)).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Background alerts" })).toBeInTheDocument();
		expect(screen.getByText("0.15.0")).toBeInTheDocument();
		expect(window.location.pathname).toBe("/settings");
	});

	it("opens the private account-security notebook as a dedicated workspace", async () => {
		const user = userEvent.setup();
		render(<App />);
		await screen.findByRole("heading", { name: "Home security overview" });
		await user.click(screen.getByRole("link", { name: "Accounts" }));
		expect(await screen.findByRole("heading", { name: "Accounts", level: 1 })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Unlock account details" })).toBeInTheDocument();
		expect(api.listAccountProfiles).not.toHaveBeenCalled();
		await user.click(screen.getByRole("button", { name: "Unlock with passkey" }));
		expect(screen.getByRole("heading", { name: "Account readiness" })).toBeInTheDocument();
		expect(screen.getByText(/Owner-reported, not provider-verified/)).toBeInTheDocument();
		expect(api.listAccountProfiles).toHaveBeenCalledWith("account-access");
		expect(window.location.pathname).toBe("/accounts");
	});

	it("honors a directly addressed device history route", async () => {
		window.history.replaceState(null, "", "/devices/device-a/history");
		render(<App />);

		expect(await screen.findByRole("heading", { name: "ADAM-TEST" })).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "History" })).toHaveAttribute("aria-current", "page");
		await waitFor(() => expect(api.getDevice).toHaveBeenCalledWith("device-a", expect.any(AbortSignal)));
	});

	it("has no automatically detectable critical accessibility violations on the overview", async () => {
		render(<App />);
		expect(await screen.findByRole("heading", { name: "Home security overview" })).toBeInTheDocument();
		const result = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
		expect(result.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious")).toEqual([]);
	});
});
