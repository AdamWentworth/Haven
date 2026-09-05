// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountNotebook } from "./account-notebook";
import { emptyAccountProfile } from "./account-security";
import type { AccountProfile } from "./types";

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});

function profile(overrides: Partial<AccountProfile> = {}): AccountProfile {
	return {
		...emptyAccountProfile(), id: "acct_test_profile", provider: "Google", label: "Personal",
		twoStepStatus: "disabled", passwordStatus: "unique", recoveryStatus: "configured", backupCodesStatus: "missing",
		status: "attention", suggestions: [{ id: "enable-two-step", priority: "high", title: "Enable two-step verification", summary: "Add a second factor at Google." }],
		createdAt: "2026-09-01T00:00:00Z", updatedAt: "2026-09-04T00:00:00Z", ...overrides,
	};
}

describe("account security notebook", () => {
	it("renders manual posture and separates suggestions from alerts", () => {
		const { container } = render(<AccountNotebook profiles={[profile({ reviewDetails: ["Signed-in devices reviewed; nothing unfamiliar."] })]} demoMode={false} unlocked busy={false} unlock={vi.fn()} lock={vi.fn()} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByRole("heading", { name: "Account readiness" })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Personal" })).toBeInTheDocument();
		expect(screen.getByText("Enable two-step verification")).toBeInTheDocument();
		expect(screen.getByText(/never threat alerts or push notifications/i)).toBeInTheDocument();
		expect(screen.getByText("Signed-in devices reviewed; nothing unfamiliar.")).toBeInTheDocument();
		expect(container.querySelector('[data-provider-brand="Google"] svg')).toBeInTheDocument();
	});

	it("keeps a healthy reviewed card concise", () => {
		render(<AccountNotebook profiles={[profile({ status: "good", suggestions: [], lastReviewedAt: "2026-09-04T12:00:00Z", sessionStatus: "recognized", sessionReviewedAt: "2026-09-04T12:00:00Z", sessionChecks: ["devices", "recent-activity", "third-party-access", "unused-sessions"] })]} demoMode={false} unlocked busy={false} unlock={vi.fn()} lock={vi.fn()} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByText("Checklist looks good")).toBeInTheDocument();
		expect(screen.getByText("All recognized")).toBeInTheDocument();
		expect(screen.getByText("Third-party account access reviewed")).toBeInTheDocument();
		expect(screen.getByRole("link", { name: /Review at Google/ })).toHaveAttribute("href", "https://myaccount.google.com/device-activity");
		expect(screen.getAllByText(/Reviewed Sep 4, 2026/)).toHaveLength(2);
		expect(screen.queryByText(/No improvement suggestion follows/)).not.toBeInTheDocument();
		expect(screen.queryByText(/5:00:00 AM/)).not.toBeInTheDocument();
	});

	it("does not render private profiles until the notebook is unlocked", async () => {
		const user = userEvent.setup();
		const unlock = vi.fn();
		render(<AccountNotebook profiles={[profile({ identifier: "owner@example.com" })]} demoMode={false} unlocked={false} busy={false} unlock={unlock} lock={vi.fn()} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByRole("heading", { name: "Unlock account details" })).toBeInTheDocument();
		expect(screen.queryByText("owner@example.com")).not.toBeInTheDocument();
		await user.click(screen.getByRole("button", { name: "Unlock with passkey" }));
		expect(unlock).toHaveBeenCalledOnce();
	});

	it("creates an account without offering any secret field", async () => {
		const user = userEvent.setup();
		const save = vi.fn().mockResolvedValue(true);
		render(<AccountNotebook profiles={[]} demoMode={false} unlocked busy={false} unlock={vi.fn()} lock={vi.fn()} save={save} remove={vi.fn()} />);
		await user.click(screen.getByRole("button", { name: "Add your first account" }));
		expect(screen.getByText(/Never paste a password/)).toBeInTheDocument();
		expect(screen.queryByLabelText(/^Password$/)).not.toBeInTheDocument();
		await user.type(screen.getByLabelText("Provider or platform"), "Google");
		await user.type(screen.getByLabelText("Profile label"), "Personal");
		await user.selectOptions(screen.getByLabelText("Two-step verification"), "enabled");
		await user.click(screen.getByLabelText("Authenticator app"));
		await user.selectOptions(screen.getByLabelText("Session status"), "recognized");
		await user.click(screen.getByLabelText("Signed-in devices and sessions reviewed"));
		expect(screen.getByRole("link", { name: /official session page/ })).toHaveAttribute("href", "https://myaccount.google.com/device-activity");
		expect(screen.getByText(/never signs in, reads cookies, or stores session tokens/i)).toBeInTheDocument();
		await user.click(screen.getByRole("button", { name: "Save profile" }));
		expect(save).toHaveBeenCalledWith(expect.objectContaining({ provider: "Google", label: "Personal", twoStepStatus: "enabled", factors: ["authenticator"], sessionStatus: "recognized", sessionChecks: ["devices"] }));
	});

	it("updates an account without resending derived presentation fields", async () => {
		const user = userEvent.setup();
		const save = vi.fn().mockResolvedValue(true);
		render(<AccountNotebook profiles={[profile()]} demoMode={false} unlocked busy={false} unlock={vi.fn()} lock={vi.fn()} save={save} remove={vi.fn()} />);
		await user.click(screen.getByRole("button", { name: "Edit" }));
		await user.clear(screen.getByLabelText("Sign-in or profile identifier optional"));
		await user.type(screen.getByLabelText("Sign-in or profile identifier optional"), "owner@example.com");
		await user.selectOptions(screen.getByLabelText("Category"), "email");
		await user.click(screen.getByRole("button", { name: "Save profile" }));
		expect(save).toHaveBeenCalledWith(expect.objectContaining({ id: "acct_test_profile", identifier: "owner@example.com", category: "email" }));
		const submitted = save.mock.calls[0][0] as Record<string, unknown>;
		expect(submitted).not.toHaveProperty("status");
		expect(submitted).not.toHaveProperty("suggestions");
		expect(submitted).not.toHaveProperty("createdAt");
		expect(submitted).not.toHaveProperty("updatedAt");
	});

	it("keeps synthetic portfolio profiles read-only", () => {
		render(<AccountNotebook profiles={[profile({ id: "acct_demo_profile" })]} demoMode unlocked={false} busy={false} unlock={vi.fn()} lock={vi.fn()} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByText(/Synthetic account notebook/)).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Add account" })).not.toBeInTheDocument();
	});

	it("keeps official provider navigation outside the isolated Electron client", () => {
		vi.spyOn(navigator, "userAgent", "get").mockReturnValue("Mozilla/5.0 HAVEN-Desktop/0.25.1 Electron");
		render(<AccountNotebook profiles={[profile({ sessionStatus: "recognized", sessionChecks: ["devices"] })]} demoMode={false} unlocked busy={false} unlock={vi.fn()} lock={vi.fn()} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.queryByRole("link", { name: /Review at Google/ })).not.toBeInTheDocument();
		expect(screen.getByText(/Desktop isolation blocks external navigation/)).toBeInTheDocument();
		expect(screen.getByText("https://myaccount.google.com/device-activity")).toBeInTheDocument();
	});
});
