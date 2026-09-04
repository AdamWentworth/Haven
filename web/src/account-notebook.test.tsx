// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountNotebook } from "./account-notebook";
import { emptyAccountProfile } from "./account-security";
import type { AccountProfile } from "./types";

afterEach(cleanup);

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
		render(<AccountNotebook profiles={[profile()]} demoMode={false} busy={false} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByRole("heading", { name: "Account readiness" })).toBeInTheDocument();
		expect(screen.getByRole("heading", { name: "Personal" })).toBeInTheDocument();
		expect(screen.getByText("Enable two-step verification")).toBeInTheDocument();
		expect(screen.getByText(/never threat alerts or push notifications/i)).toBeInTheDocument();
	});

	it("creates an account without offering any secret field", async () => {
		const user = userEvent.setup();
		const save = vi.fn().mockResolvedValue(true);
		render(<AccountNotebook profiles={[]} demoMode={false} busy={false} save={save} remove={vi.fn()} />);
		await user.click(screen.getByRole("button", { name: "Add your first account" }));
		expect(screen.getByText(/Never paste a password/)).toBeInTheDocument();
		expect(screen.queryByLabelText(/^Password$/)).not.toBeInTheDocument();
		await user.type(screen.getByLabelText("Provider or platform"), "Google");
		await user.type(screen.getByLabelText("Profile label"), "Personal");
		await user.selectOptions(screen.getByLabelText("Two-step verification"), "enabled");
		await user.click(screen.getByLabelText("Authenticator app"));
		await user.click(screen.getByRole("button", { name: "Save profile" }));
		expect(save).toHaveBeenCalledWith(expect.objectContaining({ provider: "Google", label: "Personal", twoStepStatus: "enabled", factors: ["authenticator"] }));
	});

	it("updates an account without resending derived presentation fields", async () => {
		const user = userEvent.setup();
		const save = vi.fn().mockResolvedValue(true);
		render(<AccountNotebook profiles={[profile()]} demoMode={false} busy={false} save={save} remove={vi.fn()} />);
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
		render(<AccountNotebook profiles={[profile({ id: "acct_demo_profile" })]} demoMode busy={false} save={vi.fn()} remove={vi.fn()} />);
		expect(screen.getByText(/Synthetic account notebook/)).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Add account" })).not.toBeInTheDocument();
	});
});
