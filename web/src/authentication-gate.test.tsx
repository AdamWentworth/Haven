// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthenticationGate } from "./authentication-gate";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe("owner authentication gate", () => {
	it("redirects passkey ceremonies to the configured trusted origin", () => {
		render(<AuthenticationGate status={{ configured: true, authenticated: false, origin: "https://haven.example.test", useConfiguredOrigin: true }} authenticate={vi.fn()} />);
		expect(screen.getByRole("link", { name: "Continue to https://haven.example.test" })).toHaveAttribute("href", "https://haven.example.test");
	});

	it("explains when a browser cannot use passkeys", () => {
		render(<AuthenticationGate status={{ configured: false, authenticated: false, origin: "https://haven.example.test", useConfiguredOrigin: false }} authenticate={vi.fn()} />);
		expect(screen.getByRole("alert")).toHaveTextContent("does not expose the passkey APIs");
		expect(screen.getByRole("button", { name: "Create HAVEN passkey" })).toBeDisabled();
	});

	it("submits a trimmed one-time code and owner-selected label", async () => {
		vi.stubGlobal("PublicKeyCredential", class {});
		Object.defineProperty(navigator, "credentials", { configurable: true, value: {} });
		const authenticate = vi.fn().mockResolvedValue(undefined);
		const user = userEvent.setup();
		render(<AuthenticationGate status={{ configured: false, authenticated: false, origin: "https://haven.example.test", useConfiguredOrigin: false }} authenticate={authenticate} />);
		await user.clear(screen.getByLabelText("Passkey label"));
		await user.type(screen.getByLabelText("Passkey label"), " ADAM-PC ");
		await user.type(screen.getByLabelText("One-time enrollment code"), " enroll-code ");
		await user.click(screen.getByRole("button", { name: "Create HAVEN passkey" }));
		expect(authenticate).toHaveBeenCalledWith("enroll-code", "ADAM-PC");
	});
});
