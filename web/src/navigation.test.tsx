// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AppNavigation, DeviceNavigation } from "./navigation";

describe("console navigation", () => {
	it("exposes every top-level destination and marks the active page", async () => {
		const navigate = vi.fn();
		const user = userEvent.setup();
		render(<AppNavigation current="network" navigate={navigate} />);

		expect(screen.getAllByRole("link")).toHaveLength(7);
		expect(screen.getByRole("link", { name: "Accounts" })).toHaveAttribute("href", "/accounts");
		expect(screen.getByRole("link", { name: "Network" })).toHaveAttribute("aria-current", "page");
		await user.click(screen.getByRole("link", { name: "Settings" }));
		expect(navigate).toHaveBeenCalledWith({ page: "settings" });
	});

	it("keeps each device subsection directly addressable", () => {
		render(<DeviceNavigation deviceId="device/a" current="services" navigate={vi.fn()} />);
		expect(screen.getByRole("link", { name: "Services & connections" })).toHaveAttribute("href", "/devices/device%2Fa/services");
		expect(screen.getByRole("link", { name: "Services & connections" })).toHaveAttribute("aria-current", "page");
	});
});
