import { describe, expect, it } from "vitest";
import { parseRoute, routePath } from "./routing";

describe("application routes", () => {
	it("maps each top-level page to a stable URL", () => {
		expect(parseRoute("/")).toEqual({ page: "overview" });
		expect(parseRoute("/devices")).toEqual({ page: "devices" });
		expect(parseRoute("/network")).toEqual({ page: "network" });
		expect(parseRoute("/appliances")).toEqual({ page: "appliances" });
		expect(parseRoute("/accounts")).toEqual({ page: "accounts" });
		expect(parseRoute("/activity")).toEqual({ page: "activity" });
		expect(parseRoute("/settings")).toEqual({ page: "settings" });
	});

	it("round-trips a device and its selected section", () => {
		const route = { page: "device", deviceId: "device/a", section: "services" } as const;
		expect(parseRoute(routePath(route))).toEqual(route);
	});

	it("falls back safely for unknown pages and device sections", () => {
		expect(parseRoute("/not-a-page")).toEqual({ page: "overview" });
		expect(parseRoute("/devices/%E0%A4%A")).toEqual({ page: "overview" });
		expect(parseRoute("/devices/device-a/not-a-section")).toEqual({ page: "device", deviceId: "device-a", section: "overview" });
	});
});
