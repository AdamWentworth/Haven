import { describe, expect, it } from "vitest";
import { networkServiceLabel } from "./network";

describe("portable product defaults", () => {
	it("does not guess that a deployment-specific VPN port belongs to every owner", () => {
		expect(networkServiceLabel("udp", 51822)).toBe("");
		expect(networkServiceLabel("tcp", 8443)).toBe("HTTPS (alternate)");
	});
});
