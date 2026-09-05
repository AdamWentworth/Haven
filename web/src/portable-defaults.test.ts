import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { networkServiceLabel } from "./network";

const runtimeSources = ["App.tsx", "baseline.ts", "network.ts"]
	.map((name) => readFileSync(new URL(`./${name}`, import.meta.url), "utf8"))
	.join("\n");

describe("portable product defaults", () => {
	it("does not embed one household's device or workload names in runtime presentation", () => {
		expect(runtimeSources).not.toMatch(/ADAM-PC|AdamWentworth|PokeGoNexus|BinderLedger|WinRift/);
	});

	it("does not guess that a deployment-specific VPN port belongs to every owner", () => {
		expect(networkServiceLabel("udp", 51822)).toBe("");
		expect(networkServiceLabel("tcp", 8443)).toBe("HTTPS (alternate)");
	});
});
