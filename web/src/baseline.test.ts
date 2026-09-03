import { describe, expect, it } from "vitest";
import { suggestedBaseline } from "./App";
import { expectedServiceMatches, logicalListeners } from "./network";
import type { ExpectedService, NetworkConnection } from "./types";

function udp(port: number, unit: string): NetworkConnection {
  return { protocol: "UDP", localAddress: "0.0.0.0", localPort: port, remoteAddress: "", remotePort: 0, state: "Bound", processId: 0, processName: "", systemdUnit: unit };
}

describe("Linux baseline suggestions", () => {
  it("groups Avahi's changing UDP sockets into an owner-constrained dynamic range", () => {
    const listeners = logicalListeners([
      udp(44399, "avahi-daemon.service"),
      udp(45126, "avahi-daemon.service"),
    ]);
    const suggestion = suggestedBaseline("dev-laptop", "Ubuntu 24.04 LTS", listeners, null, [])
      .find((item) => item.id === "avahi-dynamic:wildcard");

    expect(suggestion?.listenerKeys).toHaveLength(2);
    expect(suggestion?.services).toEqual([expect.objectContaining({
      protocol: "UDP",
      port: 32768,
      portEnd: 60999,
      bindScope: "wildcard",
      processNames: [],
      systemdUnits: ["avahi-daemon.service"],
    })]);
  });

	it("leaves an unrelated owner in the same range untrusted", () => {
		const listeners = logicalListeners([udp(44399, "avahi-daemon.service"), udp(45126, "unexpected.service")]);
		const suggestion = suggestedBaseline("dev-laptop", "Ubuntu 24.04 LTS", listeners, null, [])
			.find((item) => item.id === "avahi-dynamic:wildcard");
		expect(suggestion?.listenerKeys).toHaveLength(1);
		const service: ExpectedService = { id: "avahi", createdAt: "2026-09-02T00:00:00Z", updatedAt: "2026-09-02T00:00:00Z", expiresAt: null, ...suggestion!.services[0] };
		expect(expectedServiceMatches(listeners[1], service, null)).toBe(false);
	});

	it("does not suggest the Avahi range without Avahi ownership", () => {
		const listeners = logicalListeners([udp(44399, "unexpected.service")]);
		expect(suggestedBaseline("dev-laptop", "Ubuntu 24.04 LTS", listeners, null, []))
			.not.toEqual(expect.arrayContaining([expect.objectContaining({ id: "avahi-dynamic:wildcard" })]));
	});
});
