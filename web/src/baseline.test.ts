import { describe, expect, it } from "vitest";
import { suggestedBaseline } from "./baseline";
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


describe("VM and GVfs review suggestions", () => {
  it("offers an explicit owner-constrained range covering changing discovery ports", () => {
    const listeners = logicalListeners([udp(3702, "gvfs-daemon.service"), udp(40000, "gvfs-daemon.service"), udp(50000, "gvfs-daemon.service"), udp(54000, "unrelated.service")]);
    const suggestions = suggestedBaseline("dev-laptop", "Ubuntu", listeners, null, []);
    const suggestion = suggestions.find((item) => item.id.startsWith("gvfs-discovery:"))!;
    expect(suggestion.listenerKeys).toHaveLength(2);
    expect(suggestion.services).toEqual([expect.objectContaining({ port: 32768, portEnd: 60999, bindScope: "wildcard", systemdUnits: ["gvfs-daemon.service"] })]);
    const service: ExpectedService = { id: "discovery", createdAt: "2026-09-02T00:00:00Z", updatedAt: "2026-09-02T00:00:00Z", expiresAt: null, ...suggestion.services[0] };
    for (const port of [32768, 45000, 60999]) expect(expectedServiceMatches(logicalListeners([udp(port, "gvfs-daemon.service")])[0], service, null)).toBe(true);
    for (const input of [udp(61000, "gvfs-daemon.service"), udp(50000, "unrelated.service"), udp(50000, ""), { ...udp(50000, "gvfs-daemon.service"), protocol: "TCP" }, { ...udp(50000, "gvfs-daemon.service"), localAddress: "192.0.2.1" }]) {
      expect(expectedServiceMatches(logicalListeners([input])[0], service, null)).toBe(false);
    }
    expect(suggestedBaseline("dev-laptop", "Ubuntu", listeners, null, [service]).some((item) => item.id.startsWith("gvfs-discovery:"))).toBe(false);
    expect(suggestedBaseline("dev-laptop", "Windows", listeners, null, []).some((item) => item.id.startsWith("gvfs-discovery:"))).toBe(false);
  });

  it("does not suggest a discovery range without matching UDP 3702 evidence", () => {
    const listeners = logicalListeners([udp(40000, "gvfs-daemon.service")]);
    expect(suggestedBaseline("dev-laptop", "Ubuntu", listeners, null, [])).toEqual([]);
  });

  it("offers exact libvirt DNS and DHCP expectations, never a broad VM range", () => {
    const listeners = logicalListeners([udp(53, "libvirtd.service"), udp(67, "libvirtd.service"), { ...udp(53, "virtnetworkd.service"), protocol: "TCP" }]);
    const suggestions = suggestedBaseline("dev-laptop", "Ubuntu", listeners, null, []);
    expect(suggestions).toHaveLength(3);
    expect(suggestions.every((item) => item.services[0].port === item.services[0].portEnd)).toBe(true);
    expect(suggestions.map((item) => item.title)).toContain("Virtual machine network setup (DHCP)");
  });
});
