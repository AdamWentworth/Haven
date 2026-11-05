import { describe, expect, it } from "vitest";
import { listenerPurpose } from "./listener-purpose";
import { logicalListeners } from "./network";
import type { NetworkConnection } from "./types";

function socket(port: number, systemdUnit = "gvfs-daemon.service", extra: Partial<NetworkConnection> = {}): NetworkConnection {
  return { protocol: "UDP", localAddress: "0.0.0.0", localPort: port, remoteAddress: "", remotePort: 0, state: "Bound", processId: 0, processName: "", systemdUnit, ...extra };
}

describe("listener purpose evidence", () => {
  it("explains VM DNS and DHCP only with compatible libvirt ownership", () => {
    for (const unit of ["libvirtd.service", "virtnetworkd.service"]) {
      for (const protocol of ["TCP", "UDP"]) {
        const listener = logicalListeners([socket(53, unit, { protocol, processName: "dnsmasq" })])[0];
        expect(listenerPurpose(listener, [listener])?.title).toBe("Virtual machine DNS");
      }
      const listener = logicalListeners([socket(67, unit)])[0];
      expect(listenerPurpose(listener, [listener])?.title).toContain("DHCP");
    }
    for (const input of [socket(53, "other.service"), socket(67, "libvirtd.service", { protocol: "TCP" }), socket(9999, "libvirtd.service"), socket(53, "libvirtd.service", { processName: "other" })]) {
      const listener = logicalListeners([input])[0];
      expect(listenerPurpose(listener, [listener])).toBeNull();
    }
  });

  it("describes dynamic GVfs ports only alongside matching discovery ownership", () => {
    const listeners = logicalListeners([socket(3702), socket(40000)]);
    expect(listenerPurpose(listeners[0], listeners)?.title).toBe("File manager network discovery");
    expect(listenerPurpose(listeners[1], listeners)?.title).toBe("File manager discovery reply socket");
    expect(listenerPurpose(listeners[1], [listeners[1]])).toBeNull();
    for (const input of [socket(40000, ""), socket(40000, "other.service"), socket(40000, "gvfs-daemon.service", { processName: "other" }), socket(40000, "gvfs-daemon.service", { processName: "python3" }), socket(40000, "gvfs-daemon.service", { protocol: "TCP" }), socket(32767), socket(61000)]) {
      const listener = logicalListeners([input])[0];
      expect(listenerPurpose(listener, [listeners[0], listener])).toBeNull();
    }
    const mixed = logicalListeners([socket(40000), socket(40000, "other.service")])[0];
    expect(listenerPurpose(mixed, [listeners[0], mixed])).toBeNull();
    const python = logicalListeners([socket(3702, "gvfs-daemon.service", { processName: "python3" }), socket(40000, "gvfs-daemon.service", { processName: "python3" })]);
    expect(listenerPurpose(python[1], python)?.title).toContain("reply socket");
  });
});
