import { canonicalOwnerName, type LogicalListener } from "./network";

function hasOnlyUnits(listener: LogicalListener, allowed: string[]) {
  return listener.systemdUnits.length > 0 && listener.systemdUnits.every((unit) => allowed.includes(canonicalOwnerName(unit)));
}

export function isGvfsDiscovery(listener: LogicalListener) {
  return listener.protocol === "UDP" && hasOnlyUnits(listener, ["gvfs-daemon.service"])
    && listener.processes.every((process) => ["wsdd", "python3"].includes(canonicalOwnerName(process)));
}

function ownerKey(listener: LogicalListener) {
  return JSON.stringify([listener.systemdUnits.map((unit) => canonicalOwnerName(unit)).sort(), listener.processes.map((process) => canonicalOwnerName(process)).sort()]);
}

export function isGvfsDynamicDiscovery(listener: LogicalListener, listeners: LogicalListener[]) {
  return isGvfsDiscovery(listener) && listener.port >= 32768 && listener.port <= 60999
    && listeners.some((other) => isGvfsDiscovery(other) && other.port === 3702 && ownerKey(other) === ownerKey(listener));
}

export function listenerPurpose(listener: LogicalListener, listeners: LogicalListener[]) {
  if (hasOnlyUnits(listener, ["libvirtd.service", "virtnetworkd.service"])
    && listener.processes.every((process) => canonicalOwnerName(process) === "dnsmasq")) {
    if (listener.port === 53) return { title: "Virtual machine DNS", description: "Looks up network names for virtual machines managed by libvirt." };
    if (listener.protocol === "UDP" && listener.port === 67) return { title: "Virtual machine network setup (DHCP)", description: "Gives libvirt virtual machines their network settings. A wildcard address alone does not establish which interfaces can receive traffic." };
  }
  if (isGvfsDiscovery(listener) && listener.port === 3702) return { title: "File manager network discovery", description: "Helps the file manager find Windows computers and shared devices on the network. Multicast and individual-address sockets belong to the same discovery activity." };
  if (isGvfsDynamicDiscovery(listener, listeners)) return { title: "File manager discovery reply socket", description: "Likely part of the GVfs network discovery activity also observed on UDP 3702. These port numbers can change; review the grouped discovery suggestion instead of approving each number." };
  return null;
}
