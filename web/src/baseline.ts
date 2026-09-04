import { bindScopeLabel, canonicalOwnerName, expectedServiceMatches, listenerOwnerSummary, workloadAttribution, type LogicalListener } from "./network";
import type { ExpectedService, ExpectedServiceInput, WorkloadInventory } from "./types";

export interface BaselineSuggestion {
	id: string;
	title: string;
	description: string;
	listenerKeys: string[];
	services: ExpectedServiceInput[];
}

const workloadLabels: Record<string, string> = {
	frontend_nginx: "PokeGoNexus public web ingress",
	binderledger_api: "BinderLedger API",
	binderledger_web: "BinderLedger web",
	haven_dns: "HAVEN private DNS",
	haven_hub: "HAVEN agent hub",
	haven_proxy: "HAVEN HTTPS console",
	winrift_api: "WinRift API",
	winrift_web: "WinRift web",
};

function readableIdentifier(value: string) {
	return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function knownSystemdLabel(unit: string) {
	if (unit === "systemd-resolved.service") return "systemd-resolved local DNS";
	if (unit === "binderledger-localhost-proxy@8081.service") return "BinderLedger localhost proxy";
	return "";
}

export function suggestedBaseline(deviceId: string, operatingSystem: string, listeners: LogicalListener[], inventory: WorkloadInventory | null, expectedServices: ExpectedService[]) {
	const suggestions: BaselineSuggestion[] = [];
	const isWindows = /windows/i.test(operatingSystem);
	const unreviewed = listeners.filter((listener) => !expectedServices.some((service) => expectedServiceMatches(listener, service, inventory)));
	const exactLabels = isWindows ? new Map<string, string>([
		["TCP:135", "Windows RPC Endpoint Mapper"],
		["TCP:139", "Windows file sharing (NetBIOS)"],
		["TCP:445", "Windows file sharing (SMB)"],
		["TCP:3389", "Remote Desktop"],
		["TCP:5040", "Windows Connected Devices"],
		["TCP:5357", "Windows device discovery (WSD)"],
		["TCP:8096", "Jellyfin"],
	]) : new Map<string, string>([
		["TCP:22", "OpenSSH"],
		["UDP:546", "DHCPv6 client"],
		["UDP:5353", "mDNS discovery"],
		["UDP:51822", "WireGuard VPN"],
	]);

	for (const listener of unreviewed) {
		const attributions = workloadAttribution(listener, inventory);
		if (attributions.length === 1) {
			const workload = attributions[0].workload;
			const title = workloadLabels[workload.name] || readableIdentifier(workload.name);
			suggestions.push({
				id: `workload:${listener.key}:${workload.name}`,
				title,
				description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)} · currently published by Docker workload ${workload.name}${listenerOwnerSummary(listener) ? ` · ${listenerOwnerSummary(listener)}` : ""}.`,
				listenerKeys: [listener.key],
				services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: [workload.name], systemdUnits: listener.systemdUnits }],
			});
			continue;
		}
		const knownUnitLabels = listener.systemdUnits.map(knownSystemdLabel);
		if (knownUnitLabels.length > 0 && knownUnitLabels.every(Boolean) && new Set(knownUnitLabels).size === 1) {
			const title = knownUnitLabels[0];
			suggestions.push({
				id: `systemd:${listener.key}:${listener.systemdUnits.join(",")}`,
				title,
				description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)} · ${listenerOwnerSummary(listener)}.`,
				listenerKeys: [listener.key],
				services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: [], systemdUnits: listener.systemdUnits }],
			});
			continue;
		}
		if (listener.bindScope === "local") continue;
		const title = exactLabels.get(`${listener.protocol}:${listener.port}`);
		if (!title) continue;
		suggestions.push({
			id: `native:${listener.key}`,
			title,
			description: `${listener.protocol} ${listener.port} · ${bindScopeLabel(listener.bindScope)}${listenerOwnerSummary(listener) ? ` · ${listenerOwnerSummary(listener)}` : ""}.`,
			listenerKeys: [listener.key],
			services: [{ deviceId, label: title, protocol: listener.protocol, port: listener.port, portEnd: listener.port, bindScope: listener.bindScope, processNames: listener.processes, workloadNames: [], systemdUnits: listener.systemdUnits }],
		});
	}

	if (isWindows) {
		const systemProcesses = new Set(["system", "svchost", "services", "lsass", "wininit", "winlogon", "spoolsv"]);
		const exactSuggestionKeys = new Set(suggestions.flatMap((suggestion) => suggestion.listenerKeys));
		const dynamicByScope = new Map<LogicalListener["bindScope"], LogicalListener[]>();
		for (const listener of unreviewed) {
			const processes = listener.processes.map((process) => canonicalOwnerName(process, true));
			if (exactSuggestionKeys.has(listener.key) || listener.protocol !== "TCP" || listener.port < 49152 || listener.port > 65535 || processes.length === 0 || !processes.every((process) => systemProcesses.has(process))) continue;
			dynamicByScope.set(listener.bindScope, [...(dynamicByScope.get(listener.bindScope) || []), listener]);
		}
		for (const [scope, grouped] of dynamicByScope) {
			const processes = [...new Set(grouped.flatMap((listener) => listener.processes.map((process) => canonicalOwnerName(process, true))))].sort();
			suggestions.push({
				id: `windows-rpc:${scope}:${processes.join(",")}`,
				title: "Windows dynamic RPC services",
				description: `Groups ${grouped.length} current listener${grouped.length === 1 ? "" : "s"} in TCP 49152–65535, but only while owned by reviewed Windows system processes: ${processes.join(", ")}.`,
				listenerKeys: grouped.map((listener) => listener.key),
				services: [{ deviceId, label: "Windows dynamic RPC services", protocol: "TCP", port: 49152, portEnd: 65535, bindScope: scope, processNames: processes, workloadNames: [], systemdUnits: [] }],
			});
		}
	} else {
		const containerdByScope = new Map<LogicalListener["bindScope"], LogicalListener[]>();
		for (const listener of unreviewed) {
			const units = listener.systemdUnits.map((unit) => canonicalOwnerName(unit));
			if (listener.protocol !== "TCP" || listener.port < 32768 || listener.port > 60999 || units.length === 0 || !units.every((unit) => unit === "containerd.service")) continue;
			containerdByScope.set(listener.bindScope, [...(containerdByScope.get(listener.bindScope) || []), listener]);
		}
		for (const [scope, grouped] of containerdByScope) {
			const processes = [...new Set(grouped.flatMap((listener) => listener.processes))].sort();
			suggestions.push({
				id: `containerd:${scope}`,
				title: "containerd internal runtime listeners",
				description: `Covers ${grouped.length} current TCP listener${grouped.length === 1 ? "" : "s"} in the Linux ephemeral range 32768–60999, but only while owned by containerd.service${processes.length ? ` and process${processes.length === 1 ? "" : "es"} ${processes.join(", ")}` : ""}.`,
				listenerKeys: grouped.map((listener) => listener.key),
				services: [{ deviceId, label: "containerd internal runtime listeners", protocol: "TCP", port: 32768, portEnd: 60999, bindScope: scope, processNames: processes, workloadNames: [], systemdUnits: ["containerd.service"] }],
			});
		}
		const avahiByScope = new Map<LogicalListener["bindScope"], LogicalListener[]>();
		for (const listener of unreviewed) {
			const units = listener.systemdUnits.map((unit) => canonicalOwnerName(unit));
			if (listener.protocol !== "UDP" || listener.port < 32768 || listener.port > 60999 || units.length === 0 || !units.every((unit) => unit === "avahi-daemon.service")) continue;
			avahiByScope.set(listener.bindScope, [...(avahiByScope.get(listener.bindScope) || []), listener]);
		}
		for (const [scope, grouped] of avahiByScope) {
			const processes = [...new Set(grouped.flatMap((listener) => listener.processes))].sort();
			suggestions.push({
				id: `avahi-dynamic:${scope}`,
				title: "Avahi dynamic mDNS sockets",
				description: `Covers ${grouped.length} current UDP socket${grouped.length === 1 ? "" : "s"} in this host's Linux dynamic range 32768–60999, but only while attributed to avahi-daemon.service${processes.length ? ` and process${processes.length === 1 ? "" : "es"} ${processes.join(", ")}` : ""}.`,
				listenerKeys: grouped.map((listener) => listener.key),
				services: [{ deviceId, label: "Avahi dynamic mDNS sockets", protocol: "UDP", port: 32768, portEnd: 60999, bindScope: scope, processNames: processes, workloadNames: [], systemdUnits: ["avahi-daemon.service"] }],
			});
		}
	}

	return suggestions;
}
