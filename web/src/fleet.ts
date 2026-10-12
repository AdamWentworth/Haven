import type { DeviceRecord } from "./types";
import type { Tone } from "./ui";

export type FleetLifecycle = "ready" | "compatible" | "overdue" | "away" | "check-in-due" | "pending" | "revoked" | "legacy" | "development" | "version-drift" | "revision-drift" | "local" | "demo";

export interface FleetPresentation {
	state: FleetLifecycle;
	label: string;
	tone: Tone;
	detail: string;
}

export function reportingPresentation(device: DeviceRecord): FleetPresentation {
	const state = device.reportingStatus ?? (device.status === "stale" ? "overdue" : device.status);
	if (state === "away") return { state: "away", label: "Not currently reporting", tone: "configured", detail: "Intermittent reporting is expected; the last report remains visible" };
	if (state === "check-in-due") return { state: "check-in-due", label: "Check-in reminder", tone: "configured", detail: "No report for over a week; check the agent when you next use this device" };
	if (state === "overdue") return { state: "overdue", label: "Report overdue", tone: "attention", detail: "Authenticated reporting is outside the freshness allowance for an always-on device" };
	if (state === "awaiting-first-report") return { state: "pending", label: "Awaiting report", tone: "attention", detail: "Enrollment has not produced an observation" };
	if (state === "revoked") return { state: "revoked", label: "Revoked", tone: "danger", detail: "This identity can no longer report" };
	return { state: "ready", label: "Reporting now", tone: "healthy", detail: "The hub has a recent authenticated report" };
}

export function fleetPresentation(device: DeviceRecord): FleetPresentation {
	if (device.trustState === "synthetic") return { state: "demo", label: "Synthetic", tone: "configured", detail: "Invented portfolio fixture" };
	if (device.trustState === "local") return { state: "local", label: "Local collector", tone: "configured", detail: "Collected inside this development hub" };
	if (device.status === "revoked") return { state: "revoked", label: "Revoked", tone: "danger", detail: "This identity can no longer report" };
	if (device.status !== "current") return reportingPresentation(device);
	if (!device.agent) return { state: "legacy", label: "Legacy reporter", tone: "attention", detail: "Reporting normally, but without 0.14 build evidence" };
	switch (device.agent.compatibility) {
		case "current": return { state: "ready", label: "Build verified", tone: "healthy", detail: "Agent version and immutable revision match this hub" };
		case "compatible": return { state: "compatible", label: "Protocol compatible", tone: "healthy", detail: `Agent ${device.agent.version} uses the observation schema supported by this hub` };
		case "development": return { state: "development", label: "Development build", tone: "configured", detail: "Version matches; one build has no immutable revision" };
		case "version-drift": return { state: "version-drift", label: "Release differs", tone: "configured", detail: `Agent ${device.agent.version} differs from the hub release; its accepted report remains protocol compatible` };
		case "revision-drift": return { state: "revision-drift", label: "Revision differs", tone: "attention", detail: "Release version matches, but source revisions differ" };
	}
}

export function fleetSummary(devices: DeviceRecord[]) {
	const active = devices.filter((device) => device.status !== "revoked");
	const presentations = active.map(fleetPresentation);
	return {
		total: active.length,
		reporting: active.filter((device) => device.status === "current").length,
		compatible: presentations.filter((item) => item.state === "ready" || item.state === "compatible").length,
		maintenance: active.filter((device, index) => device.trustState === "enrolled" && ["legacy", "development", "version-drift", "revision-drift"].includes(presentations[index].state)).length,
		limited: active.filter((device) => (device.agent?.collectionNotices || 0) > 0).length,
	};
}

export function capabilityLabel(capability: string) {
	return capability.split("-").map((part) => part === "systemd" ? "systemd" : part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}
