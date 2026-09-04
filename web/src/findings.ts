import type { FindingReview, HavenAlert, SecurityEvent, SecurityFinding } from "./types";

export interface FindingLifecycle {
	event: SecurityEvent;
	openedAt: string | null;
}

export function actionableFindings(findings: SecurityFinding[], reviews: FindingReview[], now = new Date()): SecurityFinding[] {
	return findings.filter((finding) => {
		const currentReview = reviews.find((review) => review.findingId === finding.id);
		if (!currentReview) return true;
		if (currentReview.state === "accepted-risk") return false;
		return currentReview.state !== "snoozed" || !currentReview.snoozedUntil || new Date(currentReview.snoozedUntil) <= now;
	});
}

function latestFindingLifecycles(events: SecurityEvent[]) {
	const ordered = [...events].sort((left, right) => new Date(right.occurredAt).valueOf() - new Date(left.occurredAt).valueOf() || right.id - left.id);
	const seen = new Set<string>();
	const lifecycles: FindingLifecycle[] = [];
	for (const event of ordered) {
		const key = `${event.deviceId}:${event.findingId}`;
		if (seen.has(key)) continue;
		seen.add(key);
		const opened = event.kind === "opened" ? event : ordered.find((candidate) => candidate.deviceId === event.deviceId && candidate.findingId === event.findingId && candidate.kind === "opened" && new Date(candidate.occurredAt) <= new Date(event.occurredAt));
		lifecycles.push({ event, openedAt: opened?.occurredAt || null });
	}
	return lifecycles.sort((left, right) => Number(left.event.kind === "resolved") - Number(right.event.kind === "resolved") || new Date(right.event.occurredAt).valueOf() - new Date(left.event.occurredAt).valueOf());
}

const retiredFindingIDs = new Set(["drive-encryption", "openssh-running"]);

export function visibleFindingLifecycles(events: SecurityEvent[], alerts: HavenAlert[]): FindingLifecycle[] {
	const activeKeys = new Set(alerts.filter((alert) => alert.kind === "finding").map((alert) => {
		const prefix = `finding:${alert.deviceId}:`;
		const findingId = alert.id.startsWith(prefix) ? alert.id.slice(prefix.length) : alert.id;
		return `${alert.deviceId}:${findingId}`;
	}));
	return latestFindingLifecycles(events).filter(({ event }) => !retiredFindingIDs.has(event.findingId) && (event.kind === "resolved" || activeKeys.has(`${event.deviceId}:${event.findingId}`)));
}
