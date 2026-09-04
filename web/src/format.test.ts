import { afterEach, describe, expect, it, vi } from "vitest";
import { booleanValue, formatBytes, formatDate, formatDuration, formatInterval, formatPortBinding, formatRelativeTime, formatTimeRemaining, policyValue } from "./format";

describe("display formatting", () => {
	afterEach(() => vi.useRealTimers());

	it("keeps missing and invalid timestamps explicit", () => {
		expect(formatDate(null)).toBe("Not reported");
		expect(formatDate("invalid", "Unknown")).toBe("Unknown");
		expect(formatRelativeTime(undefined)).toBe("not reported");
	});

	it("formats relative and remaining time at stable boundaries", () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-09-04T12:00:00Z"));
		expect(formatRelativeTime("2026-09-04T11:59:55Z")).toBe("just now");
		expect(formatRelativeTime("2026-09-04T11:59:30Z")).toBe("30s ago");
		expect(formatRelativeTime("2026-09-04T11:30:00Z")).toBe("30 min ago");
		expect(formatRelativeTime("2026-09-04T10:00:00Z")).toBe("2 hr ago");
		expect(formatRelativeTime("2026-09-01T12:00:00Z")).toBe("3 days ago");
		expect(formatTimeRemaining("2026-09-04T12:00:30Z")).toBe("less than 1 min");
		expect(formatTimeRemaining("2026-09-04T12:30:00Z")).toBe("30 min");
		expect(formatTimeRemaining("2026-09-04T14:00:00Z")).toBe("2 hr");
		expect(formatTimeRemaining("2026-09-07T12:00:00Z")).toBe("3 days");
	});

	it("formats bounded machine facts without changing their meaning", () => {
		expect(formatDuration(null)).toBe("Uptime unavailable");
		expect(formatDuration(3600)).toBe("1h uptime");
		expect(formatDuration(90000)).toBe("1d 1h uptime");
		expect(formatInterval(30)).toBe("30s");
		expect(formatInterval(900)).toBe("15 min");
		expect(formatInterval(7200)).toBe("2 hr");
		expect(formatBytes(null)).toBe("Not reported");
		expect(formatBytes(512)).toBe("512 B");
		expect(formatBytes(1536)).toBe("1.5 KiB");
		expect(booleanValue(true)).toEqual({ label: "On", className: "value-good" });
		expect(booleanValue(false)).toEqual({ label: "Off", className: "value-bad" });
		expect(booleanValue(null)).toEqual({ label: "Unavailable", className: "value-muted" });
		expect(policyValue()).toBe("System default");
		expect(policyValue("Deny")).toBe("Deny");
	});

	it("distinguishes container-only, IPv4, and IPv6 port bindings", () => {
		expect(formatPortBinding({ protocol: "TCP", containerPort: 8080, published: false })).toBe("8080/tcp · container only");
		expect(formatPortBinding({ protocol: "TCP", containerPort: 80, published: true, hostAddress: "0.0.0.0", hostPort: 8080 })).toBe("0.0.0.0:8080 → 80/tcp");
		expect(formatPortBinding({ protocol: "UDP", containerPort: 53, published: true, hostAddress: "::1", hostPort: 53 })).toBe("[::1]:53 → 53/udp");
	});
});
