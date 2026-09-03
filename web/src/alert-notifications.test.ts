import { describe, expect, it } from "vitest";
import { notificationCandidates, parseAlertReceipts, receiptsForCurrentAlerts } from "./alert-notifications";
import type { HavenAlert } from "./alerts";

function alert(overrides: Partial<HavenAlert> = {}): HavenAlert {
  return { id: "finding:device:test", instanceId: "finding:device:test:first", deviceId: "device", deviceName: "Test Device", kind: "finding", severity: "medium", title: "Test", summary: "Test summary", evidence: "Test evidence", startedAt: "2026-09-02T20:00:00Z", ...overrides };
}

describe("desktop alert receipts", () => {
  it("parses only bounded string receipts and rejects malformed storage", () => {
    expect(parseAlertReceipts("not-json")).toEqual({});
    expect(parseAlertReceipts(JSON.stringify({ valid: "instance", invalid: 3 }))).toEqual({ valid: "instance" });
    expect(parseAlertReceipts(JSON.stringify(["nope"]))).toEqual({});
  });

  it("notifies once for each medium or high alert instance", () => {
    const current = alert();
    expect(notificationCandidates([current], {})).toEqual([current]);
    expect(notificationCandidates([current], { [current.id]: current.instanceId })).toEqual([]);
    expect(notificationCandidates([{ ...current, instanceId: "second" }], { [current.id]: current.instanceId })).toHaveLength(1);
  });

  it("keeps low-severity review items visible without a desktop interruption", () => {
    expect(notificationCandidates([alert({ severity: "low" })], {})).toEqual([]);
  });

  it("replaces receipts with the current active set so a later recurrence can notify", () => {
    const current = alert();
    expect(receiptsForCurrentAlerts([current])).toEqual({ [current.id]: current.instanceId });
    expect(receiptsForCurrentAlerts([])).toEqual({});
  });
});
