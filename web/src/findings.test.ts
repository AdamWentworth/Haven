import { describe, expect, it } from "vitest";
import { actionableFindings, visibleFindingLifecycles } from "./findings";
import type { FindingReview, HavenAlert, SecurityEvent, SecurityFinding } from "./types";

const finding = (id: string): SecurityFinding => ({
  id,
  category: "Test",
  title: id,
  severity: "low",
  summary: "summary",
  recommendation: "recommendation",
});

const review = (findingId: string, state: FindingReview["state"], snoozedUntil: string | null = null): FindingReview => ({
  deviceId: "device-a",
  findingId,
  state,
  note: "reviewed",
  snoozedUntil,
  reviewedAt: "2026-09-01T00:00:00Z",
});

const event = (findingId: string, kind: SecurityEvent["kind"] = "opened"): SecurityEvent => ({
  id: findingId.length,
  deviceId: "device-a",
  deviceName: "Device A",
  findingId,
  kind,
  category: "Test",
  title: findingId,
  severity: "low",
  summary: "summary",
  occurredAt: "2026-09-01T00:00:00Z",
});

const alert = (findingId: string): HavenAlert => ({
  id: `finding:device-a:${findingId}`,
  instanceId: `finding:device-a:${findingId}:instance`,
  deviceId: "device-a",
  deviceName: "Device A",
  kind: "finding",
  severity: "low",
  title: findingId,
  summary: "summary",
  evidence: "evidence",
  startedAt: "2026-09-01T00:00:00Z",
});

describe("finding presentation policy", () => {
  it("removes accepted risks and active snoozes from reminder surfaces", () => {
    const now = new Date("2026-09-02T00:00:00Z");
    const visible = actionableFindings(
      [finding("accepted"), finding("snoozed"), finding("expired"), finding("acknowledged"), finding("new")],
      [
        review("accepted", "accepted-risk"),
        review("snoozed", "snoozed", "2026-09-03T00:00:00Z"),
        review("expired", "snoozed", "2026-09-01T00:00:00Z"),
        review("acknowledged", "acknowledged"),
      ],
      now,
    );

    expect(visible.map((item) => item.id)).toEqual(["expired", "acknowledged", "new"]);
  });

  it("does not resurface retired BitLocker or service-presence policies in change watch", () => {
    const visible = visibleFindingLifecycles(
      [event("drive-encryption"), event("openssh-running"), event("firewall-disabled"), event("updates-stale", "resolved")],
      [alert("firewall-disabled")],
    );

    expect(visible.map((item) => item.event.findingId)).toEqual(["firewall-disabled", "updates-stale"]);
  });
});
