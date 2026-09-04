import { describe, expect, it } from "vitest";
import { componentHealthTone, coverageTone, healthStatusLabel, managedHealthTone, storageSetDetail, storageSetLabel } from "./appliance-health";

describe("managed appliance health presentation", () => {
  it("never presents partial or unavailable evidence as healthy", () => {
    expect(managedHealthTone("partial")).toBe("unknown");
    expect(managedHealthTone("unavailable")).toBe("unknown");
    expect(healthStatusLabel("partial")).toBe("partly verified");
  });

  it("keeps degraded, rebuilding, failed, and critical components visible", () => {
    expect(componentHealthTone("degraded")).toBe("attention");
    expect(componentHealthTone("rebuilding")).toBe("attention");
    expect(componentHealthTone("failed")).toBe("danger");
    expect(componentHealthTone("critical")).toBe("danger");
  });

  it("distinguishes verified, partial, and absent coverage", () => {
    expect(coverageTone("verified")).toBe("healthy");
    expect(coverageTone("partial")).toBe("configured");
    expect(coverageTone("unsupported")).toBe("unknown");
    expect(coverageTone("unavailable")).toBe("unknown");
  });

  it("does not present a one-member Linux md set as redundant RAID", () => {
    const singleDisk = { name: "/dev/md0", raidLevel: "raid1", state: "healthy" as const, memberCount: 1, activeCount: 1, lastChangedAt: null };
    expect(storageSetLabel(singleDisk)).toBe("Single-disk storage");
    expect(storageSetDetail(singleDisk)).toContain("no drive redundancy");
    expect(storageSetDetail(singleDisk)).toContain("TOS-managed Linux md set");
  });

  it("retains RAID terminology for multi-member sets", () => {
    const redundant = { name: "/dev/md0", raidLevel: "raid1", state: "healthy" as const, memberCount: 2, activeCount: 2, lastChangedAt: null };
    expect(storageSetLabel(redundant)).toBe("RAID1");
    expect(storageSetDetail(redundant)).toBe("2/2 members active");
  });
});
