import { describe, expect, it } from "vitest";
import { componentHealthTone, coverageTone, healthStatusLabel, managedHealthTone } from "./appliance-health";

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
});
