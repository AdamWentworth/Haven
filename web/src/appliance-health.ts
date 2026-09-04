import type { ManagedHealthComponentState, ManagedHealthCoverageState, ManagedHealthStatus, ManagedPoolHealth } from "./types";

export type HealthTone = "healthy" | "configured" | "attention" | "danger" | "unknown";

export function managedHealthTone(status: ManagedHealthStatus["status"]): HealthTone {
  if (status === "healthy") return "healthy";
  if (status === "attention") return "attention";
  if (status === "pending") return "configured";
  return "unknown";
}

export function componentHealthTone(state: ManagedHealthComponentState): HealthTone {
  if (state === "healthy" || state === "standby") return "healthy";
  if (state === "warning" || state === "degraded" || state === "rebuilding") return "attention";
  if (state === "critical" || state === "failed") return "danger";
  if (state === "observed") return "configured";
  return "unknown";
}

export function coverageTone(state: ManagedHealthCoverageState): HealthTone {
  if (state === "verified") return "healthy";
  if (state === "partial") return "configured";
  return "unknown";
}

export function healthStatusLabel(status: ManagedHealthStatus["status"]): string {
  switch (status) {
    case "healthy": return "verified healthy";
    case "attention": return "review needed";
    case "partial": return "partly verified";
    case "unavailable": return "unavailable";
    default: return "pending";
  }
}

export function storageSetLabel(pool: ManagedPoolHealth): string {
  if (pool.memberCount === 1) return "Single-disk storage";
  return pool.raidLevel ? pool.raidLevel.toUpperCase() : "Storage set";
}

export function storageSetDetail(pool: ManagedPoolHealth): string {
  const noun = pool.memberCount === 1 ? "member" : "members";
  const activity = `${pool.activeCount}/${pool.memberCount} ${noun} active`;
  if (pool.memberCount === 1) return `${activity} · no drive redundancy · TOS-managed Linux md set`;
  return activity;
}
