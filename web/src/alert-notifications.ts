import type { HavenAlert } from "./alerts";

export type AlertReceipts = Record<string, string>;

export function parseAlertReceipts(value: string | null): AlertReceipts {
  if (!value) return {};
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return Object.fromEntries(Object.entries(parsed).filter(([key, instance]) => key.length <= 240 && typeof instance === "string" && instance.length <= 500));
  } catch {
    return {};
  }
}

export function notificationCandidates(alerts: HavenAlert[], receipts: AlertReceipts) {
  return alerts.filter((alert) => (alert.severity === "high" || alert.severity === "medium") && receipts[alert.id] !== alert.instanceId);
}

export function receiptsForCurrentAlerts(alerts: HavenAlert[]) {
  return Object.fromEntries(alerts.map((alert) => [alert.id, alert.instanceId]));
}
