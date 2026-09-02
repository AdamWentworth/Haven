import type { DeviceDetail, DeviceRecord, RuntimeStatus, SecurityEvent, SecuritySnapshot } from "./types";

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error(`The HAVEN hub returned HTTP ${response.status}.`);
  return (await response.json()) as T;
}

export async function collectSnapshot(signal?: AbortSignal): Promise<SecuritySnapshot> {
  return getJSON<SecuritySnapshot>("/api/security/snapshot", signal);
}

export const getLatestSnapshot = (signal?: AbortSignal) => getJSON<SecuritySnapshot>("/api/security/latest", signal);

export const listDevices = (signal?: AbortSignal) => getJSON<DeviceRecord[]>("/api/devices", signal);

export const getDevice = (deviceId: string, signal?: AbortSignal) =>
  getJSON<DeviceDetail>(`/api/devices/${encodeURIComponent(deviceId)}`, signal);

export const getRuntimeStatus = (signal?: AbortSignal) => getJSON<RuntimeStatus>("/api/health", signal);

export const listEvents = (deviceId?: string, signal?: AbortSignal) => {
  const query = new URLSearchParams({ limit: "60" });
  if (deviceId) query.set("deviceId", deviceId);
  return getJSON<SecurityEvent[]>(`/api/events?${query.toString()}`, signal);
};
