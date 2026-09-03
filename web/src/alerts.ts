import { bindScopeLabel, canonicalOwnerName, expectedServiceMatches, logicalListeners, networkServiceLabel, workloadAttribution, type LogicalListener, type NetworkDeviceObservation } from "./network";
import type { SecurityEvent } from "./types";

export type AlertSeverity = "high" | "medium" | "low";
export type AlertKind = "finding" | "stale-agent" | "awaiting-agent" | "new-service" | "service-drift";

export interface HavenAlert {
  id: string;
  instanceId: string;
  deviceId: string;
  deviceName: string;
  kind: AlertKind;
  severity: AlertSeverity;
  title: string;
  summary: string;
  evidence: string;
  startedAt: string;
}

const severityOrder = { high: 0, medium: 1, low: 2 } satisfies Record<AlertSeverity, number>;

function validTimestamp(value: string | null | undefined, fallback: string) {
  return value && Number.isFinite(new Date(value).valueOf()) ? value : fallback;
}

function ownerEvidence(listener: LogicalListener, device: NetworkDeviceObservation) {
  const owners = [
    ...listener.processes.map((name) => `process ${name}`),
    ...listener.systemdUnits.map((name) => `service ${name}`),
    ...workloadAttribution(listener, device.snapshot?.linuxBaseline?.workloads ?? null).map(({ workload }) => `workload ${workload.name}`),
  ];
  return [...new Set(owners)].sort();
}

function matchingEndpointBaseline(listener: LogicalListener, device: NetworkDeviceObservation) {
  return device.expectedServices.filter((service) => {
    const portEnd = service.portEnd || service.port;
    return service.protocol === listener.protocol
      && listener.port >= service.port
      && listener.port <= portEnd
      && (service.bindScope === "any" || service.bindScope === listener.bindScope);
  });
}

export function deriveCurrentAlerts(devices: NetworkDeviceObservation[], events: SecurityEvent[], freshnessAllowanceSeconds?: number) {
  const latestOpenedEvents = new Map<string, SecurityEvent>();
  for (const event of [...events].sort((left, right) => right.id - left.id)) {
    const key = `${event.deviceId}:${event.findingId}`;
    if (event.kind === "opened" && !latestOpenedEvents.has(key)) latestOpenedEvents.set(key, event);
  }

  const alerts: HavenAlert[] = [];
  for (const device of devices) {
    const { snapshot } = device;
    if (device.device.status === "stale") {
      const lastSeen = validTimestamp(device.device.lastSeenAt, validTimestamp(device.device.enrolledAt, new Date(0).toISOString()));
      const allowance = Number.isFinite(freshnessAllowanceSeconds) && freshnessAllowanceSeconds! > 0 ? freshnessAllowanceSeconds! : 0;
      const staleAt = new Date(new Date(lastSeen).valueOf() + allowance * 1000).toISOString();
      alerts.push({
        id: `stale-agent:${device.device.id}`,
        instanceId: `stale-agent:${device.device.id}:${lastSeen}`,
        deviceId: device.device.id,
        deviceName: device.device.displayName,
        kind: "stale-agent",
        severity: "medium",
        title: "Authenticated agent report is overdue",
        summary: allowance > 0 ? `HAVEN has not received a report within the server's ${Math.round(allowance / 60)}-minute freshness allowance.` : "The HAVEN server classifies this endpoint's authenticated report as overdue.",
        evidence: `Last authenticated contact: ${lastSeen}`,
        startedAt: staleAt,
      });
    } else if (device.device.status === "awaiting-first-report") {
      const enrolledAt = validTimestamp(device.device.enrolledAt, new Date(0).toISOString());
      alerts.push({
        id: `awaiting-agent:${device.device.id}`,
        instanceId: `awaiting-agent:${device.device.id}:${enrolledAt}`,
        deviceId: device.device.id,
        deviceName: device.device.displayName,
        kind: "awaiting-agent",
        severity: "low",
        title: "Enrolled device has not reported yet",
        summary: "The identity is enrolled, but HAVEN has not accepted its first authenticated observation.",
        evidence: `Enrolled: ${enrolledAt}`,
        startedAt: enrolledAt,
      });
    }

    if (!snapshot) continue;
    for (const finding of snapshot.findings || []) {
      const opened = latestOpenedEvents.get(`${device.device.id}:${finding.id}`);
      const startedAt = validTimestamp(opened?.occurredAt, snapshot.collectedAt);
      alerts.push({
        id: `finding:${device.device.id}:${finding.id}`,
        instanceId: `finding:${device.device.id}:${finding.id}:${startedAt}:${finding.severity}`,
        deviceId: device.device.id,
        deviceName: device.device.displayName,
        kind: "finding",
        severity: finding.severity,
        title: finding.title,
        summary: finding.summary,
        evidence: "Current evaluated endpoint posture",
        startedAt,
      });
    }

    const workloadInventory = snapshot.linuxBaseline?.workloads ?? null;
    for (const listener of logicalListeners(snapshot.connections || [])) {
      if (listener.bindScope === "local" || device.expectedServices.some((service) => expectedServiceMatches(listener, service, workloadInventory))) continue;
      const observation = device.listenerObservations.find((item) => item.present && item.protocol === listener.protocol && item.port === listener.port && item.bindScope === listener.bindScope);
      const startedAt = validTimestamp(observation?.appearedAt, snapshot.collectedAt);
      const endpointBaselines = matchingEndpointBaseline(listener, device);
      const drift = endpointBaselines.length > 0;
      const owners = ownerEvidence(listener, device);
      const service = networkServiceLabel(listener.protocol, listener.port);
      const ownerRevision = owners.map((owner) => canonicalOwnerName(owner)).join("|") || "owner-unavailable";
      const endpointName = `${listener.protocol} ${listener.port}${service ? ` (${service})` : ""}`;
      alerts.push({
        id: `${drift ? "service-drift" : "new-service"}:${device.device.id}:${listener.key}`,
        instanceId: `${drift ? "service-drift" : "new-service"}:${device.device.id}:${listener.key}:${startedAt}:${ownerRevision}`,
        deviceId: device.device.id,
        deviceName: device.device.displayName,
        kind: drift ? "service-drift" : "new-service",
        severity: "medium",
        title: drift ? `Service attribution changed for ${endpointName}` : `Unreviewed service appeared on ${endpointName}`,
        summary: drift
          ? "The port and bind scope match an owner-approved baseline, but its current process, system-service, or workload attribution does not."
          : "A currently listening non-local service is not covered by an owner-approved baseline. This requires review but is not, by itself, evidence of Internet exposure or compromise.",
        evidence: `${bindScopeLabel(listener.bindScope)}${owners.length ? ` · ${owners.join(", ")}` : " · owner unavailable"}`,
        startedAt,
      });
    }
  }

  return alerts.sort((left, right) => severityOrder[left.severity] - severityOrder[right.severity]
    || new Date(right.startedAt).valueOf() - new Date(left.startedAt).valueOf()
    || left.id.localeCompare(right.id));
}
