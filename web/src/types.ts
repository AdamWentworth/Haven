export interface SecuritySnapshot {
  collectedAt: string;
  device: DeviceSummary;
  defender: DefenderStatus | null;
  windowsBaseline: WindowsBaseline | null;
  linuxBaseline: LinuxBaseline | null;
  baselineChecks: BaselineCheck[];
  findings: SecurityFinding[];
  firewallProfiles: FirewallProfileStatus[];
  connections: NetworkConnection[];
  notices: CollectorNotice[];
}

export interface LinuxBaseline {
  updates: { pendingPackageCount: number | null; pendingSecurityPackageCount: number | null; pendingReboot: boolean | null } | null;
  firewall: { provider: string; active: boolean | null; defaultInboundAction?: string; defaultOutboundAction?: string } | null;
  ssh: { serverRunning: boolean | null; passwordAuthentication?: string; permitRootLogin?: string; publicKeyAuthentication?: string; failedLoginCount24Hours: number | null } | null;
  services: { failedUnitCount: number | null; failedUnits: string[] } | null;
  automaticUpdates: { enabled: boolean | null; active: boolean | null } | null;
  appArmor: { enabled: boolean | null } | null;
  timeSync: { synchronized: boolean | null } | null;
  storage: { mountPoint: string; fileSystem?: string; capacityBytes: number | null; availableBytes: number | null; usedPercentage: number | null } | null;
}

export interface WindowsBaseline {
  update: { lastInstalledAt: string | null; pendingReboot: boolean | null; rebootReasons: string[] } | null;
  systemEncryption: { systemDrive: string; volumeStatus: string; protectionStatus: string; encryptionPercentage: number | null } | null;
  platformSecurity: { secureBootEnabled: boolean | null; tpmPresent: boolean | null; tpmReady: boolean | null; tpmVersion?: string; tpmManufacturer?: string; tpmSource?: string } | null;
  remoteAccess: { remoteDesktopEnabled: boolean | null; networkLevelAuthRequired: boolean | null; rdpFirewallScope?: "restricted" | "unrestricted" | "blocked" | "unknown"; rdpFirewallRuleCount: number | null; remoteAssistanceEnabled: boolean | null; smb1Enabled: boolean | null; openSshServerRunning: boolean | null } | null;
  localAccounts: { administratorCount: number | null; enabledAdministratorCount: number | null } | null;
  threats: { activeThreatCount: number | null; recentDetectionCount: number | null; lastDetectedAt: string | null } | null;
}

export interface BaselineCheck {
  id: string;
  category: string;
  title: string;
  status: "pass" | "configured" | "attention" | "unknown";
  summary: string;
  evidence?: string;
}

export interface SecurityFinding {
  id: string;
  category: string;
  title: string;
  severity: "high" | "medium" | "low";
  summary: string;
  recommendation: string;
}

export interface SecurityEvent {
  id: number;
  deviceId: string;
  deviceName: string;
  findingId: string;
  kind: "opened" | "resolved";
  category: string;
  title: string;
  severity: "high" | "medium" | "low";
  summary: string;
  occurredAt: string;
}

export interface DeviceSummary {
  deviceId?: string;
  hostName: string;
  operatingSystem: string;
  architecture: string;
  uptimeSeconds: number | null;
}

export interface DefenderStatus {
  antivirusEnabled: boolean | null;
  realTimeProtectionEnabled: boolean | null;
  behaviorMonitorEnabled: boolean | null;
  downloadProtectionEnabled: boolean | null;
  tamperProtected: boolean | null;
  tamperProtectionSource?: string;
  signatureVersion?: string;
  signatureUpdatedAt: string | null;
  lastQuickScanAt: string | null;
  lastFullScanAt: string | null;
}

export interface FirewallProfileStatus {
  name: string;
  enabled: boolean | null;
  defaultInboundAction?: string;
  defaultOutboundAction?: string;
  logFileName?: string;
}

export interface NetworkConnection {
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  processId: number;
  processName: string;
}

export type BindScope = "any" | "local" | "private" | "wildcard" | "specific";

export interface ExpectedService {
  id: string;
  deviceId: string;
  label: string;
  protocol: "TCP" | "UDP";
  port: number;
  bindScope: BindScope;
  createdAt: string;
  updatedAt: string;
}

export interface ObservedListener {
  deviceId: string;
  protocol: "TCP" | "UDP";
  port: number;
  bindScope: Exclude<BindScope, "any">;
  firstSeenAt: string;
  appearedAt: string;
  lastSeenAt: string;
  present: boolean;
}

export interface CollectorNotice {
  source: string;
  severity: string;
  message: string;
}

export interface DeviceRecord {
  id: string;
  displayName: string;
  hostName: string;
  operatingSystem: string;
  architecture: string;
  trustState: "local" | "enrolled" | "synthetic" | "revoked";
  status: "current" | "stale" | "awaiting-first-report" | "revoked";
  enrolledAt: string;
  lastSeenAt: string | null;
  lastCollectedAt: string | null;
  certificateExpiresAt: string | null;
  revokedAt: string | null;
}

export interface DeviceDetail {
  device: DeviceRecord;
  snapshot: SecuritySnapshot | null;
}

export interface RuntimeStatus {
  status: string;
  service: string;
  agentIngestion: string;
  demoMode: boolean;
  localCollection: boolean;
  actionCapabilities: ActionCapability[];
  monitor: {
    enabled: boolean;
    intervalSeconds: number;
    lastAttemptAt: string | null;
    lastSuccessfulAt: string | null;
    lastCollectionError?: string;
  };
  timestamp: string;
}

export interface AuthStatus {
  configured: boolean;
  authenticated: boolean;
  origin: string;
  useConfiguredOrigin: boolean;
}

export interface PasskeyInfo {
  id: string;
  label: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export type FindingReviewState = "new" | "acknowledged" | "snoozed" | "accepted-risk";

export interface FindingReview {
  deviceId: string;
  findingId: string;
  state: FindingReviewState;
  note: string;
  snoozedUntil: string | null;
  reviewedAt: string;
}

export interface AuditEvent {
  id: number;
  actor: string;
  action: string;
  target: string;
  outcome: string;
  detail: string;
  occurredAt: string;
}

export type SecurityActionKind = string;

export interface ActionCapability {
  id: SecurityActionKind;
  provider: string;
  platform: string;
  label: string;
  description: string;
  requiresReauthorization: boolean;
}

export interface SecurityAction {
  id: string;
  kind: SecurityActionKind;
  status: "queued" | "running" | "succeeded" | "failed";
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  message: string;
}
