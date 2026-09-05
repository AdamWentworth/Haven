export interface SecuritySnapshot {
  collectedAt: string;
  device: DeviceSummary;
  defender: DefenderStatus | null;
  windowsBaseline: WindowsBaseline | null;
  linuxBaseline: LinuxBaseline | null;
	browserSecurity?: BrowserSecurityStatus | null;
  baselineChecks: BaselineCheck[];
  findings: SecurityFinding[];
  firewallProfiles: FirewallProfileStatus[];
  connections: NetworkConnection[];
  notices: CollectorNotice[];
}

export interface BrowserSecurityStatus {
	coverage: "observed" | "partial" | "unavailable";
	browsers: BrowserInstallation[];
	protections: BrowserProtectionStatus[];
	changes?: BrowserExtensionChange[];
}

export interface BrowserInstallation {
	id: string;
	name: string;
	version?: string;
	profileCount: number;
	extensions: BrowserExtension[];
	profiles?: BrowserProfile[];
}

export interface BrowserProfile {
	fingerprint: string;
	name: string;
	cookieStatus: "observed" | "partial" | "unavailable";
	cookieCount: number;
	sites: BrowserCookieSite[];
	truncated?: boolean;
}

export interface BrowserCookieSite {
	domain: string;
	cookieCount: number;
	sessionCookieCount: number;
	persistentCookieCount: number;
	secureCookieCount: number;
	httpOnlyCookieCount: number;
	lastAccessedAt?: string;
	latestExpiryAt?: string;
}

export type BrowserSiteReviewState = "signed-in-keep" | "recognized-ordinary" | "clear-candidate" | "review-later";

export interface BrowserSiteReviewKey {
	deviceId: string;
	browserId: string;
	profileFingerprint: string;
	domain: string;
}

export interface BrowserSiteReviewInput extends BrowserSiteReviewKey {
	state: BrowserSiteReviewState;
}

export interface BrowserSiteReview extends BrowserSiteReviewInput {
	reviewedAt: string;
}

export interface BrowserExtension {
	fingerprint: string;
	name: string;
	version?: string;
	state: "installed" | "active" | "disabled";
	profileCount: number;
	siteAccess: "none-declared" | "specific-sites" | "all-sites";
	optionalSiteAccess: "none-declared" | "specific-sites" | "all-sites";
	sensitivePermissions: string[];
	optionalSensitivePermissions: string[];
}

export interface BrowserProtectionStatus {
	id: string;
	name: string;
	state: "enabled" | "audit" | "disabled" | "unknown" | "default" | "clear" | "attention";
	source?: string;
	eventCount?: number;
}

export interface BrowserExtensionChange {
	id: string;
	browserId: string;
	fingerprint: string;
	extensionName: string;
	kind: "installed" | "enabled" | "permissions-expanded";
	siteAccess: "none-declared" | "specific-sites" | "all-sites";
	addedPermissions: string[];
}

export interface LinuxBaseline {
  updates: { pendingPackageCount: number | null; pendingSecurityPackageCount: number | null; pendingReboot: boolean | null } | null;
  firewall: { provider: string; active: boolean | null; defaultInboundAction?: string; defaultOutboundAction?: string } | null;
  ssh: { serverRunning: boolean | null; passwordAuthentication?: string; keyboardInteractiveAuthentication?: string; permitRootLogin?: string; publicKeyAuthentication?: string; failedLoginCount24Hours: number | null } | null;
  services: { failedUnitCount: number | null; failedUnits: string[] } | null;
  automaticUpdates: { enabled: boolean | null; active: boolean | null } | null;
  appArmor: { enabled: boolean | null } | null;
  timeSync: { synchronized: boolean | null } | null;
  storage: { mountPoint: string; fileSystem?: string; capacityBytes: number | null; availableBytes: number | null; usedPercentage: number | null } | null;
  workloads: WorkloadInventory | null;
}

export interface WorkloadInventory {
  runtime: "docker";
  collectedAt: string;
  workloads: ContainerWorkload[];
}

export interface ContainerWorkload {
  name: string;
  image?: string;
  project?: string;
  service?: string;
  state: string;
  health?: "healthy" | "unhealthy" | "starting" | "not-configured";
  ports: ContainerPortBinding[];
}

export interface ContainerPortBinding {
  protocol: "TCP" | "UDP";
  containerPort: number;
  published: boolean;
  hostAddress?: string;
  hostPort?: number;
}

export interface WindowsBaseline {
  update: { lastInstalledAt: string | null; pendingReboot: boolean | null; rebootReasons: string[]; pendingFileReplacement?: boolean | null } | null;
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

export type AlertSeverity = "high" | "medium" | "low";
export type AlertKind = "finding" | "stale-agent" | "awaiting-agent" | "new-service" | "service-drift" | "expired-service-expectation" | "appliance-stale" | "appliance-unreachable" | "appliance-service" | "appliance-certificate" | "appliance-health" | "appliance-disk" | "appliance-raid" | "appliance-capacity" | "appliance-temperature";

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

export interface PushDestination {
  id: string;
  label: string;
  createdAt: string;
  updatedAt: string;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  failureCount: number;
}

export interface PushNotificationStatus {
  available: boolean;
  vapidPublicKey: string;
  destinations: PushDestination[];
  pendingCount: number;
  failedCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  evaluationPeriodSeconds: number;
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
  systemdUnit?: string;
}

export type BindScope = "any" | "local" | "private" | "wildcard" | "specific";

export interface ExpectedServiceInput {
  deviceId: string;
  label: string;
  protocol: "TCP" | "UDP";
  port: number;
  portEnd: number;
  bindScope: BindScope;
  processNames: string[];
  workloadNames: string[];
  systemdUnits: string[];
	expiresAt?: string | null;
}

export interface ExpectedService {
  id: string;
  deviceId: string;
  label: string;
  protocol: "TCP" | "UDP";
  port: number;
  portEnd: number;
  bindScope: BindScope;
  processNames: string[];
  workloadNames: string[];
  systemdUnits: string[];
	expiresAt: string | null;
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
  agent: AgentMetadata | null;
}

export interface AgentMetadata {
  schemaVersion: number;
  version: string;
  revision: string;
  platform: string;
  installation: string;
  capabilities: string[];
  collectionNotices: number;
  compatibility: "current" | "compatible" | "development" | "version-drift" | "revision-drift";
}

export interface DeviceDetail {
  device: DeviceRecord;
  snapshot: SecuritySnapshot | null;
}

export interface ManagedApplianceStatus {
  id: string;
  displayName: string;
  kind: string;
  address: string;
  status: "pending" | "rechecking" | "attention" | "observed" | "healthy";
  configuredAt: string;
  lastCheckedAt: string | null;
  services: ManagedServiceStatus[];
  health?: ManagedHealthStatus;
}

export type ManagedHealthCoverageState = "verified" | "partial" | "unsupported" | "unavailable";
export type ManagedHealthComponentState = "healthy" | "observed" | "standby" | "warning" | "critical" | "degraded" | "failed" | "rebuilding" | "unavailable" | "unknown";

export interface ManagedHealthStatus {
  provider: string;
  status: "pending" | "unavailable" | "partial" | "healthy" | "attention";
  lastCheckedAt: string | null;
  lastChangedAt: string | null;
  consecutiveFailures: number;
  errorClass?: string;
  system: {
    model?: string;
    firmwareVersion?: string;
    kernelVersion?: string;
    uptimeSeconds?: number;
  };
  coverage: {
    disks: ManagedHealthCoverageState;
    raid: ManagedHealthCoverageState;
    temperature: ManagedHealthCoverageState;
    capacity: ManagedHealthCoverageState;
    firmware: ManagedHealthCoverageState;
  };
  disks: ManagedDiskHealth[];
  pools: ManagedPoolHealth[];
  volumes: ManagedVolumeHealth[];
  temperatures: ManagedTemperature[];
}

export interface ManagedDiskHealth {
  name: string;
  model?: string;
  capacityBytes?: number;
  state: ManagedHealthComponentState;
  smart: ManagedHealthComponentState;
  temperatureC?: number;
  lastChangedAt: string | null;
}

export interface ManagedPoolHealth {
  name: string;
  raidLevel?: string;
  state: ManagedHealthComponentState;
  memberCount: number;
  activeCount: number;
  lastChangedAt: string | null;
}

export interface ManagedVolumeHealth {
  name: string;
  capacityBytes: number;
  availableBytes: number;
  usedPercentage: number;
  state: ManagedHealthComponentState;
  lastChangedAt: string | null;
}

export interface ManagedTemperature {
  name: string;
  celsius: number;
  kind: string;
  state: ManagedHealthComponentState;
  driveStandby?: boolean;
  lastChangedAt: string | null;
}

export interface ManagedServiceStatus {
  id: string;
  name: string;
  protocol: "TCP";
  port: number;
  tls: boolean;
  required: boolean;
  reachable: boolean;
  consecutiveFailures: number;
  firstCheckedAt: string | null;
  lastCheckedAt: string | null;
  lastChangedAt: string | null;
  errorClass?: string;
  certificate?: ManagedCertificateStatus;
}

export interface ManagedCertificateStatus {
  subject: string;
  issuer: string;
  fingerprint: string;
  notBefore: string;
  notAfter: string;
  systemTrust: boolean;
  nameValid: boolean;
}

export interface RuntimeStatus {
  status: string;
  service: string;
  version: string;
  revision: string;
  agentIngestion: string;
  demoMode: boolean;
  localCollection: boolean;
  deviceFreshnessAllowanceSeconds: number;
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

export type AccountCategory = "email" | "social" | "developer" | "finance" | "gaming" | "shopping" | "work" | "other";
export type TwoStepStatus = "unknown" | "enabled" | "disabled" | "not-supported";
export type AccountFactor = "authenticator" | "passkey" | "security-key" | "provider-prompt" | "sms" | "email" | "other";
export type PasswordStatus = "unknown" | "unique" | "reused" | "passwordless" | "not-applicable";
export type RecoveryStatus = "unknown" | "configured" | "missing" | "not-supported";
export type BackupCodesStatus = "unknown" | "stored" | "missing" | "not-supported";
export type SessionStatus = "unknown" | "recognized" | "attention" | "not-supported";
export type SessionCheck = "devices" | "recent-activity" | "third-party-access" | "unused-sessions";

export interface AccountProfileInput {
  id?: string;
  provider: string;
  label: string;
  identifier?: string;
  category: AccountCategory;
  twoStepStatus: TwoStepStatus;
  factors: AccountFactor[];
  passwordStatus: PasswordStatus;
  recoveryStatus: RecoveryStatus;
  backupCodesStatus: BackupCodesStatus;
  lastReviewedAt?: string | null;
  sessionStatus: SessionStatus;
  sessionReviewedAt?: string | null;
  sessionChecks: SessionCheck[];
  reviewDetails?: string[];
  notes?: string;
}

export interface AccountAccessGrant {
  token: string;
  expiresAt: string;
  absoluteExpiresAt: string;
  idleTimeoutSeconds: number;
}

export interface AccountSuggestion {
  id: string;
  priority: "high" | "medium" | "low";
  title: string;
  summary: string;
}

export interface AccountProfile extends AccountProfileInput {
  id: string;
  status: "good" | "attention" | "incomplete";
  suggestions: AccountSuggestion[];
  createdAt: string;
  updatedAt: string;
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
