package model

import "time"

// SecuritySnapshot is one point-in-time observation reported by a collector.
// It contains posture metadata only, never credentials or packet payloads.
type SecuritySnapshot struct {
	CollectedAt      time.Time               `json:"collectedAt"`
	Device           DeviceSummary           `json:"device"`
	BrowserSecurity  *BrowserSecurityStatus  `json:"browserSecurity"`
	Defender         *DefenderStatus         `json:"defender"`
	WindowsBaseline  *WindowsBaseline        `json:"windowsBaseline"`
	LinuxBaseline    *LinuxBaseline          `json:"linuxBaseline"`
	BaselineChecks   []BaselineCheck         `json:"baselineChecks"`
	Findings         []SecurityFinding       `json:"findings"`
	FirewallProfiles []FirewallProfileStatus `json:"firewallProfiles"`
	Connections      []NetworkConnection     `json:"connections"`
	Notices          []CollectorNotice       `json:"notices"`
}

// BrowserSecurityStatus is a deliberately narrow inventory of supported
// browser installations, manifest-declared extension capabilities, and
// platform web protections. It never contains profile names, extension IDs,
// host match patterns, browsing history, cookies, credentials, tokens, page
// contents, or saved form data. Extension fingerprints are one-way hashes used
// only to correlate the same installation between observations.
type BrowserSecurityStatus struct {
	Coverage    string                    `json:"coverage"`
	Browsers    []BrowserInstallation     `json:"browsers"`
	Protections []BrowserProtectionStatus `json:"protections"`
}

type BrowserInstallation struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version,omitempty"`
	ProfileCount int                `json:"profileCount"`
	Extensions   []BrowserExtension `json:"extensions"`
}

type BrowserExtension struct {
	Fingerprint                  string   `json:"fingerprint"`
	Name                         string   `json:"name"`
	Version                      string   `json:"version,omitempty"`
	State                        string   `json:"state"`
	ProfileCount                 int      `json:"profileCount"`
	SiteAccess                   string   `json:"siteAccess"`
	OptionalSiteAccess           string   `json:"optionalSiteAccess"`
	SensitivePermissions         []string `json:"sensitivePermissions"`
	OptionalSensitivePermissions []string `json:"optionalSensitivePermissions"`
}

type BrowserProtectionStatus struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Source string `json:"source,omitempty"`
}

// LinuxBaseline contains host-level, privacy-bounded Linux posture. It keeps
// counts and effective configuration states, never usernames, login source
// addresses, package names, journal contents, or file paths from user data.
// Failed systemd unit names are bounded and sanitized because the name is the
// minimum useful identifier for investigating a failed service.
type LinuxBaseline struct {
	Updates          *LinuxUpdateStatus          `json:"updates"`
	Firewall         *LinuxFirewallStatus        `json:"firewall"`
	SSH              *LinuxSSHStatus             `json:"ssh"`
	Services         *LinuxServiceStatus         `json:"services"`
	AutomaticUpdates *LinuxAutomaticUpdateStatus `json:"automaticUpdates"`
	AppArmor         *LinuxAppArmorStatus        `json:"appArmor"`
	TimeSync         *LinuxTimeSyncStatus        `json:"timeSync"`
	Storage          *LinuxStorageStatus         `json:"storage"`
	Workloads        *WorkloadInventory          `json:"workloads"`
}

type LinuxUpdateStatus struct {
	PendingPackageCount         *int  `json:"pendingPackageCount"`
	PendingSecurityPackageCount *int  `json:"pendingSecurityPackageCount"`
	PendingReboot               *bool `json:"pendingReboot"`
}

type LinuxFirewallStatus struct {
	Provider              string `json:"provider"`
	Active                *bool  `json:"active"`
	DefaultInboundAction  string `json:"defaultInboundAction,omitempty"`
	DefaultOutboundAction string `json:"defaultOutboundAction,omitempty"`
}

type LinuxSSHStatus struct {
	ServerRunning                     *bool  `json:"serverRunning"`
	PasswordAuthentication            string `json:"passwordAuthentication,omitempty"`
	KeyboardInteractiveAuthentication string `json:"keyboardInteractiveAuthentication,omitempty"`
	PermitRootLogin                   string `json:"permitRootLogin,omitempty"`
	PublicKeyAuthentication           string `json:"publicKeyAuthentication,omitempty"`
	FailedLoginCount24Hours           *int   `json:"failedLoginCount24Hours"`
}

type LinuxServiceStatus struct {
	FailedUnitCount *int     `json:"failedUnitCount"`
	FailedUnits     []string `json:"failedUnits"`
}

type LinuxAutomaticUpdateStatus struct {
	Enabled *bool `json:"enabled"`
	Active  *bool `json:"active"`
}

type LinuxAppArmorStatus struct {
	Enabled *bool `json:"enabled"`
}

type LinuxTimeSyncStatus struct {
	Synchronized *bool `json:"synchronized"`
}

type LinuxStorageStatus struct {
	MountPoint     string   `json:"mountPoint"`
	FileSystem     string   `json:"fileSystem,omitempty"`
	CapacityBytes  *int64   `json:"capacityBytes"`
	AvailableBytes *int64   `json:"availableBytes"`
	UsedPercentage *float64 `json:"usedPercentage"`
}

// WorkloadInventory is a deliberately narrow, live-only view of a container
// runtime. It excludes environment variables, commands, mounts, arbitrary
// labels, logs, container IDs, container network addresses, remote endpoints,
// and control capabilities. Host bind addresses are retained only so a
// published port can be correlated with a host listener.
type WorkloadInventory struct {
	Runtime     string              `json:"runtime"`
	CollectedAt time.Time           `json:"collectedAt"`
	Workloads   []ContainerWorkload `json:"workloads"`
}

type ContainerWorkload struct {
	Name    string                 `json:"name"`
	Image   string                 `json:"image,omitempty"`
	Project string                 `json:"project,omitempty"`
	Service string                 `json:"service,omitempty"`
	State   string                 `json:"state"`
	Health  string                 `json:"health,omitempty"`
	Ports   []ContainerPortBinding `json:"ports"`
}

type ContainerPortBinding struct {
	Protocol      string `json:"protocol"`
	ContainerPort int    `json:"containerPort"`
	Published     bool   `json:"published"`
	HostAddress   string `json:"hostAddress,omitempty"`
	HostPort      int    `json:"hostPort,omitempty"`
}

// WindowsBaseline contains privacy-bounded host posture. It records counts and
// configuration state, never account names, threat resource paths, or update
// titles.
type WindowsBaseline struct {
	Update           *WindowsUpdateStatus    `json:"update"`
	SystemEncryption *DiskEncryptionStatus   `json:"systemEncryption"`
	PlatformSecurity *PlatformSecurityStatus `json:"platformSecurity"`
	RemoteAccess     *RemoteAccessStatus     `json:"remoteAccess"`
	LocalAccounts    *LocalAccountStatus     `json:"localAccounts"`
	Threats          *DefenderThreatStatus   `json:"threats"`
}

type WindowsUpdateStatus struct {
	LastInstalledAt        *time.Time `json:"lastInstalledAt"`
	PendingReboot          *bool      `json:"pendingReboot"`
	RebootReasons          []string   `json:"rebootReasons"`
	PendingFileReplacement *bool      `json:"pendingFileReplacement"`
}

type DiskEncryptionStatus struct {
	SystemDrive          string   `json:"systemDrive"`
	VolumeStatus         string   `json:"volumeStatus"`
	ProtectionStatus     string   `json:"protectionStatus"`
	EncryptionPercentage *float64 `json:"encryptionPercentage"`
}

type PlatformSecurityStatus struct {
	SecureBootEnabled *bool  `json:"secureBootEnabled"`
	TPMPresent        *bool  `json:"tpmPresent"`
	TPMReady          *bool  `json:"tpmReady"`
	TPMVersion        string `json:"tpmVersion,omitempty"`
	TPMManufacturer   string `json:"tpmManufacturer,omitempty"`
	TPMSource         string `json:"tpmSource,omitempty"`
}

type RemoteAccessStatus struct {
	RemoteDesktopEnabled     *bool  `json:"remoteDesktopEnabled"`
	NetworkLevelAuthRequired *bool  `json:"networkLevelAuthRequired"`
	RDPFirewallScope         string `json:"rdpFirewallScope,omitempty"`
	RDPFirewallRuleCount     *int   `json:"rdpFirewallRuleCount"`
	RemoteAssistanceEnabled  *bool  `json:"remoteAssistanceEnabled"`
	SMB1Enabled              *bool  `json:"smb1Enabled"`
	OpenSSHServerRunning     *bool  `json:"openSshServerRunning"`
}

type LocalAccountStatus struct {
	AdministratorCount        *int `json:"administratorCount"`
	EnabledAdministratorCount *int `json:"enabledAdministratorCount"`
}

type DefenderThreatStatus struct {
	ActiveThreatCount    *int       `json:"activeThreatCount"`
	RecentDetectionCount *int       `json:"recentDetectionCount"`
	LastDetectedAt       *time.Time `json:"lastDetectedAt"`
}

type BaselineCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence,omitempty"`
}

type SecurityFinding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Summary        string `json:"summary"`
	Recommendation string `json:"recommendation"`
}

// SecurityEvent records a privacy-bounded finding transition. It deliberately
// excludes connection metadata, account names, threat paths, and credentials.
type SecurityEvent struct {
	ID         int64     `json:"id"`
	DeviceID   string    `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	FindingID  string    `json:"findingId"`
	Kind       string    `json:"kind"`
	Category   string    `json:"category"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Summary    string    `json:"summary"`
	OccurredAt time.Time `json:"occurredAt"`
}

// Alert is the hub-owned projection of a currently actionable fact. ID stays
// stable for one logical condition; InstanceID changes when that condition
// resolves and later recurs or when its evidence materially changes.
type Alert struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instanceId"`
	DeviceID   string    `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	Evidence   string    `json:"evidence"`
	StartedAt  time.Time `json:"startedAt"`
}

type MonitorStatus struct {
	Enabled             bool       `json:"enabled"`
	IntervalSeconds     int64      `json:"intervalSeconds"`
	LastAttemptAt       *time.Time `json:"lastAttemptAt"`
	LastSuccessfulAt    *time.Time `json:"lastSuccessfulAt"`
	LastCollectionError string     `json:"lastCollectionError,omitempty"`
}

type DeviceSummary struct {
	DeviceID        string `json:"deviceId,omitempty"`
	HostName        string `json:"hostName"`
	OperatingSystem string `json:"operatingSystem"`
	Architecture    string `json:"architecture"`
	UptimeSeconds   *int64 `json:"uptimeSeconds"`
}

type DefenderStatus struct {
	AntivirusEnabled          *bool      `json:"antivirusEnabled"`
	RealTimeProtectionEnabled *bool      `json:"realTimeProtectionEnabled"`
	BehaviorMonitorEnabled    *bool      `json:"behaviorMonitorEnabled"`
	DownloadProtectionEnabled *bool      `json:"downloadProtectionEnabled"`
	TamperProtected           *bool      `json:"tamperProtected"`
	TamperProtectionSource    string     `json:"tamperProtectionSource,omitempty"`
	SignatureVersion          string     `json:"signatureVersion,omitempty"`
	SignatureUpdatedAt        *time.Time `json:"signatureUpdatedAt"`
	LastQuickScanAt           *time.Time `json:"lastQuickScanAt"`
	LastFullScanAt            *time.Time `json:"lastFullScanAt"`
}

type FirewallProfileStatus struct {
	Name                  string `json:"name"`
	Enabled               *bool  `json:"enabled"`
	DefaultInboundAction  string `json:"defaultInboundAction,omitempty"`
	DefaultOutboundAction string `json:"defaultOutboundAction,omitempty"`
	LogFileName           string `json:"logFileName,omitempty"`
}

type NetworkConnection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"localAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	State         string `json:"state"`
	ProcessID     int    `json:"processId"`
	ProcessName   string `json:"processName"`
	SystemdUnit   string `json:"systemdUnit,omitempty"`
}

type CollectorNotice struct {
	Source   string `json:"source"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
