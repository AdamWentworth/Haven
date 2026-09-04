package model

import "time"

// ManagedApplianceDefinition is an explicitly configured network appliance.
// HAVEN probes only these declared private addresses and ports; it never
// expands them into a LAN scan. Optional health credentials are file-backed.
type ManagedApplianceDefinition struct {
	ID          string                     `json:"id"`
	DisplayName string                     `json:"displayName"`
	Kind        string                     `json:"kind"`
	Address     string                     `json:"address"`
	Services    []ManagedServiceDefinition `json:"services"`
	Health      *ManagedHealthDefinition   `json:"health,omitempty"`
}

type ManagedServiceDefinition struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	TLS      bool   `json:"tls"`
	Required bool   `json:"required"`
}

// ManagedHealthDefinition describes an explicitly configured, read-only
// health source. Credential contents live in mounted files and are never part
// of deployment configuration, API responses, or persisted observations.
type ManagedHealthDefinition struct {
	Provider          string `json:"provider"`
	SNMPPort          int    `json:"snmpPort"`
	CommunityFile     string `json:"communityFile"`
	SSHPort           int    `json:"sshPort"`
	SSHUsername       string `json:"sshUsername"`
	SSHPrivateKeyFile string `json:"sshPrivateKeyFile"`
	SSHHostKeySHA256  string `json:"sshHostKeySHA256"`
}

// ManagedApplianceStatus is the latest hub-observed state. It contains no
// credentials, response bodies, packet payloads, or discovered services.
type ManagedApplianceStatus struct {
	ID            string                 `json:"id"`
	DisplayName   string                 `json:"displayName"`
	Kind          string                 `json:"kind"`
	Address       string                 `json:"address"`
	Status        string                 `json:"status"`
	ConfiguredAt  time.Time              `json:"configuredAt"`
	LastCheckedAt *time.Time             `json:"lastCheckedAt"`
	Services      []ManagedServiceStatus `json:"services"`
	Health        *ManagedHealthStatus   `json:"health,omitempty"`
}

type ManagedServiceStatus struct {
	ID                  string                    `json:"id"`
	Name                string                    `json:"name"`
	Protocol            string                    `json:"protocol"`
	Port                int                       `json:"port"`
	TLS                 bool                      `json:"tls"`
	Required            bool                      `json:"required"`
	Reachable           bool                      `json:"reachable"`
	ConsecutiveFailures int                       `json:"consecutiveFailures"`
	FirstCheckedAt      *time.Time                `json:"firstCheckedAt"`
	LastCheckedAt       *time.Time                `json:"lastCheckedAt"`
	LastChangedAt       *time.Time                `json:"lastChangedAt"`
	ErrorClass          string                    `json:"errorClass,omitempty"`
	Certificate         *ManagedCertificateStatus `json:"certificate,omitempty"`
}

type ManagedCertificateStatus struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	SystemTrust bool      `json:"systemTrust"`
	NameValid   bool      `json:"nameValid"`
}

// ManagedHealthStatus is bounded current evidence. Unsupported means the
// configured provider does not expose the signal; unavailable means a signal
// that should exist could not be collected. Neither state is treated as
// healthy.
type ManagedHealthStatus struct {
	Provider            string                `json:"provider"`
	Status              string                `json:"status"`
	LastCheckedAt       *time.Time            `json:"lastCheckedAt"`
	LastChangedAt       *time.Time            `json:"lastChangedAt"`
	ConsecutiveFailures int                   `json:"consecutiveFailures"`
	ErrorClass          string                `json:"errorClass,omitempty"`
	System              ManagedSystemHealth   `json:"system"`
	Coverage            ManagedHealthCoverage `json:"coverage"`
	Disks               []ManagedDiskHealth   `json:"disks"`
	Pools               []ManagedPoolHealth   `json:"pools"`
	Volumes             []ManagedVolumeHealth `json:"volumes"`
	Temperatures        []ManagedTemperature  `json:"temperatures"`
}

// ManagedHealthReport is the fixed, credential-free response emitted by a
// narrowly constrained appliance-side helper. It intentionally excludes
// identifiers such as disk serial numbers, network settings, and account data.
type ManagedHealthReport struct {
	System       ManagedSystemHealth   `json:"system"`
	Coverage     ManagedHealthCoverage `json:"coverage"`
	Disks        []ManagedDiskHealth   `json:"disks"`
	Pools        []ManagedPoolHealth   `json:"pools"`
	Volumes      []ManagedVolumeHealth `json:"volumes"`
	Temperatures []ManagedTemperature  `json:"temperatures"`
}

type ManagedSystemHealth struct {
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmwareVersion,omitempty"`
	KernelVersion   string `json:"kernelVersion,omitempty"`
	UptimeSeconds   *int64 `json:"uptimeSeconds,omitempty"`
}

type ManagedHealthCoverage struct {
	Disks       string `json:"disks"`
	RAID        string `json:"raid"`
	Temperature string `json:"temperature"`
	Capacity    string `json:"capacity"`
	Firmware    string `json:"firmware"`
}

type ManagedDiskHealth struct {
	Name          string     `json:"name"`
	Model         string     `json:"model,omitempty"`
	CapacityBytes *uint64    `json:"capacityBytes,omitempty"`
	State         string     `json:"state"`
	SMART         string     `json:"smart"`
	TemperatureC  *float64   `json:"temperatureC,omitempty"`
	LastChangedAt *time.Time `json:"lastChangedAt"`
}

type ManagedPoolHealth struct {
	Name          string     `json:"name"`
	RAIDLevel     string     `json:"raidLevel,omitempty"`
	State         string     `json:"state"`
	MemberCount   int        `json:"memberCount"`
	ActiveCount   int        `json:"activeCount"`
	LastChangedAt *time.Time `json:"lastChangedAt"`
}

type ManagedVolumeHealth struct {
	Name           string     `json:"name"`
	CapacityBytes  uint64     `json:"capacityBytes"`
	AvailableBytes uint64     `json:"availableBytes"`
	UsedPercentage float64    `json:"usedPercentage"`
	State          string     `json:"state"`
	LastChangedAt  *time.Time `json:"lastChangedAt"`
}

type ManagedTemperature struct {
	Name          string     `json:"name"`
	Celsius       float64    `json:"celsius"`
	Kind          string     `json:"kind"`
	State         string     `json:"state"`
	DriveStandby  bool       `json:"driveStandby,omitempty"`
	LastChangedAt *time.Time `json:"lastChangedAt"`
}
