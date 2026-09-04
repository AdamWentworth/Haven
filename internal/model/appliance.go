package model

import "time"

// ManagedApplianceDefinition is an explicitly configured, credential-free
// network appliance. HAVEN probes only these declared private addresses and
// ports; it never expands them into a LAN scan.
type ManagedApplianceDefinition struct {
	ID          string                     `json:"id"`
	DisplayName string                     `json:"displayName"`
	Kind        string                     `json:"kind"`
	Address     string                     `json:"address"`
	Services    []ManagedServiceDefinition `json:"services"`
}

type ManagedServiceDefinition struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	TLS      bool   `json:"tls"`
	Required bool   `json:"required"`
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
