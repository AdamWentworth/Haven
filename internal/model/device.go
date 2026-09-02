package model

import "time"

type DeviceRecord struct {
	ID                   string     `json:"id"`
	DisplayName          string     `json:"displayName"`
	HostName             string     `json:"hostName"`
	OperatingSystem      string     `json:"operatingSystem"`
	Architecture         string     `json:"architecture"`
	TrustState           string     `json:"trustState"`
	Status               string     `json:"status"`
	EnrolledAt           time.Time  `json:"enrolledAt"`
	LastSeenAt           *time.Time `json:"lastSeenAt"`
	LastCollectedAt      *time.Time `json:"lastCollectedAt"`
	CertificateExpiresAt *time.Time `json:"certificateExpiresAt"`
	RevokedAt            *time.Time `json:"revokedAt"`
}

type DeviceDetail struct {
	Device   DeviceRecord      `json:"device"`
	Snapshot *SecuritySnapshot `json:"snapshot"`
}
