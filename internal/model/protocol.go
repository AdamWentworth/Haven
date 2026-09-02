package model

import "time"

const ObservationSchemaVersion = 2

// ObservationEnvelope is the versioned message accepted from an enrolled
// agent. Device identity is derived from the client certificate by the hub;
// DeviceID is present only so mismatches can be rejected explicitly.
type ObservationEnvelope struct {
	SchemaVersion int              `json:"schemaVersion"`
	ObservationID string           `json:"observationId"`
	DeviceID      string           `json:"deviceId"`
	Sequence      int64            `json:"sequence"`
	SentAt        time.Time        `json:"sentAt"`
	Snapshot      SecuritySnapshot `json:"snapshot"`
}

type EnrollmentRequest struct {
	Token       string `json:"token"`
	DisplayName string `json:"displayName"`
	CSRPEM      string `json:"csrPem"`
}

type EnrollmentResponse struct {
	SchemaVersion  int       `json:"schemaVersion"`
	DeviceID       string    `json:"deviceId"`
	CertificatePEM string    `json:"certificatePem"`
	CACertificate  string    `json:"caCertificatePem"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type ObservationReceipt struct {
	ObservationID string    `json:"observationId"`
	AcceptedAt    time.Time `json:"acceptedAt"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
