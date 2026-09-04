package hub

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/posture"
	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/AdamWentworth/haven/internal/trust"
)

const (
	maximumEnrollmentBody  = 64 << 10
	maximumObservationBody = 1 << 20
)

type AgentServer struct {
	store  *storage.Store
	pki    *trust.HubPKI
	logger *slog.Logger
	now    func() time.Time
	limits map[string]rateWindow
	mutex  sync.Mutex
}

type rateWindow struct {
	started time.Time
	count   int
}

func NewAgentServer(store *storage.Store, pki *trust.HubPKI, logger *slog.Logger) *AgentServer {
	return &AgentServer{store: store, pki: pki, logger: logger, now: time.Now, limits: make(map[string]rateWindow)}
}

func (server *AgentServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", server.enroll)
	mux.HandleFunc("POST /v1/observations", server.observe)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			server.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func (server *AgentServer) enroll(writer http.ResponseWriter, request *http.Request) {
	if !server.allow("enroll:"+remoteHost(request.RemoteAddr), 12, 5*time.Minute) {
		writer.Header().Set("Retry-After", "300")
		server.writeError(writer, http.StatusTooManyRequests, "rate_limited", "Too many enrollment attempts. Try again later.")
		return
	}
	var enrollment model.EnrollmentRequest
	if err := decodeJSON(writer, request, maximumEnrollmentBody, &enrollment); err != nil {
		server.writeError(writer, http.StatusBadRequest, "invalid_enrollment", err.Error())
		return
	}
	enrollment.DisplayName = strings.TrimSpace(enrollment.DisplayName)
	if enrollment.DisplayName == "" || len(enrollment.DisplayName) > 80 || !strings.HasPrefix(enrollment.Token, "enr_") {
		server.writeError(writer, http.StatusBadRequest, "invalid_enrollment", "Enrollment details are invalid.")
		return
	}

	now := server.now().UTC()
	deviceID, err := trust.NewDeviceID()
	if err != nil {
		server.internalError(writer, "generate device identity", err)
		return
	}
	certificatePEM, certificate, err := server.pki.SignAgentCertificate(
		[]byte(enrollment.CSRPEM),
		deviceID,
		now,
		90*24*time.Hour,
	)
	if err != nil {
		server.writeError(writer, http.StatusBadRequest, "invalid_certificate_request", "The agent certificate request is invalid.")
		return
	}
	err = server.store.ConsumeEnrollmentToken(
		request.Context(),
		trust.HashEnrollmentToken(enrollment.Token),
		storage.EnrollmentDevice{
			ID:                   deviceID,
			DisplayName:          enrollment.DisplayName,
			CertificateSerial:    trust.CertificateSerial(certificate),
			CertificateExpiresAt: certificate.NotAfter,
		},
		now,
	)
	if errors.Is(err, storage.ErrEnrollmentInvalid) {
		server.writeError(writer, http.StatusUnauthorized, "enrollment_rejected", "The enrollment token is invalid, expired, or already used.")
		return
	}
	if err != nil {
		server.internalError(writer, "enroll device", err)
		return
	}

	server.writeJSON(writer, http.StatusCreated, model.EnrollmentResponse{
		SchemaVersion:  model.ObservationSchemaVersion,
		DeviceID:       deviceID,
		CertificatePEM: string(certificatePEM),
		CACertificate:  string(server.pki.CACertificatePEM),
		ExpiresAt:      certificate.NotAfter,
	})
}

func (server *AgentServer) observe(writer http.ResponseWriter, request *http.Request) {
	certificate, err := verifiedClientCertificate(request)
	if err != nil {
		server.writeError(writer, http.StatusUnauthorized, "client_certificate_required", "A valid enrolled device certificate is required.")
		return
	}
	certificateDeviceID, err := trust.DeviceIDFromCertificate(certificate)
	if err != nil {
		server.writeError(writer, http.StatusUnauthorized, "invalid_device_identity", "The client certificate has no valid HAVEN identity.")
		return
	}
	if !server.allow("observe:"+certificateDeviceID, 120, time.Minute) {
		writer.Header().Set("Retry-After", "60")
		server.writeError(writer, http.StatusTooManyRequests, "rate_limited", "This device is reporting too frequently.")
		return
	}

	var envelope model.ObservationEnvelope
	if err := decodeJSON(writer, request, maximumObservationBody, &envelope); err != nil {
		server.writeError(writer, http.StatusBadRequest, "invalid_observation", err.Error())
		return
	}
	now := server.now().UTC()
	if envelope.SchemaVersion != model.ObservationSchemaVersion {
		server.writeError(writer, http.StatusUnprocessableEntity, "unsupported_schema", "The observation schema version is not supported.")
		return
	}
	if envelope.DeviceID != certificateDeviceID || envelope.ObservationID == "" || len(envelope.ObservationID) > 80 || envelope.Sequence < 1 {
		server.writeError(writer, http.StatusUnprocessableEntity, "invalid_observation", "The observation identity or sequence is invalid.")
		return
	}
	if envelope.SentAt.Before(now.Add(-15*time.Minute)) || envelope.SentAt.After(now.Add(2*time.Minute)) {
		server.writeError(writer, http.StatusUnprocessableEntity, "clock_out_of_range", "The observation timestamp is outside the accepted window.")
		return
	}
	if envelope.Snapshot.CollectedAt.IsZero() || envelope.Snapshot.CollectedAt.After(now.Add(2*time.Minute)) {
		server.writeError(writer, http.StatusUnprocessableEntity, "invalid_collection_time", "The collection timestamp is invalid.")
		return
	}

	envelope.Snapshot = posture.Evaluate(envelope.Snapshot, now)
	err = server.store.AcceptObservation(
		request.Context(),
		trust.CertificateSerial(certificate),
		envelope,
		now,
	)
	switch {
	case errors.Is(err, storage.ErrAlreadyAccepted):
		server.writeJSON(writer, http.StatusAccepted, model.ObservationReceipt{
			ObservationID: envelope.ObservationID,
			AcceptedAt:    now,
		})
		return
	case errors.Is(err, storage.ErrReplay):
		server.writeError(writer, http.StatusConflict, "replay_rejected", "This observation sequence has already been accepted.")
		return
	case errors.Is(err, storage.ErrRevokedDevice):
		server.writeError(writer, http.StatusForbidden, "device_revoked", "This device has been revoked.")
		return
	case errors.Is(err, storage.ErrUnknownDevice):
		server.writeError(writer, http.StatusForbidden, "device_not_enrolled", "This certificate is not enrolled.")
		return
	case err != nil:
		server.internalError(writer, "accept observation", err)
		return
	}

	server.writeJSON(writer, http.StatusAccepted, model.ObservationReceipt{
		ObservationID: envelope.ObservationID,
		AcceptedAt:    now,
	})
}

func (server *AgentServer) allow(key string, maximum int, duration time.Duration) bool {
	now := server.now().UTC()
	server.mutex.Lock()
	defer server.mutex.Unlock()
	window := server.limits[key]
	if window.started.IsZero() || now.Sub(window.started) >= duration {
		server.limits[key] = rateWindow{started: now, count: 1}
		return true
	}
	window.count++
	server.limits[key] = window
	return window.count <= maximum
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func verifiedClientCertificate(request *http.Request) (*x509.Certificate, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return nil, errors.New("no verified client certificate")
	}
	return request.TLS.VerifiedChains[0][0], nil
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, maximum int64, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maximum)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("Request JSON is invalid or exceeds the allowed size.")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("Request body must contain exactly one JSON value.")
	}
	return nil
}

func (server *AgentServer) internalError(writer http.ResponseWriter, operation string, err error) {
	server.logger.Error("agent API failure", "operation", operation, "error", err)
	server.writeError(writer, http.StatusInternalServerError, "internal_error", "HAVEN could not complete the request.")
}

func (server *AgentServer) writeError(writer http.ResponseWriter, status int, code, message string) {
	server.writeJSON(writer, status, model.APIError{Code: code, Message: message})
}

func (server *AgentServer) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		server.logger.Error("could not encode agent response", "error", err)
	}
}
