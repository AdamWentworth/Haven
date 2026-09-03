package hub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/action"
	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/storage"
)

type authStatus struct {
	Configured          bool   `json:"configured"`
	Authenticated       bool   `json:"authenticated"`
	Origin              string `json:"origin"`
	UseConfiguredOrigin bool   `json:"useConfiguredOrigin"`
}

func (server *Server) registerAuthenticationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", server.authenticationStatus)
	if server.auth == nil {
		return
	}
	mux.HandleFunc("POST /api/auth/register/begin", server.beginRegistration)
	mux.HandleFunc("POST /api/auth/register/finish", server.finishRegistration)
	mux.HandleFunc("POST /api/auth/login/begin", server.beginLogin)
	mux.HandleFunc("POST /api/auth/login/finish", server.finishLogin)
	mux.Handle("POST /api/auth/reauthorize/begin", server.mutating(http.HandlerFunc(server.beginReauthorization)))
	mux.Handle("POST /api/auth/reauthorize/finish", server.mutating(http.HandlerFunc(server.finishReauthorization)))
	mux.Handle("POST /api/auth/logout", server.mutating(http.HandlerFunc(server.logout)))
	mux.Handle("GET /api/passkeys", server.protected(http.HandlerFunc(server.passkeys)))
	mux.Handle("POST /api/passkeys/register/begin", server.mutating(http.HandlerFunc(server.beginAdditionalPasskey)))
	mux.Handle("POST /api/passkeys/register/finish", server.mutating(http.HandlerFunc(server.finishAdditionalPasskey)))
	mux.Handle("POST /api/passkeys/remove", server.mutating(http.HandlerFunc(server.removePasskey)))
}

func (server *Server) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.demoMode || server.auth == nil {
			next.ServeHTTP(writer, request)
			return
		}
		cookie, err := request.Cookie(authn.SessionCookie)
		if err != nil {
			server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "Passkey sign-in is required."})
			return
		}
		valid, err := server.auth.ValidateSession(request.Context(), cookie.Value, time.Now().UTC())
		if err != nil || !valid {
			server.clearAuthCookies(writer)
			server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "Your HAVEN session has expired. Sign in again."})
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) mutating(next http.Handler) http.Handler {
	return server.protected(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.demoMode || server.auth == nil {
			next.ServeHTTP(writer, request)
			return
		}
		if request.Header.Get("Origin") != server.auth.Origin() {
			server.writeJSON(writer, http.StatusForbidden, map[string]string{"error": "The request origin was rejected."})
			return
		}
		sessionCookie, sessionErr := request.Cookie(authn.SessionCookie)
		csrfCookie, csrfErr := request.Cookie(authn.CSRFCookie)
		if sessionErr != nil || csrfErr != nil || server.auth.ValidateCSRF(request.Context(), sessionCookie.Value, csrfCookie.Value, request.Header.Get("X-HAVEN-CSRF"), time.Now().UTC()) != nil {
			server.writeJSON(writer, http.StatusForbidden, map[string]string{"error": "The anti-forgery check failed."})
			return
		}
		next.ServeHTTP(writer, request)
	}))
}

func (server *Server) authenticationStatus(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.demoMode || server.auth == nil {
		server.writeJSON(writer, http.StatusOK, authStatus{Configured: true, Authenticated: true})
		return
	}
	configured, err := server.auth.Configured(request.Context())
	if err != nil {
		http.Error(writer, "could not read authentication status", http.StatusInternalServerError)
		return
	}
	authenticated := false
	if cookie, cookieErr := request.Cookie(authn.SessionCookie); cookieErr == nil {
		authenticated, _ = server.auth.ValidateSession(request.Context(), cookie.Value, time.Now().UTC())
	}
	configuredOrigin, _ := url.Parse(server.auth.Origin())
	server.writeJSON(writer, http.StatusOK, authStatus{
		Configured:          configured,
		Authenticated:       authenticated,
		Origin:              server.auth.Origin(),
		UseConfiguredOrigin: !strings.EqualFold(request.Host, configuredOrigin.Host),
	})
}

func (server *Server) beginRegistration(writer http.ResponseWriter, request *http.Request) {
	if !server.allowAuthAttempt(request) {
		server.writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "Too many authentication attempts. Wait a minute and try again."})
		return
	}
	var body struct {
		BootstrapCode string `json:"bootstrapCode"`
		Label         string `json:"label"`
	}
	if !decodeControlJSON(writer, request, &body, 4096) {
		return
	}
	response, err := server.auth.BeginRegistration(request.Context(), body.BootstrapCode, body.Label, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, response)
}

func (server *Server) finishRegistration(writer http.ResponseWriter, request *http.Request) {
	if !server.allowAuthAttempt(request) {
		server.writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "Too many authentication attempts. Wait a minute and try again."})
		return
	}
	session, err := server.auth.FinishRegistration(request.Context(), request.Header.Get("X-HAVEN-Ceremony"), request, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.setAuthCookies(writer, session)
	server.writeJSON(writer, http.StatusCreated, map[string]bool{"authenticated": true})
}

func (server *Server) beginLogin(writer http.ResponseWriter, request *http.Request) {
	if !server.allowAuthAttempt(request) {
		server.writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "Too many authentication attempts. Wait a minute and try again."})
		return
	}
	response, err := server.auth.BeginLogin(request.Context(), time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, response)
}

func (server *Server) finishLogin(writer http.ResponseWriter, request *http.Request) {
	if !server.allowAuthAttempt(request) {
		server.writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "Too many authentication attempts. Wait a minute and try again."})
		return
	}
	session, err := server.auth.FinishLogin(request.Context(), request.Header.Get("X-HAVEN-Ceremony"), request, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.setAuthCookies(writer, session)
	server.writeJSON(writer, http.StatusOK, map[string]bool{"authenticated": true})
}

func (server *Server) beginReauthorization(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Scope string `json:"scope"`
	}
	if !decodeControlJSON(writer, request, &body, 1024) {
		return
	}
	if !validReauthorizationScope(body.Scope) {
		http.Error(writer, "invalid reauthorization scope", http.StatusBadRequest)
		return
	}
	response, err := server.auth.BeginReauthorization(request.Context(), body.Scope, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, response)
}

func (server *Server) finishReauthorization(writer http.ResponseWriter, request *http.Request) {
	sessionCookie, err := request.Cookie(authn.SessionCookie)
	if err != nil {
		server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "Passkey sign-in is required."})
		return
	}
	token, err := server.auth.FinishReauthorization(request.Context(), request.Header.Get("X-HAVEN-Ceremony"), sessionCookie.Value, request, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, map[string]string{"reauthorizationToken": token})
}

func (server *Server) passkeys(writer http.ResponseWriter, request *http.Request) {
	items, err := server.auth.Passkeys(request.Context())
	if err != nil {
		http.Error(writer, "could not list passkeys", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, items)
}

func (server *Server) beginAdditionalPasskey(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	if !decodeControlJSON(writer, request, &body, 1024) {
		return
	}
	if !server.consumeReauthorization(writer, request, "passkey:add") {
		return
	}
	response, err := server.auth.BeginAdditionalRegistration(request.Context(), body.Label, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusOK, response)
}

func (server *Server) finishAdditionalPasskey(writer http.ResponseWriter, request *http.Request) {
	item, err := server.auth.FinishAdditionalRegistration(request.Context(), request.Header.Get("X-HAVEN-Ceremony"), request, time.Now().UTC())
	if err != nil {
		server.authError(writer, err)
		return
	}
	server.writeJSON(writer, http.StatusCreated, item)
}

func (server *Server) removePasskey(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !decodeControlJSON(writer, request, &body, 2048) {
		return
	}
	if len(body.ID) > 1024 || body.ID == "" {
		http.Error(writer, "invalid passkey identity", http.StatusBadRequest)
		return
	}
	if !server.consumeReauthorization(writer, request, "passkey:remove:"+body.ID) {
		return
	}
	if err := server.auth.RemovePasskey(request.Context(), body.ID, time.Now().UTC()); errors.Is(err, authn.ErrFinalPasskey) {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "The final passkey cannot be removed. Add a replacement first."})
		return
	} else if err != nil {
		http.Error(writer, "could not remove passkey", http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) logout(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(authn.SessionCookie); err == nil {
		_ = server.auth.Logout(request.Context(), cookie.Value)
	}
	server.clearAuthCookies(writer)
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "auth.logout", Target: "owner", Outcome: "succeeded", Detail: "HAVEN session ended.", OccurredAt: time.Now().UTC()})
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) allowAuthAttempt(request *http.Request) bool {
	if server.auth == nil {
		return false
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	return server.auth.AllowAttempt(host, time.Now().UTC())
}

func (server *Server) authError(writer http.ResponseWriter, err error) {
	server.logger.Warn("authentication ceremony rejected", "error", err)
	status := http.StatusUnauthorized
	message := "The passkey ceremony could not be verified."
	if errors.Is(err, authn.ErrNotConfigured) {
		status = http.StatusPreconditionRequired
		message = "HAVEN needs its first passkey."
	}
	server.writeJSON(writer, status, map[string]string{"error": message})
}

func (server *Server) setAuthCookies(writer http.ResponseWriter, session authn.Session) {
	http.SetCookie(writer, &http.Cookie{Name: authn.SessionCookie, Value: session.Token, Path: "/", Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds()), HttpOnly: true, Secure: server.auth.SecureCookies(), SameSite: http.SameSiteStrictMode})
	http.SetCookie(writer, &http.Cookie{Name: authn.CSRFCookie, Value: session.CSRFToken, Path: "/", Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds()), HttpOnly: false, Secure: server.auth.SecureCookies(), SameSite: http.SameSiteStrictMode})
}

func (server *Server) clearAuthCookies(writer http.ResponseWriter) {
	secure := server.auth != nil && server.auth.SecureCookies()
	http.SetCookie(writer, &http.Cookie{Name: authn.SessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(writer, &http.Cookie{Name: authn.CSRFCookie, Path: "/", MaxAge: -1, HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func (server *Server) findingReviews(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.URL.Query().Get("deviceId")
	if !validIdentifier(deviceID) {
		http.Error(writer, "invalid device identity", http.StatusBadRequest)
		return
	}
	reviews, err := server.store.ListFindingReviews(request.Context(), deviceID)
	if err != nil {
		http.Error(writer, "could not list finding reviews", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, reviews)
}

func (server *Server) reviewFinding(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		DeviceID     string     `json:"deviceId"`
		FindingID    string     `json:"findingId"`
		State        string     `json:"state"`
		Note         string     `json:"note"`
		SnoozedUntil *time.Time `json:"snoozedUntil"`
	}
	if !decodeControlJSON(writer, request, &body, 4096) {
		return
	}
	body.Note = strings.TrimSpace(body.Note)
	if !validIdentifier(body.DeviceID) || !validIdentifier(body.FindingID) || len(body.Note) > 500 {
		http.Error(writer, "invalid finding review", http.StatusBadRequest)
		return
	}
	allowed := body.State == "new" || body.State == "acknowledged" || body.State == "snoozed" || body.State == "accepted-risk"
	if !allowed {
		http.Error(writer, "invalid review state", http.StatusBadRequest)
		return
	}
	if body.State == "snoozed" && (body.SnoozedUntil == nil || body.SnoozedUntil.Before(time.Now()) || body.SnoozedUntil.After(time.Now().AddDate(1, 0, 0))) {
		http.Error(writer, "snooze must end within one year", http.StatusBadRequest)
		return
	}
	if body.State == "accepted-risk" && body.Note == "" {
		http.Error(writer, "accepted risk requires a note", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	review := storage.FindingReview{DeviceID: body.DeviceID, FindingID: body.FindingID, State: body.State, Note: body.Note, SnoozedUntil: body.SnoozedUntil, ReviewedAt: now}
	if err := server.store.UpsertFindingReview(request.Context(), review); err != nil {
		http.Error(writer, "could not save finding review", http.StatusInternalServerError)
		return
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "finding.review", Target: body.DeviceID + "/" + body.FindingID, Outcome: "succeeded", Detail: "Review state changed to " + body.State + ". Note content is intentionally omitted from audit history.", OccurredAt: now})
	server.writeJSON(writer, http.StatusOK, review)
}

func (server *Server) expectedServices(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.URL.Query().Get("deviceId")
	if !validIdentifier(deviceID) {
		http.Error(writer, "invalid device identity", http.StatusBadRequest)
		return
	}
	services, err := server.store.ListExpectedServices(request.Context(), deviceID)
	if err != nil {
		http.Error(writer, "could not list expected services", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, services)
}

type expectedServiceRequest struct {
	DeviceID      string     `json:"deviceId"`
	Label         string     `json:"label"`
	Protocol      string     `json:"protocol"`
	Port          int        `json:"port"`
	PortEnd       int        `json:"portEnd"`
	BindScope     string     `json:"bindScope"`
	ProcessNames  []string   `json:"processNames"`
	WorkloadNames []string   `json:"workloadNames"`
	SystemdUnits  []string   `json:"systemdUnits"`
	ExpiresAt     *time.Time `json:"expiresAt"`
}

func expectedServiceFromRequest(body expectedServiceRequest, deviceID string, now time.Time) (storage.ExpectedService, bool) {
	if deviceID == "" {
		deviceID = body.DeviceID
	}
	body.Label = strings.TrimSpace(body.Label)
	body.Protocol = strings.ToUpper(strings.TrimSpace(body.Protocol))
	body.BindScope = strings.ToLower(strings.TrimSpace(body.BindScope))
	if body.PortEnd == 0 {
		body.PortEnd = body.Port
	}
	allowedScope := body.BindScope == storage.BindScopeAny || body.BindScope == storage.BindScopeLocal || body.BindScope == storage.BindScopePrivate || body.BindScope == storage.BindScopeWildcard || body.BindScope == storage.BindScopeSpecific
	validOwners := func(values []string) bool {
		if len(values) > 16 {
			return false
		}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 80 || strings.ContainsAny(value, "\r\n\t") {
				return false
			}
		}
		return true
	}
	validExpiration := body.ExpiresAt == nil || body.ExpiresAt.After(now) && !body.ExpiresAt.After(now.Add(storage.MaximumExpectedServiceLifetime))
	valid := validIdentifier(deviceID) && body.Label != "" && len(body.Label) <= 80 && !strings.ContainsAny(body.Label, "\r\n\t") && (body.Protocol == "TCP" || body.Protocol == "UDP") && body.Port >= 1 && body.Port <= 65535 && body.PortEnd >= body.Port && body.PortEnd <= 65535 && allowedScope && validOwners(body.ProcessNames) && validOwners(body.WorkloadNames) && validOwners(body.SystemdUnits) && validExpiration
	return storage.ExpectedService{DeviceID: deviceID, Label: body.Label, Protocol: body.Protocol, Port: body.Port, PortEnd: body.PortEnd, BindScope: body.BindScope, ProcessNames: body.ProcessNames, WorkloadNames: body.WorkloadNames, SystemdUnits: body.SystemdUnits, ExpiresAt: body.ExpiresAt, UpdatedAt: now}, valid
}

func (server *Server) saveExpectedService(writer http.ResponseWriter, request *http.Request) {
	var body expectedServiceRequest
	if !decodeControlJSON(writer, request, &body, 4096) {
		return
	}
	now := time.Now().UTC()
	serviceRequest, valid := expectedServiceFromRequest(body, "", now)
	if !valid {
		http.Error(writer, "invalid expected service", http.StatusBadRequest)
		return
	}
	service, err := server.store.UpsertExpectedService(request.Context(), serviceRequest)
	if err != nil {
		http.Error(writer, "could not save expected service", http.StatusInternalServerError)
		return
	}
	detail := "An endpoint was classified as an expected service. The friendly label is intentionally omitted from audit history."
	if serviceRequest.ExpiresAt != nil {
		detail = "A temporary endpoint classification was saved. It expires automatically; the friendly label is intentionally omitted from audit history."
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "service.expectation.save", Target: serviceRequest.DeviceID + "/" + serviceRequest.Protocol + "/" + fmt.Sprint(serviceRequest.Port), Outcome: "succeeded", Detail: detail, OccurredAt: now})
	server.writeJSON(writer, http.StatusOK, service)
}

func (server *Server) saveExpectedServices(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		DeviceID string                   `json:"deviceId"`
		Services []expectedServiceRequest `json:"services"`
	}
	if !decodeControlJSON(writer, request, &body, 64*1024) {
		return
	}
	if !validIdentifier(body.DeviceID) || len(body.Services) == 0 || len(body.Services) > 64 {
		http.Error(writer, "invalid expected service batch", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	services := make([]storage.ExpectedService, 0, len(body.Services))
	for _, item := range body.Services {
		service, valid := expectedServiceFromRequest(item, body.DeviceID, now)
		if !valid {
			http.Error(writer, "invalid expected service batch", http.StatusBadRequest)
			return
		}
		services = append(services, service)
	}
	saved, err := server.store.UpsertExpectedServices(request.Context(), services)
	if err != nil {
		http.Error(writer, "could not save expected service batch", http.StatusInternalServerError)
		return
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "service.expectation.baseline", Target: body.DeviceID, Outcome: "succeeded", Detail: fmt.Sprintf("%d reviewed baseline classification(s) were saved. Friendly labels and owner names are intentionally omitted from audit history.", len(services)), OccurredAt: now})
	server.writeJSON(writer, http.StatusOK, saved)
}

func (server *Server) removeExpectedService(writer http.ResponseWriter, request *http.Request) {
	serviceID := request.PathValue("serviceID")
	var body struct {
		DeviceID string `json:"deviceId"`
	}
	if !decodeControlJSON(writer, request, &body, 2048) {
		return
	}
	if !validIdentifier(serviceID) || !validIdentifier(body.DeviceID) {
		http.Error(writer, "invalid expected service identity", http.StatusBadRequest)
		return
	}
	if err := server.store.RemoveExpectedService(request.Context(), body.DeviceID, serviceID); errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	} else if err != nil {
		http.Error(writer, "could not remove expected service", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "service.expectation.remove", Target: body.DeviceID + "/" + serviceID, Outcome: "succeeded", Detail: "An endpoint classification was removed.", OccurredAt: now})
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) listenerObservations(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.URL.Query().Get("deviceId")
	if !validIdentifier(deviceID) {
		http.Error(writer, "invalid device identity", http.StatusBadRequest)
		return
	}
	listeners, err := server.store.ListObservedListeners(request.Context(), deviceID)
	if err != nil {
		http.Error(writer, "could not list listener observations", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, listeners)
}

func (server *Server) auditEvents(writer http.ResponseWriter, request *http.Request) {
	events, err := server.store.ListAudit(request.Context(), 60)
	if err != nil {
		http.Error(writer, "could not list audit events", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, events)
}

func (server *Server) securityActions(writer http.ResponseWriter, request *http.Request) {
	actions, err := server.store.ListSecurityActions(request.Context(), 25)
	if err != nil {
		http.Error(writer, "could not list security actions", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, actions)
}

func (server *Server) requestSecurityAction(writer http.ResponseWriter, request *http.Request) {
	if server.actions == nil {
		server.writeJSON(writer, http.StatusNotImplemented, map[string]string{"error": "Security actions are not available on this hub."})
		return
	}
	var body struct {
		Kind string `json:"kind"`
	}
	if !decodeControlJSON(writer, request, &body, 1024) {
		return
	}
	if !server.consumeReauthorization(writer, request, "action:"+body.Kind) {
		return
	}
	requested, err := server.actions.Request(request.Context(), body.Kind, time.Now().UTC())
	if errors.Is(err, action.ErrUnsupportedAction) {
		http.Error(writer, "unsupported security action", http.StatusBadRequest)
		return
	}
	if errors.Is(err, action.ErrAlreadyRunning) {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "That Windows Security action is already queued or running."})
		return
	}
	if err != nil {
		http.Error(writer, "could not queue security action", http.StatusInternalServerError)
		return
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "security.action.request", Target: body.Kind, Outcome: "queued", Detail: "An allowlisted Windows Security action was requested.", OccurredAt: requested.RequestedAt})
	server.writeJSON(writer, http.StatusAccepted, requested)
}

func (server *Server) revokeDevice(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.PathValue("deviceID")
	if !validIdentifier(deviceID) {
		http.NotFound(writer, request)
		return
	}
	if !server.consumeReauthorization(writer, request, "device:revoke:"+deviceID) {
		return
	}
	now := time.Now().UTC()
	if err := server.store.RevokeDevice(request.Context(), deviceID, now); errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	} else if err != nil {
		http.Error(writer, "could not revoke device", http.StatusInternalServerError)
		return
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "device.revoke", Target: deviceID, Outcome: "succeeded", Detail: "The enrolled device certificate was revoked.", OccurredAt: now})
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) consumeReauthorization(writer http.ResponseWriter, request *http.Request, scope string) bool {
	if server.demoMode {
		return true
	}
	if server.auth == nil {
		server.writeJSON(writer, http.StatusNotImplemented, map[string]string{"error": "Passkey confirmation is unavailable."})
		return false
	}
	sessionCookie, err := request.Cookie(authn.SessionCookie)
	if err != nil {
		server.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "Passkey sign-in is required."})
		return false
	}
	if err := server.auth.ConsumeReauthorization(sessionCookie.Value, request.Header.Get("X-HAVEN-Reauthorization"), scope, time.Now().UTC()); err != nil {
		server.writeJSON(writer, http.StatusForbidden, map[string]string{"error": "Confirm this sensitive operation with a passkey first."})
		return false
	}
	return true
}

func validReauthorizationScope(scope string) bool {
	if scope == "passkey:add" {
		return true
	}
	if strings.HasPrefix(scope, "action:") {
		return action.IsAllowed(strings.TrimPrefix(scope, "action:"))
	}
	if strings.HasPrefix(scope, "device:revoke:") {
		return validIdentifier(strings.TrimPrefix(scope, "device:revoke:"))
	}
	if strings.HasPrefix(scope, "passkey:remove:") {
		value := strings.TrimPrefix(scope, "passkey:remove:")
		return value != "" && len(value) <= 1024
	}
	return false
}

func validIdentifier(value string) bool {
	return value != "" && len(value) <= 120 && !strings.ContainsAny(value, "/?#\\")
}

func decodeControlJSON(writer http.ResponseWriter, request *http.Request, destination any, limit int64) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		http.Error(writer, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	return true
}
