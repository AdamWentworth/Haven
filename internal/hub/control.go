package hub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/action"
	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/storage"
)

type authStatus struct {
	Configured    bool   `json:"configured"`
	Authenticated bool   `json:"authenticated"`
	Origin        string `json:"origin"`
	UseLocalhost  bool   `json:"useLocalhost"`
}

func (server *Server) registerAuthenticationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/status", server.authenticationStatus)
	mux.HandleFunc("POST /api/auth/register/begin", server.beginRegistration)
	mux.HandleFunc("POST /api/auth/register/finish", server.finishRegistration)
	mux.HandleFunc("POST /api/auth/login/begin", server.beginLogin)
	mux.HandleFunc("POST /api/auth/login/finish", server.finishLogin)
	mux.Handle("POST /api/auth/logout", server.mutating(http.HandlerFunc(server.logout)))
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
	host, _, splitErr := net.SplitHostPort(request.Host)
	if splitErr != nil {
		host = request.Host
	}
	server.writeJSON(writer, http.StatusOK, authStatus{Configured: configured, Authenticated: authenticated, Origin: server.auth.Origin(), UseLocalhost: !strings.EqualFold(host, "localhost")})
}

func (server *Server) beginRegistration(writer http.ResponseWriter, request *http.Request) {
	if !server.allowAuthAttempt(request) {
		server.writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "Too many authentication attempts. Wait a minute and try again."})
		return
	}
	var body struct {
		BootstrapCode string `json:"bootstrapCode"`
	}
	if !decodeControlJSON(writer, request, &body, 4096) {
		return
	}
	response, err := server.auth.BeginRegistration(request.Context(), body.BootstrapCode, time.Now().UTC())
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
	if errors.Is(err, authn.ErrAlreadyConfigured) {
		status = http.StatusConflict
		message = "HAVEN already has a passkey."
	}
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
