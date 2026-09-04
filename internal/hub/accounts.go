package hub

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/AdamWentworth/haven/internal/account"
	"github.com/AdamWentworth/haven/internal/storage"
)

func (server *Server) accountProfiles(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	if server.demoMode {
		server.writeJSON(writer, http.StatusOK, account.DemoProfiles(now))
		return
	}
	if server.accounts == nil {
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "The encrypted account notebook is unavailable."})
		return
	}
	profiles, err := server.accounts.List(request.Context(), now)
	if err != nil {
		server.logger.Error("could not open encrypted account profiles", "error", err)
		server.writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "The encrypted account notebook could not be opened."})
		return
	}
	server.writeJSON(writer, http.StatusOK, profiles)
}

func (server *Server) saveAccountProfile(writer http.ResponseWriter, request *http.Request) {
	if server.demoMode {
		server.writeJSON(writer, http.StatusNotImplemented, map[string]string{"error": "Synthetic account profiles cannot be changed."})
		return
	}
	if server.accounts == nil {
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "The encrypted account notebook is unavailable."})
		return
	}
	var input account.ProfileInput
	if !decodeControlJSON(writer, request, &input, 12*1024) {
		return
	}
	now := time.Now().UTC()
	profile, err := server.accounts.Save(request.Context(), input, now)
	if errors.Is(err, account.ErrInvalidProfile) {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "The account profile is invalid. Do not enter passwords, cookies, authenticator setup links, private keys, or recovery-code contents."})
		return
	}
	if errors.Is(err, account.ErrProfileLimit) {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "HAVEN already contains the maximum number of account profiles."})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.logger.Error("could not save encrypted account profile", "error", err)
		server.writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "The encrypted account profile could not be saved."})
		return
	}
	action := "account.profile.create"
	detail := "An owner-reported account security checklist was created. Provider, profile, identifier, and note content are omitted from audit history."
	if input.ID != "" {
		action = "account.profile.update"
		detail = "An owner-reported account security checklist was updated. Provider, profile, identifier, and note content are omitted from audit history."
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: action, Target: profile.ID, Outcome: "succeeded", Detail: detail, OccurredAt: now})
	server.writeJSON(writer, http.StatusOK, profile)
}

func (server *Server) removeAccountProfile(writer http.ResponseWriter, request *http.Request) {
	if server.demoMode {
		server.writeJSON(writer, http.StatusNotImplemented, map[string]string{"error": "Synthetic account profiles cannot be changed."})
		return
	}
	if server.accounts == nil {
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "The encrypted account notebook is unavailable."})
		return
	}
	profileID := request.PathValue("profileID")
	if err := server.accounts.Delete(request.Context(), profileID); errors.Is(err, account.ErrInvalidProfile) {
		http.Error(writer, "invalid account profile identity", http.StatusBadRequest)
		return
	} else if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	} else if err != nil {
		server.writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "The encrypted account profile could not be removed."})
		return
	}
	now := time.Now().UTC()
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "account.profile.remove", Target: profileID, Outcome: "succeeded", Detail: "An owner-reported account security checklist was removed. Its private content was never copied into audit history.", OccurredAt: now})
	writer.WriteHeader(http.StatusNoContent)
}
