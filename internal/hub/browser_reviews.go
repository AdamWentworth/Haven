package hub

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/AdamWentworth/haven/internal/browserreview"
	"github.com/AdamWentworth/haven/internal/storage"
)

func (server *Server) browserSiteReviews(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	deviceID := request.URL.Query().Get("deviceId")
	if !validIdentifier(deviceID) {
		http.Error(writer, "invalid device identity", http.StatusBadRequest)
		return
	}
	if server.demoMode {
		server.writeJSON(writer, http.StatusOK, []browserreview.Review{})
		return
	}
	if server.browserReviews == nil {
		http.Error(writer, "browser site reviews are unavailable", http.StatusServiceUnavailable)
		return
	}
	reviews, err := server.browserReviews.List(request.Context(), deviceID)
	if errors.Is(err, browserreview.ErrInvalidReview) {
		http.Error(writer, "invalid browser site review", http.StatusBadRequest)
		return
	}
	if err != nil {
		server.logger.Error("could not list browser site reviews", "error", err)
		http.Error(writer, "could not list browser site reviews", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, reviews)
}

func (server *Server) saveBrowserSiteReview(writer http.ResponseWriter, request *http.Request) {
	if server.demoMode || server.browserReviews == nil {
		http.Error(writer, "browser site reviews are unavailable", http.StatusServiceUnavailable)
		return
	}
	var input browserreview.ReviewInput
	if !decodeControlJSON(writer, request, &input, 4096) {
		return
	}
	input, err := browserreview.NormalizeReviewInput(input)
	if errors.Is(err, browserreview.ErrInvalidReview) {
		http.Error(writer, "invalid browser site review", http.StatusBadRequest)
		return
	}
	detail, err := server.store.DeviceDetail(request.Context(), input.DeviceID, time.Now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.logger.Error("could not verify browser site observation", "error", err)
		http.Error(writer, "could not verify browser site observation", http.StatusInternalServerError)
		return
	}
	observed := false
	if detail.Snapshot != nil && detail.Snapshot.BrowserSecurity != nil {
		for _, browser := range detail.Snapshot.BrowserSecurity.Browsers {
			if browser.ID != input.BrowserID {
				continue
			}
			for _, profile := range browser.Profiles {
				if profile.Fingerprint != input.ProfileFingerprint {
					continue
				}
				for _, site := range profile.Sites {
					if site.Domain == input.Domain {
						observed = true
						break
					}
				}
			}
		}
	}
	if !observed {
		http.Error(writer, "browser site is not present in the current live observation", http.StatusConflict)
		return
	}
	now := time.Now().UTC()
	review, err := server.browserReviews.Save(request.Context(), input, now)
	if errors.Is(err, browserreview.ErrInvalidReview) || errors.Is(err, browserreview.ErrReviewLimit) {
		http.Error(writer, "invalid browser site review", http.StatusBadRequest)
		return
	}
	if err != nil {
		server.logger.Error("could not save browser site review", "error", err)
		http.Error(writer, "could not save browser site review", http.StatusInternalServerError)
		return
	}
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "browser.site.review", Target: review.DeviceID + "/" + review.ProfileFingerprint, Outcome: "succeeded", Detail: "A domain-level browser site classification changed to " + review.State + ". The domain is encrypted at rest and omitted from audit history.", OccurredAt: now})
	server.writeJSON(writer, http.StatusOK, review)
}

func (server *Server) removeBrowserSiteReview(writer http.ResponseWriter, request *http.Request) {
	if server.demoMode || server.browserReviews == nil {
		http.Error(writer, "browser site reviews are unavailable", http.StatusServiceUnavailable)
		return
	}
	var key browserreview.ReviewKey
	if !decodeControlJSON(writer, request, &key, 4096) {
		return
	}
	if err := server.browserReviews.Remove(request.Context(), key); errors.Is(err, browserreview.ErrInvalidReview) {
		http.Error(writer, "invalid browser site review", http.StatusBadRequest)
		return
	} else if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	} else if err != nil {
		server.logger.Error("could not remove browser site review", "error", err)
		http.Error(writer, "could not remove browser site review", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "browser.site.review.remove", Target: key.DeviceID + "/" + key.ProfileFingerprint, Outcome: "succeeded", Detail: "A domain-level browser site classification was reset. The domain is omitted from audit history.", OccurredAt: now})
	writer.WriteHeader(http.StatusNoContent)
}
