package hub

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/AdamWentworth/haven/internal/fleet"
	"github.com/AdamWentworth/haven/internal/storage"
)

func (server *Server) saveReportingExpectation(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.demoMode {
		server.writeJSON(writer, http.StatusForbidden, map[string]string{"error": "Synthetic devices have no reporting expectation to change."})
		return
	}
	var body struct {
		ReportingExpectation string `json:"reportingExpectation"`
	}
	if !decodeControlJSON(writer, request, &body, 1024) {
		return
	}
	now := time.Now().UTC()
	deviceID := request.PathValue("deviceID")
	err := server.store.SaveReportingExpectation(request.Context(), deviceID, body.ReportingExpectation, now)
	if errors.Is(err, storage.ErrInvalidReportingExpectation) {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.logger.Error("could not save reporting expectation", "error", err)
		http.Error(writer, "could not save reporting expectation", http.StatusInternalServerError)
		return
	}
	detail, err := server.store.DeviceDetail(request.Context(), deviceID, now)
	if err != nil {
		http.Error(writer, "could not reload device", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, fleet.Present(detail.Device))
}
