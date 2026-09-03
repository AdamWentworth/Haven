package hub

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/notification"
	"github.com/AdamWentworth/haven/internal/storage"
)

const NotificationEvaluationPeriod = time.Minute

func (server *Server) currentAlerts(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	alerts, err := server.projectCurrentAlerts(request.Context())
	if err != nil {
		server.logger.Error("could not derive current alerts", "error", err)
		http.Error(writer, "could not derive current alerts", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, alerts)
}

func (server *Server) projectCurrentAlerts(ctx context.Context) ([]model.Alert, error) {
	if server.alertProjector == nil {
		return []model.Alert{}, nil
	}
	return server.alertProjector.Current(ctx, server.demoMode)
}

func (server *Server) notificationStatus(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.notifications == nil || server.demoMode {
		server.writeJSON(writer, http.StatusOK, map[string]any{
			"available":               false,
			"vapidPublicKey":          "",
			"destinations":            []any{},
			"pendingCount":            0,
			"failedCount":             0,
			"lastSuccessAt":           nil,
			"lastFailureAt":           nil,
			"evaluationPeriodSeconds": int64(NotificationEvaluationPeriod / time.Second),
		})
		return
	}
	status, err := server.notifications.Status(request.Context(), NotificationEvaluationPeriod)
	if err != nil {
		server.logger.Error("could not read notification status", "error", err)
		http.Error(writer, "could not read notification status", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, status)
}

func (server *Server) subscribeNotifications(writer http.ResponseWriter, request *http.Request) {
	if server.notifications == nil || server.demoMode {
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "Background notifications are unavailable on this hub."})
		return
	}
	var body struct {
		Subscription notification.Subscription `json:"subscription"`
		Label        string                    `json:"label"`
	}
	if !decodeControlJSON(writer, request, &body, 8192) {
		return
	}
	now := time.Now().UTC()
	alerts, err := server.projectCurrentAlerts(request.Context())
	if err != nil {
		server.logger.Error("could not baseline notification destination", "error", err)
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "HAVEN could not establish the current alert baseline."})
		return
	}
	record, created, err := server.notifications.Subscribe(request.Context(), body.Subscription, body.Label, alerts, now)
	if errors.Is(err, storage.ErrPushSubscriptionLimit) {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "HAVEN already has the maximum number of background notification destinations."})
		return
	}
	if err != nil {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if created {
		_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "notification.destination.register", Target: "owner", Outcome: "succeeded", Detail: "A browser was enabled for encrypted background alerts; alerts already active were baselined without notification.", OccurredAt: now})
	}
	server.writeJSON(writer, http.StatusOK, record)
}

func (server *Server) unsubscribeNotifications(writer http.ResponseWriter, request *http.Request) {
	if server.notifications == nil || server.demoMode {
		server.writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "Background notifications are unavailable on this hub."})
		return
	}
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	if !decodeControlJSON(writer, request, &body, 4096) {
		return
	}
	removed, err := server.notifications.Unsubscribe(request.Context(), body.Endpoint)
	if err != nil {
		server.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if removed {
		_ = server.store.AppendAudit(request.Context(), storage.AuditEvent{Actor: "owner", Action: "notification.destination.remove", Target: "owner", Outcome: "succeeded", Detail: "A browser background-alert destination was removed.", OccurredAt: time.Now().UTC()})
	}
	writer.WriteHeader(http.StatusNoContent)
}

// RunNotificationMonitor evaluates server-owned alert facts independently of
// dashboard activity and dispatches only newly created medium/high instances.
func (server *Server) RunNotificationMonitor(ctx context.Context, interval time.Duration) {
	if server.notifications == nil || server.demoMode || interval <= 0 {
		return
	}
	server.runNotificationEvaluation(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.runNotificationEvaluation(ctx)
		}
	}
}

func (server *Server) runNotificationEvaluation(ctx context.Context) {
	alerts, err := server.projectCurrentAlerts(ctx)
	if err != nil {
		server.logger.Error("background alerts could not be evaluated", "error", err)
		return
	}
	if err := server.notifications.Reconcile(ctx, alerts, time.Now().UTC()); err != nil {
		server.logger.Error("background alerts could not be reconciled", "error", err)
	}
}
