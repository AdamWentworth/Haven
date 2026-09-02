package hub

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdamWentworth/haven/internal/action"
	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/collector"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/posture"
	"github.com/AdamWentworth/haven/internal/storage"
)

type Server struct {
	collector       collector.Collector
	store           *storage.Store
	logger          *slog.Logger
	fileSystem      fs.FS
	fileServer      http.Handler
	demoMode        bool
	localCollection bool
	auth            *authn.Service
	actions         *action.Service

	collectionMutex sync.Mutex
	latestMutex     sync.RWMutex
	latestSnapshot  *model.SecuritySnapshot
	monitorMutex    sync.RWMutex
	monitor         model.MonitorStatus
}

type ServerOption func(*Server)

func WithDemoMode() ServerOption {
	return func(server *Server) { server.demoMode = true }
}

func WithLocalCollection(enabled bool) ServerOption {
	return func(server *Server) { server.localCollection = enabled }
}

func WithAuthentication(service *authn.Service) ServerOption {
	return func(server *Server) { server.auth = service }
}

func WithActions(service *action.Service) ServerOption {
	return func(server *Server) { server.actions = service }
}

func NewServer(
	securityCollector collector.Collector,
	store *storage.Store,
	logger *slog.Logger,
	webFiles fs.FS,
	options ...ServerOption,
) *Server {
	server := &Server{
		collector:       securityCollector,
		store:           store,
		logger:          logger,
		fileSystem:      webFiles,
		fileServer:      http.FileServerFS(webFiles),
		localCollection: true,
	}
	for _, option := range options {
		option(server)
	}
	return server
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", server.health)
	server.registerAuthenticationRoutes(mux)
	mux.Handle("GET /api/runtime", server.protected(http.HandlerFunc(server.runtimeStatus)))
	mux.Handle("POST /api/security/snapshot", server.mutating(http.HandlerFunc(server.securitySnapshot)))
	mux.Handle("GET /api/security/latest", server.protected(http.HandlerFunc(server.latestSecuritySnapshot)))
	mux.Handle("GET /api/devices", server.protected(http.HandlerFunc(server.devices)))
	mux.Handle("GET /api/devices/{deviceID}", server.protected(http.HandlerFunc(server.deviceDetail)))
	mux.Handle("POST /api/devices/{deviceID}/revoke", server.mutating(http.HandlerFunc(server.revokeDevice)))
	mux.Handle("GET /api/events", server.protected(http.HandlerFunc(server.securityEvents)))
	mux.Handle("GET /api/finding-reviews", server.protected(http.HandlerFunc(server.findingReviews)))
	mux.Handle("POST /api/finding-reviews", server.mutating(http.HandlerFunc(server.reviewFinding)))
	mux.Handle("GET /api/audit", server.protected(http.HandlerFunc(server.auditEvents)))
	mux.Handle("GET /api/actions", server.protected(http.HandlerFunc(server.securityActions)))
	mux.Handle("POST /api/actions", server.mutating(http.HandlerFunc(server.requestSecurityAction)))
	mux.HandleFunc("/", server.webApplication)
	return server.securityHeaders(mux)
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	server.writeJSON(writer, http.StatusOK, map[string]any{
		"status":         "ready",
		"service":        "HAVEN",
		"agentIngestion": "mutual-tls",
		"timestamp":      time.Now().UTC(),
	})
}

func (server *Server) runtimeStatus(writer http.ResponseWriter, _ *http.Request) {
	capabilities := []action.Capability{}
	if server.actions != nil {
		capabilities = server.actions.Capabilities()
	}
	server.writeJSON(writer, http.StatusOK, map[string]any{
		"status":             "ready",
		"service":            "HAVEN",
		"agentIngestion":     "mutual-tls",
		"demoMode":           server.demoMode,
		"localCollection":    server.localCollection,
		"authentication":     server.auth != nil,
		"actionCapabilities": capabilities,
		"monitor":            server.monitorStatus(),
		"timestamp":          time.Now().UTC(),
	})
}

func (server *Server) securityEvents(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	deviceID := request.URL.Query().Get("deviceId")
	if len(deviceID) > 80 || strings.ContainsAny(deviceID, "/?#") {
		http.Error(writer, "invalid device identity", http.StatusBadRequest)
		return
	}
	limit := 40
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			http.Error(writer, "limit must be from 1 through 100", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	events, err := server.store.ListSecurityEvents(request.Context(), deviceID, limit, server.demoMode)
	if err != nil {
		server.logger.Error("could not list security events", "error", err)
		http.Error(writer, "could not list security events", http.StatusInternalServerError)
		return
	}
	server.writeJSON(writer, http.StatusOK, events)
}

func (server *Server) devices(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	devices, err := server.store.ListDevices(request.Context(), time.Now().UTC())
	if err != nil {
		server.logger.Error("could not list devices", "error", err)
		http.Error(writer, "could not list devices", http.StatusInternalServerError)
		return
	}
	devices = visibleDevices(devices, server.demoMode)
	server.writeJSON(writer, http.StatusOK, devices)
}

func (server *Server) deviceDetail(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	deviceID := request.PathValue("deviceID")
	if deviceID == "" || len(deviceID) > 80 || strings.ContainsAny(deviceID, "/?#") {
		http.NotFound(writer, request)
		return
	}
	detail, err := server.store.DeviceDetail(request.Context(), deviceID, time.Now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		server.logger.Error("could not load device", "error", err)
		http.Error(writer, "could not load device", http.StatusInternalServerError)
		return
	}
	if (detail.Device.TrustState == "synthetic") != server.demoMode {
		http.NotFound(writer, request)
		return
	}
	if detail.Snapshot != nil {
		evaluated := posture.Evaluate(*detail.Snapshot, time.Now().UTC())
		detail.Snapshot = &evaluated
	}
	server.writeJSON(writer, http.StatusOK, detail)
}

func (server *Server) securitySnapshot(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.demoMode {
		devices, err := server.store.ListDevices(request.Context(), time.Now().UTC())
		if err != nil {
			server.logger.Error("could not list demo devices", "error", err)
			http.Error(writer, "could not load demo data", http.StatusInternalServerError)
			return
		}
		devices = visibleDevices(devices, true)
		if len(devices) == 0 {
			http.Error(writer, "demo mode has no synthetic devices; run haven-hub demo seed", http.StatusServiceUnavailable)
			return
		}
		detail, err := server.store.DeviceDetail(request.Context(), devices[0].ID, time.Now().UTC())
		if err != nil || detail.Snapshot == nil {
			server.logger.Error("could not load demo observation", "error", err)
			http.Error(writer, "could not load demo observation", http.StatusInternalServerError)
			return
		}
		evaluated := posture.Evaluate(*detail.Snapshot, time.Now().UTC())
		server.writeJSON(writer, http.StatusOK, evaluated)
		return
	}
	if !server.localCollection {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "Local collection is disabled on this hub; observations come from enrolled native agents."})
		return
	}
	snapshot, _ := server.collectSnapshot(request.Context())
	server.writeJSON(writer, http.StatusOK, snapshot)
}

func (server *Server) latestSecuritySnapshot(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if server.demoMode {
		server.securitySnapshot(writer, request)
		return
	}
	if !server.localCollection {
		server.writeJSON(writer, http.StatusConflict, map[string]string{"error": "Local collection is disabled on this hub; select an enrolled device observation."})
		return
	}
	server.latestMutex.RLock()
	defer server.latestMutex.RUnlock()
	if server.latestSnapshot == nil {
		http.Error(writer, "the first automatic observation is still running", http.StatusServiceUnavailable)
		return
	}
	server.writeJSON(writer, http.StatusOK, *server.latestSnapshot)
}

func (server *Server) collectSnapshot(ctx context.Context) (model.SecuritySnapshot, error) {
	server.collectionMutex.Lock()
	defer server.collectionMutex.Unlock()
	snapshot := server.collector.Collect(ctx)
	snapshot = posture.Evaluate(snapshot, time.Now().UTC())
	if err := server.store.SaveSnapshot(ctx, snapshot); err != nil {
		server.logger.Error("could not persist security observation", "error", err)
		snapshot.Notices = append(snapshot.Notices, model.CollectorNotice{
			Source:   "HAVEN storage",
			Severity: "warning",
			Message:  "The observation is visible but could not be saved to history.",
		})
		return snapshot, err
	}
	server.latestMutex.Lock()
	server.latestSnapshot = &snapshot
	server.latestMutex.Unlock()
	return snapshot, nil
}

// RunMonitor performs an immediate collection and then continues on the
// configured interval until the context is cancelled. Collections share the
// same lock as manual refreshes so an expensive native collector never runs
// twice at once.
func (server *Server) RunMonitor(ctx context.Context, interval time.Duration) {
	if server.demoMode || !server.localCollection || interval <= 0 {
		return
	}
	server.monitorMutex.Lock()
	server.monitor.Enabled = true
	server.monitor.IntervalSeconds = int64(interval / time.Second)
	server.monitorMutex.Unlock()

	server.runScheduledCollection(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.runScheduledCollection(ctx)
		}
	}
}

func (server *Server) runScheduledCollection(ctx context.Context) {
	attemptedAt := time.Now().UTC()
	_, err := server.collectSnapshot(ctx)
	server.monitorMutex.Lock()
	defer server.monitorMutex.Unlock()
	server.monitor.LastAttemptAt = &attemptedAt
	if err != nil {
		server.monitor.LastCollectionError = "The latest automatic observation could not be stored."
		return
	}
	server.monitor.LastSuccessfulAt = &attemptedAt
	server.monitor.LastCollectionError = ""
}

func (server *Server) monitorStatus() model.MonitorStatus {
	server.monitorMutex.RLock()
	defer server.monitorMutex.RUnlock()
	return server.monitor
}

func visibleDevices(devices []model.DeviceRecord, demoMode bool) []model.DeviceRecord {
	filtered := make([]model.DeviceRecord, 0, len(devices))
	for _, device := range devices {
		if (device.TrustState == "synthetic") == demoMode {
			filtered = append(filtered, device)
		}
	}
	return filtered
}

func (server *Server) webApplication(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") {
		http.NotFound(writer, request)
		return
	}

	requestedPath := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
	if requestedPath == "." || requestedPath == "" {
		requestedPath = "index.html"
	}
	if _, err := fs.Stat(server.fileSystem, requestedPath); err != nil {
		requestedPath = "index.html"
	}
	if requestedPath == "index.html" {
		writer.Header().Set("Cache-Control", "no-store")
	}

	clone := request.Clone(request.Context())
	if requestedPath == "index.html" {
		clone.URL.Path = "/"
	} else {
		clone.URL.Path = "/" + requestedPath
	}
	server.fileServer.ServeHTTP(writer, clone)
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		)
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		server.logger.Error("could not encode HTTP response", "error", err)
	}
}
