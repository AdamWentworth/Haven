package hub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/collector"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/posture"
	"github.com/AdamWentworth/haven/internal/storage"
)

type Server struct {
	collector  collector.Collector
	store      *storage.Store
	logger     *slog.Logger
	fileSystem fs.FS
	fileServer http.Handler
	demoMode   bool
}

type ServerOption func(*Server)

func WithDemoMode() ServerOption {
	return func(server *Server) { server.demoMode = true }
}

func NewServer(
	securityCollector collector.Collector,
	store *storage.Store,
	logger *slog.Logger,
	webFiles fs.FS,
	options ...ServerOption,
) *Server {
	server := &Server{
		collector:  securityCollector,
		store:      store,
		logger:     logger,
		fileSystem: webFiles,
		fileServer: http.FileServerFS(webFiles),
	}
	for _, option := range options {
		option(server)
	}
	return server
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", server.health)
	mux.HandleFunc("GET /api/security/snapshot", server.securitySnapshot)
	mux.HandleFunc("GET /api/devices", server.devices)
	mux.HandleFunc("GET /api/devices/{deviceID}", server.deviceDetail)
	mux.HandleFunc("/", server.webApplication)
	return server.securityHeaders(mux)
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	server.writeJSON(writer, http.StatusOK, map[string]any{
		"status":         "ready",
		"service":        "HAVEN",
		"agentIngestion": "mutual-tls",
		"demoMode":       server.demoMode,
		"timestamp":      time.Now().UTC(),
	})
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
	snapshot := server.collector.Collect(request.Context())
	snapshot = posture.Evaluate(snapshot, time.Now().UTC())
	if err := server.store.SaveSnapshot(request.Context(), snapshot); err != nil {
		server.logger.Error("could not persist security observation", "error", err)
		snapshot.Notices = append(snapshot.Notices, model.CollectorNotice{
			Source:   "HAVEN storage",
			Severity: "warning",
			Message:  "The observation is visible but could not be saved to history.",
		})
	}
	server.writeJSON(writer, http.StatusOK, snapshot)
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
