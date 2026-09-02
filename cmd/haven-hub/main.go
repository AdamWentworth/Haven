package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AdamWentworth/haven/internal/action"
	"github.com/AdamWentworth/haven/internal/authn"
	"github.com/AdamWentworth/haven/internal/collector"
	"github.com/AdamWentworth/haven/internal/hub"
	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/AdamWentworth/haven/internal/trust"
	"github.com/AdamWentworth/haven/internal/webui"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		failIf(runHealthcheck())
		return
	}
	if len(os.Args) > 1 {
		handled, err := runCommand(os.Args[1], os.Args[2:])
		if handled {
			failIf(err)
			return
		}
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("HAVEN hub stopped", "error", err)
		os.Exit(1)
	}
}

func failIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCommand(command string, arguments []string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch command {
	case "auth":
		if len(arguments) == 0 || arguments[0] != "bootstrap" {
			return true, errors.New("usage: haven-hub auth bootstrap [--valid-for 10m]")
		}
		flags := flag.NewFlagSet("auth bootstrap", flag.ContinueOnError)
		validFor := flags.Duration("valid-for", 10*time.Minute, "bootstrap code validity")
		if err := flags.Parse(arguments[1:]); err != nil {
			return true, err
		}
		if *validFor < time.Minute || *validFor > time.Hour {
			return true, errors.New("valid-for must be between 1m and 1h")
		}
		store, err := openStore(ctx)
		if err != nil {
			return true, err
		}
		defer store.Close()
		configured, err := store.AuthConfigured(ctx)
		if err != nil {
			return true, err
		}
		code, err := authn.CreateBootstrap(ctx, store, *validFor, time.Now().UTC())
		if err != nil {
			return true, err
		}
		fmt.Println(code)
		purpose := "first-passkey setup"
		if configured {
			purpose = "local passkey recovery"
		}
		fmt.Fprintf(os.Stderr, "One-time HAVEN %s code expires in %s. Open http://localhost:5080 to use it.\n", purpose, validFor.String())
		return true, nil

	case "enrollment":
		if len(arguments) == 0 || arguments[0] != "create" {
			return true, errors.New("usage: haven-hub enrollment create --name <device name>")
		}
		flags := flag.NewFlagSet("enrollment create", flag.ContinueOnError)
		name := flags.String("name", "", "friendly device name")
		validFor := flags.Duration("valid-for", 15*time.Minute, "token validity")
		if err := flags.Parse(arguments[1:]); err != nil {
			return true, err
		}
		if *name == "" || *validFor < time.Minute || *validFor > time.Hour {
			return true, errors.New("name is required and valid-for must be between 1m and 1h")
		}
		store, err := openStore(ctx)
		if err != nil {
			return true, err
		}
		defer store.Close()
		token, tokenHash, err := trust.NewEnrollmentToken()
		if err != nil {
			return true, err
		}
		now := time.Now().UTC()
		if err := store.CreateEnrollmentToken(ctx, tokenHash, *name, now.Add(*validFor), now); err != nil {
			return true, err
		}
		fmt.Println(token)
		fmt.Fprintf(os.Stderr, "One-time enrollment token for %q expires at %s.\n", *name, now.Add(*validFor).Format(time.RFC3339))
		return true, nil

	case "device":
		if len(arguments) == 0 || arguments[0] != "revoke" {
			return true, errors.New("usage: haven-hub device revoke --id <device id>")
		}
		flags := flag.NewFlagSet("device revoke", flag.ContinueOnError)
		deviceID := flags.String("id", "", "device identity")
		if err := flags.Parse(arguments[1:]); err != nil {
			return true, err
		}
		if *deviceID == "" {
			return true, errors.New("device id is required")
		}
		store, err := openStore(ctx)
		if err != nil {
			return true, err
		}
		defer store.Close()
		if err := store.RevokeDevice(ctx, *deviceID, time.Now().UTC()); err != nil {
			return true, err
		}
		fmt.Printf("Revoked %s.\n", *deviceID)
		return true, nil

	case "demo":
		if len(arguments) == 0 || arguments[0] != "seed" {
			return true, errors.New("usage: haven-hub demo seed [--count 5]")
		}
		flags := flag.NewFlagSet("demo seed", flag.ContinueOnError)
		count := flags.Int("count", 5, "number of synthetic devices")
		if err := flags.Parse(arguments[1:]); err != nil {
			return true, err
		}
		store, err := openStore(ctx)
		if err != nil {
			return true, err
		}
		defer store.Close()
		if err := store.SeedSyntheticDevices(ctx, *count, time.Now().UTC()); err != nil {
			return true, err
		}
		fmt.Printf("Seeded %d synthetic devices.\n", *count)
		return true, nil

	case "backup":
		flags := flag.NewFlagSet("backup", flag.ContinueOnError)
		destination := flags.String("to", "", "new backup database path")
		if err := flags.Parse(arguments); err != nil {
			return true, err
		}
		if *destination == "" {
			return true, errors.New("usage: haven-hub backup --to <new database path>")
		}
		store, err := openStore(ctx)
		if err != nil {
			return true, err
		}
		defer store.Close()
		if err := store.Backup(ctx, *destination); err != nil {
			return true, err
		}
		fmt.Printf("Backup created at %s.\n", *destination)
		return true, nil
	}
	return false, nil
}

func openStore(ctx context.Context) (*storage.Store, error) {
	dataPath, err := storage.DefaultPath()
	if err != nil {
		return nil, err
	}
	return storage.Open(ctx, dataPath)
}

func run(logger *slog.Logger) error {
	startupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := openStore(startupContext)
	if err != nil {
		return err
	}
	defer store.Close()

	retentionDays, err := configuredRetentionDays()
	if err != nil {
		return err
	}
	deleted, err := store.DeleteBefore(startupContext, time.Now().UTC().AddDate(0, 0, -retentionDays))
	if err != nil {
		return err
	}
	if deleted > 0 {
		logger.Info("expired historical observations", "count", deleted)
	}

	stateDirectory, err := storage.DefaultStateDirectory()
	if err != nil {
		return err
	}
	agentServerNames, err := configuredAgentServerNames()
	if err != nil {
		return err
	}
	pki, err := trust.EnsureHubPKIForServerNames(filepath.Join(stateDirectory, "pki"), time.Now().UTC(), agentServerNames)
	if err != nil {
		return err
	}
	webFiles, err := webui.Files()
	if err != nil {
		return fmt.Errorf("open embedded web application: %w", err)
	}
	demoMode, err := configuredBoolean("HAVEN_DEMO_MODE")
	if err != nil {
		return err
	}
	collectionInterval, err := configuredCollectionInterval()
	if err != nil {
		return err
	}

	uiAddress := configuredAddress("HAVEN_LISTEN_ADDRESS", "127.0.0.1:5080")
	agentAddress := configuredAddress("HAVEN_AGENT_LISTEN_ADDRESS", "127.0.0.1:5443")
	serverOptions := []hub.ServerOption{}
	if demoMode {
		serverOptions = append(serverOptions, hub.WithDemoMode())
		logger.Info("synthetic demo mode enabled")
	} else {
		publicOrigin, err := configuredPublicOrigin(uiAddress)
		if err != nil {
			return err
		}
		authentication, err := authn.New(store, filepath.Join(stateDirectory, "auth-credential.key"), publicOrigin)
		if err != nil {
			return err
		}
		serverOptions = append(serverOptions, hub.WithAuthentication(authentication))
		if runtime.GOOS == "windows" {
			serverOptions = append(serverOptions, hub.WithActions(action.New(store, logger)))
		}
		logger.Info("passkey authentication enabled", "origin", publicOrigin)
	}
	dashboard := hub.NewServer(collector.NewForCurrentPlatform(), store, logger, webFiles, serverOptions...)
	uiServer := hardenedServer(uiAddress, dashboard.Handler())
	agentServer := hardenedServer(agentAddress, hub.NewAgentServer(store, pki, logger).Handler())
	agentServer.TLSConfig = trust.ServerTLSConfig(pki)

	uiListener, err := net.Listen("tcp", uiAddress)
	if err != nil {
		return fmt.Errorf("listen for dashboard: %w", err)
	}
	defer uiListener.Close()
	agentListener, err := net.Listen("tcp", agentAddress)
	if err != nil {
		return fmt.Errorf("listen for agents: %w", err)
	}
	defer agentListener.Close()

	runtimeContext, stopRuntime := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRuntime()
	if !demoMode {
		go dashboard.RunMonitor(runtimeContext, collectionInterval)
		logger.Info("continuous local monitoring enabled", "interval", collectionInterval.String())
	}

	serverErrors := make(chan error, 2)
	go serve(logger, "dashboard", uiAddress, uiServer, uiListener, serverErrors)
	go serve(logger, "agent", agentAddress, agentServer, tls.NewListener(agentListener, agentServer.TLSConfig), serverErrors)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-runtimeContext.Done():
	}
	stopRuntime()

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	agentErr := agentServer.Shutdown(shutdownContext)
	uiErr := uiServer.Shutdown(shutdownContext)
	return errors.Join(uiErr, agentErr)
}

func hardenedServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
}

func serve(logger *slog.Logger, service, address string, server *http.Server, listener net.Listener, errorsChannel chan<- error) {
	logger.Info("HAVEN listener ready", "service", service, "address", address)
	errorsChannel <- server.Serve(listener)
}

func configuredAddress(environmentName, fallback string) string {
	if value := os.Getenv(environmentName); value != "" {
		return value
	}
	return fallback
}

func configuredBoolean(environmentName string) (bool, error) {
	value := os.Getenv(environmentName)
	if value == "" || value == "false" || value == "0" {
		return false, nil
	}
	if value == "true" || value == "1" {
		return true, nil
	}
	return false, fmt.Errorf("%s must be true, false, 1, or 0", environmentName)
}

func configuredRetentionDays() (int, error) {
	value := os.Getenv("HAVEN_RETENTION_DAYS")
	if value == "" {
		return 90, nil
	}
	days, err := strconv.Atoi(value)
	if err != nil || days < 1 || days > 3650 {
		return 0, errors.New("HAVEN_RETENTION_DAYS must be a whole number from 1 through 3650")
	}
	return days, nil
}

func configuredCollectionInterval() (time.Duration, error) {
	value := os.Getenv("HAVEN_COLLECTION_INTERVAL")
	if value == "" {
		return 15 * time.Minute, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < time.Minute || interval > 24*time.Hour {
		return 0, errors.New("HAVEN_COLLECTION_INTERVAL must be a duration from 1m through 24h")
	}
	return interval, nil
}

func configuredAgentServerNames() ([]string, error) {
	value := strings.TrimSpace(os.Getenv("HAVEN_AGENT_SERVER_NAMES"))
	if value == "" {
		return nil, nil
	}
	values := strings.Split(value, ",")
	if len(values) > 16 {
		return nil, errors.New("HAVEN_AGENT_SERVER_NAMES accepts at most 16 comma-separated hostnames or addresses")
	}
	return values, nil
}

func configuredPublicOrigin(listenAddress string) (string, error) {
	if value := os.Getenv("HAVEN_PUBLIC_ORIGIN"); value != "" {
		return strings.TrimRight(value, "/"), nil
	}
	_, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return "", fmt.Errorf("derive HAVEN public origin: %w", err)
	}
	return "http://localhost:" + port, nil
}

func runHealthcheck() error {
	url := os.Getenv("HAVEN_HEALTHCHECK_URL")
	if url == "" {
		url = "http://127.0.0.1:8080/api/health"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HAVEN healthcheck failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HAVEN healthcheck returned HTTP %d", response.StatusCode)
	}
	return nil
}
