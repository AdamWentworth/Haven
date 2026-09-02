package action

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

const (
	DefenderQuickScan       = "defender-quick-scan"
	DefenderSignatureUpdate = "defender-signature-update"
)

var (
	ErrUnsupportedAction = errors.New("security action is not supported")
	ErrAlreadyRunning    = errors.New("security action is already queued or running")
)

type Executor interface {
	Execute(context.Context, string) error
}

type Service struct {
	store    *storage.Store
	executor Executor
	logger   *slog.Logger
}

func New(store *storage.Store, logger *slog.Logger) *Service {
	return &Service{store: store, executor: NativeExecutor{}, logger: logger}
}

func NewWithExecutor(store *storage.Store, logger *slog.Logger, executor Executor) *Service {
	return &Service{store: store, executor: executor, logger: logger}
}

func IsAllowed(kind string) bool {
	return kind == DefenderQuickScan || kind == DefenderSignatureUpdate
}

func (service *Service) Request(ctx context.Context, kind string, now time.Time) (storage.SecurityAction, error) {
	if !IsAllowed(kind) {
		return storage.SecurityAction{}, ErrUnsupportedAction
	}
	active, err := service.store.SecurityActionActive(ctx, kind)
	if err != nil {
		return storage.SecurityAction{}, err
	}
	if active {
		return storage.SecurityAction{}, ErrAlreadyRunning
	}
	id, err := actionID()
	if err != nil {
		return storage.SecurityAction{}, err
	}
	action := storage.SecurityAction{ID: id, Kind: kind, Status: "queued", RequestedAt: now, Message: "Waiting to run."}
	if err := service.store.CreateSecurityAction(ctx, action); err != nil {
		return storage.SecurityAction{}, err
	}
	go service.run(id, kind)
	return action, nil
}

func (service *Service) run(id, kind string) {
	started := time.Now().UTC()
	if err := service.store.UpdateSecurityAction(context.Background(), id, "running", "Running the allowlisted Windows Security action.", started); err != nil {
		service.logger.Error("could not mark security action as running", "action", id, "error", err)
		return
	}
	timeout := 15 * time.Minute
	if kind == DefenderQuickScan {
		timeout = 2 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := service.executor.Execute(ctx, kind)
	completed := time.Now().UTC()
	status := "succeeded"
	message := "The requested Windows Security action completed successfully."
	if err != nil {
		status = "failed"
		message = "Windows Security could not complete the requested action. Check Windows Security for details."
		service.logger.Warn("security action failed", "action", id, "kind", kind, "error", err)
	}
	if updateErr := service.store.UpdateSecurityAction(context.Background(), id, status, message, completed); updateErr != nil {
		service.logger.Error("could not finish security action", "action", id, "error", updateErr)
	}
	_ = service.store.AppendAudit(context.Background(), storage.AuditEvent{Actor: "owner", Action: "security.action.complete", Target: kind, Outcome: status, Detail: message, OccurredAt: completed})
}

type NativeExecutor struct{}

func (NativeExecutor) Execute(ctx context.Context, kind string) error {
	if runtime.GOOS != "windows" {
		return errors.New("Windows Security actions are available only on Windows")
	}
	var command string
	switch kind {
	case DefenderQuickScan:
		command = "Start-MpScan -ScanType QuickScan"
	case DefenderSignatureUpdate:
		command = "Update-MpSignature"
	default:
		return ErrUnsupportedAction
	}
	// The command is selected exclusively from the fixed allowlist above. No
	// browser-supplied text is ever interpolated into PowerShell.
	process := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
	if output, err := process.CombinedOutput(); err != nil {
		return fmt.Errorf("execute fixed Defender action: %w (%d output bytes)", err, len(output))
	}
	return nil
}

func actionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "act_" + hex.EncodeToString(value), nil
}
