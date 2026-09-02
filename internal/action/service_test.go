package action

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

type fakeExecutor struct{ err error }

func (executor fakeExecutor) Execute(context.Context, string) error { return executor.err }

type blockingExecutor struct{ release <-chan struct{} }

func (executor blockingExecutor) Execute(ctx context.Context, _ string) error {
	select {
	case <-executor.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestRequestRejectsAnythingOutsideTheAllowlist(t *testing.T) {
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := NewWithExecutor(store, slog.New(slog.NewTextHandler(io.Discard, nil)), fakeExecutor{})
	if _, err := service.Request(context.Background(), "powershell-whoami", time.Now()); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("expected unsupported action, got %v", err)
	}
}

func TestRequestRejectsDuplicateActiveAction(t *testing.T) {
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	service := NewWithExecutor(store, slog.New(slog.NewTextHandler(io.Discard, nil)), blockingExecutor{release: release})
	if _, err := service.Request(context.Background(), DefenderQuickScan, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Request(context.Background(), DefenderQuickScan, time.Now()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected duplicate action rejection, got %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		active, err := store.SecurityActionActive(context.Background(), DefenderQuickScan)
		if err != nil {
			t.Fatal(err)
		}
		if !active {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if active, err := store.SecurityActionActive(context.Background(), DefenderQuickScan); err != nil || active {
		t.Fatalf("action did not complete: active=%v err=%v", active, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
