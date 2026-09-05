package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdamWentworth/haven/internal/buildinfo"
)

func TestDefaultInstallationRecognizesSystemdInvocation(t *testing.T) {
	t.Setenv("INVOCATION_ID", "test-invocation")
	if got := defaultInstallation(); got != "systemd-user" {
		t.Fatalf("expected systemd installation, got %q", got)
	}
	t.Setenv("INVOCATION_ID", "")
	previous := buildinfo.AgentInstallation
	buildinfo.AgentInstallation = "windows-task"
	t.Cleanup(func() { buildinfo.AgentInstallation = previous })
	if got := defaultInstallation(); got != "windows-task" {
		t.Fatalf("expected packaged installation identity, got %q", got)
	}
	buildinfo.AgentInstallation = "interactive"
	if got := defaultInstallation(); got != "interactive" {
		t.Fatalf("expected interactive installation, got %q", got)
	}
}

func TestDoctorDoesNotEnrollOrCreateAgentState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent-agent")
	t.Setenv("HAVEN_AGENT_STATE_DIRECTORY", directory)
	if err := run(context.Background(), "doctor", nil); err == nil {
		t.Fatal("an absent identity must make doctor return a failed status")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("doctor must not initialize or enroll an agent, stat error = %v", err)
	}
}
