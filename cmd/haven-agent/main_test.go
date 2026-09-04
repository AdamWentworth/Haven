package main

import (
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
