package main

import "testing"

func TestDefaultInstallationRecognizesSystemdInvocation(t *testing.T) {
	t.Setenv("INVOCATION_ID", "test-invocation")
	if got := defaultInstallation(); got != "systemd-user" {
		t.Fatalf("expected systemd installation, got %q", got)
	}
	t.Setenv("INVOCATION_ID", "")
	if got := defaultInstallation(); got != "interactive" {
		t.Fatalf("expected interactive installation, got %q", got)
	}
}
