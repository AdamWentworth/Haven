package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineHubDiagnosticsDoNotInitializeOrRepairState(t *testing.T) {
	parent := t.TempDir()
	stateDirectory := filepath.Join(parent, "absent-state")
	t.Setenv("HAVEN_STATE_DIRECTORY", stateDirectory)
	t.Setenv("HAVEN_DATA_PATH", filepath.Join(stateDirectory, "haven.db"))
	t.Setenv("HAVEN_PUBLIC_ORIGIN", "https://private-hub.example:8443")
	t.Setenv("HAVEN_MANAGED_APPLIANCES_FILE", "")
	report, err := offlineHubDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "not-ready" {
		t.Fatalf("missing state must fail closed, got %q", report.Status)
	}
	if _, err := os.Stat(stateDirectory); !os.IsNotExist(err) {
		t.Fatalf("doctor must not initialize state, stat error = %v", err)
	}
}

func TestOfflineHubDiagnosticsRedactInvalidPrivateApplianceConfiguration(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private-appliances.json")
	if err := os.WriteFile(privatePath, []byte(`{"appliances":[{"id":"private-device","address":"private-address"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HAVEN_STATE_DIRECTORY", filepath.Join(directory, "state"))
	t.Setenv("HAVEN_DATA_PATH", filepath.Join(directory, "state", "haven.db"))
	t.Setenv("HAVEN_PUBLIC_ORIGIN", "https://private-hub.example:8443")
	t.Setenv("HAVEN_MANAGED_APPLIANCES_FILE", privatePath)
	report, err := offlineHubDiagnostics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{privatePath, "private-device", "private-address"} {
		if strings.Contains(string(contents), privateValue) {
			t.Fatalf("diagnostics leaked %q", privateValue)
		}
	}
}
