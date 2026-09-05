package diagnostic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/agent"
	"github.com/AdamWentworth/haven/internal/trust"
)

func TestHubReportIsRedactedAndFactBased(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"auth-credential.key", "account-notebook.key", "browser-site-reviews.key", "push-subscription.key", "vapid-keys.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("private-marker"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "haven.db"), []byte("SQLite format 3\x00payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.EnsureHubPKI(filepath.Join(directory, "pki"), time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	privateOrigin := "https://private-host.example:8443"
	report := Hub(context.Background(), HubOptions{StateDirectory: directory, DataPath: filepath.Join(directory, "haven.db"), PublicOrigin: privateOrigin, DashboardAddress: "127.0.0.1:5080", AgentAddress: "0.0.0.0:5443", Production: true, ManagedAppliances: 1, StoreProbe: func(context.Context) error { return nil }, Now: time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC)})
	encoded, err := JSON(report)
	if err != nil {
		t.Fatal(err)
	}
	text := Text(report)
	for _, privateValue := range []string{directory, privateOrigin, "private-host", "private-marker", "secret-marker", "127.0.0.1", "0.0.0.0", ":5080", ":5443"} {
		if strings.Contains(string(encoded), privateValue) || strings.Contains(text, privateValue) {
			t.Fatalf("diagnostic output leaked private value %q", privateValue)
		}
	}
	if report.Status != "ready" || report.Summary.Advisory != 0 || report.Summary.Failed != 0 {
		t.Fatalf("unexpected report summary: %#v", report.Summary)
	}
}

func TestHubReportFailsClosedWhenContinuityMaterialIsMissing(t *testing.T) {
	directory := t.TempDir()
	report := Hub(context.Background(), HubOptions{StateDirectory: directory, DataPath: filepath.Join(directory, "missing.db"), PublicOrigin: "http://localhost:5080", DashboardAddress: "invalid", AgentAddress: "invalid", Production: true})
	if report.Status != "not-ready" || report.Summary.Failed < 5 {
		t.Fatalf("missing continuity material must be visible: %#v", report.Summary)
	}
}

func TestHubPKICheckRejectsAnUncoveredServerNameWithoutDisclosingIt(t *testing.T) {
	now := time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC)
	directory := t.TempDir()
	if _, err := trust.EnsureHubPKI(filepath.Join(directory, "pki"), now); err != nil {
		t.Fatal(err)
	}
	privateName := "private-agent.example"
	check := pkiCheck(directory, []string{privateName}, now)
	if check.State != StateFail || !strings.Contains(check.Summary, "does not cover") {
		t.Fatalf("unexpected check: %#v", check)
	}
	if strings.Contains(check.Summary+check.Guidance, privateName) {
		t.Fatal("certificate diagnostic disclosed a private server name")
	}
}

func TestRecoveryPlanNeverClaimsSourceRestoresPrivateState(t *testing.T) {
	plan := redactedRecoveryPlan()
	joined := strings.Join(append(append(plan.Preserved, plan.Reinitialize...), plan.Checklist...), " ")
	for _, required := range []string{"complete, matching private state directory", "Private hostnames", "Every agent identity"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing recovery boundary %q", required)
		}
	}
}

func TestAgentReportValidatesIdentityWithoutDisclosingIt(t *testing.T) {
	now := time.Date(2026, 9, 5, 2, 3, 4, 0, time.UTC)
	directory := t.TempDir()
	pki, err := trust.EnsureHubPKI(filepath.Join(t.TempDir(), "pki"), now)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := trust.GenerateAgentIdentity("private-device-label")
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, err := pki.SignAgentCertificate(identity.CSRPEM, "private-device-id", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(agent.Config{HubURL: "https://private-hub.example:5443", DeviceID: "private-device-id", DisplayName: "private-device-label", Sequence: 3})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{"config.json": config, "ca.crt": pki.CACertificatePEM, "client.crt": certificate, "client.key": identity.PrivateKeyPEM} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := Agent(context.Background(), directory, "windows-task", now)
	if report.Status != "ready" || report.Summary.Failed != 0 || report.Summary.Advisory != 0 {
		t.Fatalf("unexpected valid-agent report: %#v", report.Summary)
	}
	contents, err := JSON(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{directory, "private-hub", "private-device-id", "private-device-label"} {
		if strings.Contains(string(contents), privateValue) {
			t.Fatalf("agent diagnostic leaked %q", privateValue)
		}
	}
}
