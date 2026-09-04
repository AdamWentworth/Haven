package appliance

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

type captureStatusStore struct {
	definitions []model.ManagedApplianceDefinition
	services    []model.ManagedServiceStatus
	health      *model.ManagedHealthStatus
}

func (store *captureStatusStore) RecordManagedApplianceHealth(_ context.Context, _ string, health model.ManagedHealthStatus, _ time.Time) error {
	store.health = &health
	return nil
}

func (store *captureStatusStore) SyncManagedAppliances(_ context.Context, definitions []model.ManagedApplianceDefinition, _ time.Time) error {
	store.definitions = definitions
	return nil
}

func (store *captureStatusStore) RecordManagedApplianceProbe(_ context.Context, _ string, services []model.ManagedServiceStatus, _ time.Time) error {
	store.services = services
	return nil
}

func (*captureStatusStore) ListManagedAppliances(context.Context) ([]model.ManagedApplianceStatus, error) {
	return nil, nil
}

func TestLoadDefinitionsAcceptsOnlyExplicitPrivateEndpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appliances.json")
	privateAddress := strings.Join([]string{"192", "168", "1", "69"}, ".")
	contents := fmt.Sprintf(`{
		"appliances": [{
			"id": " Home-NAS ", "displayName": "TNAS", "kind": " NAS ", "address": %q,
			"health": {
				"provider": " TerraMaster-TOS5 ", "snmpPort": 161,
				"communityFile": "/run/secrets/nas-community", "sshPort": 9222,
				"sshUsername": "adam", "sshPrivateKeyFile": "/run/secrets/nas-key",
				"sshHostKeySHA256": "SHA256:+z7AR7nyLAfU5Vzn0J3/DtnnQ4hqy7TshW3nWeu+uxU"
			},
			"services": [
				{"id":"smb","name":"SMB","protocol":"tcp","port":445,"tls":false,"required":true},
				{"id":"admin","name":"Management HTTPS","protocol":"TCP","port":5443,"tls":true,"required":true}
			]
		}]
	}`, privateAddress)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	definitions, err := LoadDefinitions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 || definitions[0].ID != "home-nas" || definitions[0].Kind != "nas" || definitions[0].Services[0].Protocol != "TCP" || definitions[0].Health == nil || definitions[0].Health.Provider != "terramaster-tos5" {
		t.Fatalf("configuration was not normalized: %#v", definitions)
	}
}

func TestLoadDefinitionsRejectsDiscoveryLikeOrAmbiguousConfiguration(t *testing.T) {
	privateAddress := strings.Join([]string{"192", "168", "1", "69"}, ".")
	tests := map[string]string{
		"public address":    `{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":"203.0.113.9","services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`,
		"hostname":          `{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":"nas.example","services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`,
		"range":             fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`, privateAddress+"/24"),
		"udp":               fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"services":[{"id":"snmp","name":"SNMP","protocol":"UDP","port":161}]}]}`, privateAddress),
		"unknown field":     fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"scan":true,"services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`, privateAddress),
		"duplicate port":    fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"services":[{"id":"a","name":"A","protocol":"TCP","port":445},{"id":"b","name":"B","protocol":"TCP","port":445}]}]}`, privateAddress),
		"inline community":  fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"health":{"provider":"terramaster-tos5","community":"public"},"services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`, privateAddress),
		"relative secret":   fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"health":{"provider":"terramaster-tos5","communityFile":"secret","sshUsername":"adam","sshPrivateKeyFile":"/run/secrets/key","sshHostKeySHA256":"SHA256:+z7AR7nyLAfU5Vzn0J3/DtnnQ4hqy7TshW3nWeu+uxU"},"services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`, privateAddress),
		"broad secret path": fmt.Sprintf(`{"appliances":[{"id":"nas","displayName":"NAS","kind":"nas","address":%q,"health":{"provider":"terramaster-tos5","communityFile":"/etc/passwd","sshUsername":"adam","sshPrivateKeyFile":"/run/secrets/key","sshHostKeySHA256":"SHA256:+z7AR7nyLAfU5Vzn0J3/DtnnQ4hqy7TshW3nWeu+uxU"},"services":[{"id":"smb","name":"SMB","protocol":"TCP","port":445}]}]}`, privateAddress),
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "appliances.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDefinitions(path); err == nil {
				t.Fatal("unsafe or ambiguous configuration was accepted")
			}
		})
	}
}

func TestDeriveAlertsRequiresRepeatedRequiredServiceFailure(t *testing.T) {
	now := time.Date(2026, time.September, 4, 6, 0, 0, 0, time.UTC)
	changed := now.Add(-20 * time.Minute)
	checked := now.Add(-time.Minute)
	status := model.ManagedApplianceStatus{
		ID: "nas", DisplayName: "NAS", LastCheckedAt: &checked,
		Services: []model.ManagedServiceStatus{
			{ID: "smb", Name: "SMB", Protocol: "TCP", Port: 445, Required: true, ConsecutiveFailures: 1, LastChangedAt: &changed},
			{ID: "http", Name: "HTTP redirect", Protocol: "TCP", Port: 80, Required: false, ConsecutiveFailures: 8, LastChangedAt: &changed},
		},
	}
	if alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now); len(alerts) != 0 {
		t.Fatalf("a transient or optional failure must remain quiet: %#v", alerts)
	}
	status.Services[0].ConsecutiveFailures = FailureThreshold
	alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now)
	if len(alerts) != 1 || alerts[0].Kind != "appliance-unreachable" {
		t.Fatalf("all required services down should collapse to one appliance alert: %#v", alerts)
	}
	if !alerts[0].StartedAt.Equal(changed) {
		t.Fatalf("failure transition should anchor alert identity: %#v", alerts[0])
	}
}

func TestDeriveAlertsSeparatesPartialFailureAndCertificateExpiry(t *testing.T) {
	now := time.Date(2026, time.September, 4, 6, 0, 0, 0, time.UTC)
	checked := now.Add(-time.Minute)
	changed := now.Add(-15 * time.Minute)
	status := model.ManagedApplianceStatus{
		ID: "nas", DisplayName: "NAS", LastCheckedAt: &checked,
		Services: []model.ManagedServiceStatus{
			{ID: "smb", Name: "SMB", Protocol: "TCP", Port: 445, Required: true, Reachable: true, LastChangedAt: &changed},
			{ID: "admin", Name: "Management HTTPS", Protocol: "TCP", Port: 5443, Required: true, ConsecutiveFailures: 2, LastChangedAt: &changed},
			{ID: "backup", Name: "Backup HTTPS", Protocol: "TCP", Port: 443, TLS: true, Reachable: true, Certificate: &model.ManagedCertificateStatus{NotAfter: now.Add(10 * 24 * time.Hour)}},
		},
	}
	alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now)
	if len(alerts) != 2 {
		t.Fatalf("expected service and certificate alerts, got %#v", alerts)
	}
	kinds := alerts[0].Kind + "," + alerts[1].Kind
	if !strings.Contains(kinds, "appliance-service") || !strings.Contains(kinds, "appliance-certificate") {
		t.Fatalf("unexpected alert kinds: %s", kinds)
	}
}

func TestDeriveAlertsReportsOverdueHubChecks(t *testing.T) {
	now := time.Date(2026, time.September, 4, 6, 0, 0, 0, time.UTC)
	checked := now.Add(-StaleAfter - time.Second)
	status := model.ManagedApplianceStatus{ID: "nas", DisplayName: "NAS", LastCheckedAt: &checked}
	alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now)
	if len(alerts) != 1 || alerts[0].Kind != "appliance-stale" {
		t.Fatalf("expected one stale check alert, got %#v", alerts)
	}
}

func TestDeriveAlertsProjectsOnlyRepeatedOrActionableHealthConditions(t *testing.T) {
	now := time.Date(2026, time.September, 4, 8, 0, 0, 0, time.UTC)
	checked := now.Add(-time.Minute)
	changed := now.Add(-10 * time.Minute)
	status := model.ManagedApplianceStatus{
		ID: "nas", DisplayName: "NAS", LastCheckedAt: &checked,
		Health: &model.ManagedHealthStatus{
			Status: "partial", LastCheckedAt: &checked, LastChangedAt: &changed,
			Coverage: model.ManagedHealthCoverage{Disks: "partial", RAID: "partial", Temperature: "unsupported", Capacity: "verified", Firmware: "partial"},
			Volumes:  []model.ManagedVolumeHealth{{Name: "/Volume1", UsedPercentage: 40, State: "healthy", LastChangedAt: &changed}},
		},
	}
	if alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now); len(alerts) != 0 {
		t.Fatalf("partial but non-actionable coverage should remain visible without an alert: %#v", alerts)
	}
	status.Health.Status = "attention"
	status.Health.Pools = []model.ManagedPoolHealth{{Name: "/dev/md0", RAIDLevel: "raid1", State: "degraded", MemberCount: 2, ActiveCount: 1, LastChangedAt: &changed}}
	status.Health.Volumes[0] = model.ManagedVolumeHealth{Name: "/Volume1", UsedPercentage: 96, State: "critical", LastChangedAt: &changed}
	alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now)
	if len(alerts) != 2 || alerts[0].Kind != "appliance-raid" || alerts[0].Severity != "high" || alerts[1].Kind != "appliance-capacity" {
		t.Fatalf("actionable health evidence was not projected: %#v", alerts)
	}
	if !strings.Contains(alerts[0].InstanceID, changed.Format(time.RFC3339)) {
		t.Fatalf("health alert identity did not retain the condition transition: %#v", alerts[0])
	}
	status.Health = &model.ManagedHealthStatus{Status: "unavailable", LastCheckedAt: &checked, LastChangedAt: &changed, ConsecutiveFailures: 1, ErrorClass: "health-sources-unavailable"}
	if alerts := DeriveAlerts([]model.ManagedApplianceStatus{status}, now); len(alerts) != 0 {
		t.Fatalf("one failed health collection should be a quiet retry: %#v", alerts)
	}
	status.Health.ConsecutiveFailures = FailureThreshold
	alerts = DeriveAlerts([]model.ManagedApplianceStatus{status}, now)
	if len(alerts) != 1 || alerts[0].Kind != "appliance-health" {
		t.Fatalf("repeated health collection failure did not alert: %#v", alerts)
	}
}

func TestMonitorObservesTLSWithoutIssuingApplicationRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requestCount++ }))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	store := &captureStatusStore{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	definition := model.ManagedApplianceDefinition{
		ID: "nas", DisplayName: "NAS", Kind: "nas", Address: "127.0.0.1",
		Services: []model.ManagedServiceDefinition{{ID: "admin", Name: "Admin TLS", Protocol: "TCP", Port: port, TLS: true, Required: true}},
	}
	monitor, err := NewMonitor(context.Background(), store, logger, []model.ManagedApplianceDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.services) != 1 || !store.services[0].Reachable || store.services[0].Certificate == nil || store.services[0].Certificate.Fingerprint == "" {
		t.Fatalf("TLS certificate evidence was not captured: %#v", store.services)
	}
	if requestCount != 0 {
		t.Fatalf("credential-free TLS observation sent %d application requests", requestCount)
	}
}
