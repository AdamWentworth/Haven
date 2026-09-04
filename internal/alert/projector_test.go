package alert

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

var fixedTime = time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)

func observedDevice(status string, connections ...model.NetworkConnection) DeviceObservation {
	lastSeen := fixedTime.Add(-time.Minute)
	return DeviceObservation{
		Device: model.DeviceRecord{ID: "device-a", DisplayName: "Test workstation", TrustState: "enrolled", Status: status, EnrolledAt: fixedTime.Add(-24 * time.Hour), LastSeenAt: &lastSeen},
		Snapshot: &model.SecuritySnapshot{
			CollectedAt: fixedTime,
			Device:      model.DeviceSummary{DeviceID: "device-a", HostName: "test-workstation", OperatingSystem: "Test OS"},
			Connections: connections,
		},
	}
}

func listener(port int, address, process, unit string) model.NetworkConnection {
	return model.NetworkConnection{Protocol: "TCP", LocalAddress: address, LocalPort: port, State: "Listen", ProcessName: process, SystemdUnit: unit}
}

func TestDeriveUsesOnlyCurrentFindingsAndLatestOpenLifecycle(t *testing.T) {
	device := observedDevice("current")
	device.Snapshot.Findings = []model.SecurityFinding{{ID: "firewall-disabled", Severity: "high", Title: "Firewall disabled", Summary: "No host policy is active."}}
	events := []model.SecurityEvent{
		{ID: 1, DeviceID: "device-a", FindingID: "firewall-disabled", Kind: "opened", OccurredAt: fixedTime.Add(-4 * time.Hour)},
		{ID: 2, DeviceID: "device-a", FindingID: "firewall-disabled", Kind: "resolved", OccurredAt: fixedTime.Add(-3 * time.Hour)},
		{ID: 3, DeviceID: "device-a", FindingID: "firewall-disabled", Kind: "opened", OccurredAt: fixedTime.Add(-2 * time.Hour)},
		{ID: 4, DeviceID: "device-a", FindingID: "historical-only", Kind: "opened", OccurredAt: fixedTime.Add(-time.Hour)},
	}
	alerts := Derive([]DeviceObservation{device}, events, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].StartedAt != events[2].OccurredAt || alerts[0].Severity != "high" {
		t.Fatalf("expected only the current recurrence, got %#v", alerts)
	}
	if alerts[0].InstanceID == alerts[0].ID {
		t.Fatal("recurrence identity must be distinct from the stable alert identity")
	}
}

func TestDeriveAppliesOwnerFindingReviewSemantics(t *testing.T) {
	device := observedDevice("current")
	device.Snapshot.Findings = []model.SecurityFinding{
		{ID: "accepted", Severity: "medium", Title: "Accepted", Summary: "Deliberate risk."},
		{ID: "snoozed", Severity: "medium", Title: "Snoozed", Summary: "Review later."},
		{ID: "expired-snooze", Severity: "medium", Title: "Expired snooze", Summary: "Review again."},
		{ID: "acknowledged", Severity: "low", Title: "Acknowledged", Summary: "Still active."},
	}
	future := fixedTime.Add(time.Hour)
	past := fixedTime.Add(-time.Hour)
	device.FindingReviews = []storage.FindingReview{
		{DeviceID: "device-a", FindingID: "accepted", State: "accepted-risk", ReviewedAt: fixedTime.Add(-2 * time.Hour)},
		{DeviceID: "device-a", FindingID: "snoozed", State: "snoozed", SnoozedUntil: &future, ReviewedAt: fixedTime.Add(-time.Hour)},
		{DeviceID: "device-a", FindingID: "expired-snooze", State: "snoozed", SnoozedUntil: &past, ReviewedAt: fixedTime.Add(-2 * time.Hour)},
		{DeviceID: "device-a", FindingID: "acknowledged", State: "acknowledged", ReviewedAt: fixedTime.Add(-time.Hour)},
	}

	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 2 {
		t.Fatalf("accepted risk and active snooze must leave two visible alerts, got %#v", alerts)
	}
	if alerts[0].ID != "finding:device-a:expired-snooze" || alerts[1].ID != "finding:device-a:acknowledged" {
		t.Fatalf("expired snooze and acknowledgement must remain visible, got %#v", alerts)
	}
}

func TestDeriveSeparatesNewServiceFromOwnerDrift(t *testing.T) {
	device := observedDevice("current",
		listener(443, "0.0.0.0", "caddy", "caddy.service"),
		listener(8443, "192.0.2.10", "unexpected", "unexpected.service"),
	)
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "HAVEN", Protocol: "TCP", Port: 8443, PortEnd: 8443,
		BindScope: storage.BindScopeSpecific, ProcessNames: []string{"haven-proxy"}, SystemdUnits: []string{"haven-proxy.service"},
	}}
	device.Listeners = []storage.ObservedListener{
		{DeviceID: "device-a", Protocol: "TCP", Port: 443, BindScope: storage.BindScopeWildcard, AppearedAt: fixedTime.Add(-time.Hour), Present: true},
		{DeviceID: "device-a", Protocol: "TCP", Port: 8443, BindScope: storage.BindScopeSpecific, AppearedAt: fixedTime.Add(-2 * time.Hour), Present: true},
	}
	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 2 || alerts[0].Kind != "new-service" || alerts[1].Kind != "service-drift" {
		t.Fatalf("expected a new service and owner drift, got %#v", alerts)
	}
	if alerts[0].StartedAt != device.Listeners[0].AppearedAt || alerts[1].StartedAt != device.Listeners[1].AppearedAt {
		t.Fatal("listener recurrence must use persisted appearance evidence")
	}
}

func TestDeriveIgnoresLocalAndOwnerApprovedServices(t *testing.T) {
	device := observedDevice("current",
		listener(5080, "127.0.0.1", "haven-hub", ""),
		listener(22, "0.0.0.0", "sshd", "ssh.socket"),
	)
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "SSH", Protocol: "TCP", Port: 22, PortEnd: 22,
		BindScope: storage.BindScopeWildcard, ProcessNames: []string{"sshd"}, SystemdUnits: []string{"ssh.socket"},
	}}
	if alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime); len(alerts) != 0 {
		t.Fatalf("local and owner-approved listeners must not alert: %#v", alerts)
	}
}

func TestDeriveCreatesANewLifecycleWhenTemporaryExpectationExpires(t *testing.T) {
	device := observedDevice("current", listener(8765, "0.0.0.0", "node", "apk-test.service"))
	futureExpiration := fixedTime.Add(time.Hour)
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "Temporary APK test server", Protocol: "TCP", Port: 8765, PortEnd: 8765,
		BindScope: storage.BindScopeWildcard, ProcessNames: []string{"node"}, SystemdUnits: []string{"apk-test.service"}, ExpiresAt: &futureExpiration,
	}}
	if alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime); len(alerts) != 0 {
		t.Fatalf("an unexpired temporary expectation must remain active: %#v", alerts)
	}

	firstExpiration := fixedTime.Add(-time.Hour)
	device.ExpectedServices[0].ExpiresAt = &firstExpiration
	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "expired-service-expectation" || !alerts[0].StartedAt.Equal(firstExpiration) || !strings.Contains(alerts[0].Evidence, "Temporary APK test server") {
		t.Fatalf("expected an evidence-backed expiration alert, got %#v", alerts)
	}
	firstInstance := alerts[0].InstanceID

	renewedExpiration := fixedTime.Add(-30 * time.Minute)
	device.ExpectedServices[0].ExpiresAt = &renewedExpiration
	alerts = Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].InstanceID == firstInstance || !alerts[0].StartedAt.Equal(renewedExpiration) {
		t.Fatalf("each expired renewal must create a distinct alert lifecycle, got %#v", alerts)
	}
}

func TestDeriveReportsDriftWhenAProcessJoinsAnApprovedSystemService(t *testing.T) {
	device := observedDevice("current",
		model.NetworkConnection{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 5353, State: "Bound", ProcessName: "avahi-daemon", SystemdUnit: "avahi-daemon.service"},
		model.NetworkConnection{Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 5353, State: "Bound", ProcessName: "adb"},
	)
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "mDNS discovery", Protocol: "UDP", Port: 5353, PortEnd: 5353,
		BindScope: storage.BindScopeWildcard, ProcessNames: []string{"avahi-daemon"}, SystemdUnits: []string{"avahi-daemon.service"},
	}}
	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "service-drift" {
		t.Fatalf("a newly observed co-owner must require review: %#v", alerts)
	}
}

func TestDeriveRequiresLiveWorkloadEvidenceForWorkloadBaseline(t *testing.T) {
	device := observedDevice("current", listener(443, "0.0.0.0", "docker-proxy", "docker.service"))
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "HTTPS", Protocol: "TCP", Port: 443, PortEnd: 443,
		BindScope: storage.BindScopeWildcard, ProcessNames: []string{"docker-proxy"}, WorkloadNames: []string{"gateway"}, SystemdUnits: []string{"docker.service"},
	}}
	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "service-drift" {
		t.Fatalf("a workload-constrained baseline needs current attribution: %#v", alerts)
	}
	device.Snapshot.LinuxBaseline = &model.LinuxBaseline{Workloads: &model.WorkloadInventory{Workloads: []model.ContainerWorkload{{
		Name: "gateway", Ports: []model.ContainerPortBinding{{Protocol: "TCP", Published: true, HostAddress: "0.0.0.0", HostPort: 443}},
	}}}}
	if alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime); len(alerts) != 0 {
		t.Fatalf("matching live workload attribution should satisfy the baseline: %#v", alerts)
	}
}

func TestDeriveAllowsDockerServiceEvidenceForLegacyWorkloadBaseline(t *testing.T) {
	device := observedDevice("current", listener(443, "0.0.0.0", "", "docker.service"))
	device.ExpectedServices = []storage.ExpectedService{{
		DeviceID: "device-a", Label: "HTTPS", Protocol: "TCP", Port: 443, PortEnd: 443,
		BindScope: storage.BindScopeWildcard, WorkloadNames: []string{"gateway"},
	}}
	device.Snapshot.LinuxBaseline = &model.LinuxBaseline{Workloads: &model.WorkloadInventory{Runtime: "docker", Workloads: []model.ContainerWorkload{{
		Name: "gateway", Ports: []model.ContainerPortBinding{{Protocol: "TCP", Published: true, HostAddress: "0.0.0.0", HostPort: 443}},
	}}}}
	if alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime); len(alerts) != 0 {
		t.Fatalf("Docker's own service unit should not invalidate a matching legacy workload baseline: %#v", alerts)
	}
	device.Snapshot.Connections[0].SystemdUnit = "unexpected.service"
	alerts := Derive([]DeviceObservation{device}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "service-drift" {
		t.Fatalf("an unrelated service unit must still require review: %#v", alerts)
	}
}

func TestDeriveClassifiesFreshnessAndOrdersSeverity(t *testing.T) {
	stale := observedDevice("stale")
	stale.Device.LastSeenAt = timePointer(fixedTime.Add(-time.Hour))
	stale.Snapshot.Findings = []model.SecurityFinding{{ID: "low", Severity: "low", Title: "Low", Summary: "Review later."}}
	awaiting := observedDevice("awaiting-first-report")
	awaiting.Device.ID = "device-b"
	awaiting.Device.DisplayName = "Test laptop"
	awaiting.Snapshot = nil
	alerts := Derive([]DeviceObservation{stale, awaiting}, nil, 30*time.Minute, fixedTime)
	if len(alerts) != 3 || alerts[0].Kind != "stale-agent" || alerts[0].StartedAt != fixedTime.Add(-30*time.Minute) {
		t.Fatalf("expected medium stale alert before low alerts: %#v", alerts)
	}
	if alerts[1].Severity != "low" || alerts[2].Severity != "low" {
		t.Fatalf("expected remaining low alerts: %#v", alerts)
	}
}

func TestSharedServiceExpectationContract(t *testing.T) {
	type fixture struct {
		Name     string `json:"name"`
		Listener struct {
			Protocol     string   `json:"protocol"`
			Address      string   `json:"address"`
			Port         int      `json:"port"`
			Processes    []string `json:"processes"`
			SystemdUnits []string `json:"systemdUnits"`
		} `json:"listener"`
		Service struct {
			Protocol      string   `json:"protocol"`
			Port          int      `json:"port"`
			PortEnd       int      `json:"portEnd"`
			BindScope     string   `json:"bindScope"`
			ProcessNames  []string `json:"processNames"`
			WorkloadNames []string `json:"workloadNames"`
			SystemdUnits  []string `json:"systemdUnits"`
		} `json:"service"`
		Workloads []string `json:"workloads"`
		Matches   bool     `json:"matches"`
	}
	encoded, err := os.ReadFile("../../testdata/service_expectation_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []fixture
	if err := json.Unmarshal(encoded, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixtures {
		t.Run(item.Name, func(t *testing.T) {
			connections := make([]model.NetworkConnection, 0, len(item.Listener.Processes)+len(item.Listener.SystemdUnits))
			count := len(item.Listener.Processes)
			if len(item.Listener.SystemdUnits) > count {
				count = len(item.Listener.SystemdUnits)
			}
			if count == 0 {
				count = 1
			}
			for index := 0; index < count; index++ {
				connection := model.NetworkConnection{Protocol: item.Listener.Protocol, LocalAddress: item.Listener.Address, LocalPort: item.Listener.Port, State: "Listen"}
				if index < len(item.Listener.Processes) {
					connection.ProcessName = item.Listener.Processes[index]
				}
				if index < len(item.Listener.SystemdUnits) {
					connection.SystemdUnit = item.Listener.SystemdUnits[index]
				}
				connections = append(connections, connection)
			}
			listener := logicalListeners(connections)[0]
			service := storage.ExpectedService{DeviceID: "fixture", Protocol: item.Service.Protocol, Port: item.Service.Port, PortEnd: item.Service.PortEnd, BindScope: item.Service.BindScope, ProcessNames: item.Service.ProcessNames, WorkloadNames: item.Service.WorkloadNames, SystemdUnits: item.Service.SystemdUnits}
			var inventory *model.WorkloadInventory
			if len(item.Workloads) > 0 {
				inventory = &model.WorkloadInventory{Runtime: "docker"}
				for _, name := range item.Workloads {
					inventory.Workloads = append(inventory.Workloads, model.ContainerWorkload{Name: name, Ports: []model.ContainerPortBinding{{Protocol: item.Listener.Protocol, Published: true, HostAddress: item.Listener.Address, HostPort: item.Listener.Port}}})
				}
			}
			if got := expectedServiceMatches(listener, service, inventory); got != item.Matches {
				t.Fatalf("shared policy result = %t, want %t", got, item.Matches)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time { return &value }
