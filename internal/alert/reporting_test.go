package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

func TestIntermittentAbsenceKeepsFindingsAndOnlyAddsLowReminder(t *testing.T) {
	device := observedDevice("stale")
	device.Device.ReportingExpectation = "intermittent"
	last := fixedTime.Add(-3 * 24 * time.Hour)
	device.Device.LastSeenAt = &last
	device.Snapshot.CollectedAt = last
	device.Snapshot.Findings = []model.SecurityFinding{{ID: "test-finding", Severity: "high", Title: "Last observed finding"}}
	alerts := Derive([]DeviceObservation{device}, nil, storage.EnrolledDeviceStaleAfter, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "finding" || !strings.Contains(alerts[0].Evidence, last.Format(time.RFC3339)) {
		t.Fatalf("expected absence hid a finding or created an alert: %#v", alerts)
	}
	device.Snapshot.Findings = nil
	last = fixedTime.Add(-storage.IntermittentDeviceReminderAfter)
	if alerts = Derive([]DeviceObservation{device}, nil, storage.EnrolledDeviceStaleAfter, fixedTime); len(alerts) != 0 {
		t.Fatalf("premature reminder: %#v", alerts)
	}
	last = last.Add(-time.Second)
	alerts = Derive([]DeviceObservation{device}, nil, storage.EnrolledDeviceStaleAfter, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "check-in-reminder" || alerts[0].Severity != "low" || !alerts[0].StartedAt.Equal(last.Add(storage.IntermittentDeviceReminderAfter)) {
		t.Fatalf("incorrect reminder: %#v", alerts)
	}
	device.Device.Status = "current"
	if alerts = Derive([]DeviceObservation{device}, nil, storage.EnrolledDeviceStaleAfter, fixedTime); len(alerts) != 0 {
		t.Fatal("reporting again must clear reminder")
	}
	device.Device.Status = "stale"
	device.Device.ReportingExpectation = "always-on"
	alerts = Derive([]DeviceObservation{device}, nil, storage.EnrolledDeviceStaleAfter, fixedTime)
	if len(alerts) != 1 || alerts[0].Kind != "stale-agent" || alerts[0].Severity != "medium" {
		t.Fatal("always-on overdue alert changed")
	}
}
