package appliance

import (
	"math"
	"testing"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/gosnmp/gosnmp"
)

func TestParseSNMPVolumesKeepsOnlyTopLevelManagedVolumes(t *testing.T) {
	values := []gosnmp.SnmpPDU{
		pdu(".1.3.6.1.2.1.25.2.3.1.2.39", gosnmp.ObjectIdentifier, ".1.3.6.1.2.1.25.2.1.4"),
		pdu(".1.3.6.1.2.1.25.2.3.1.3.39", gosnmp.OctetString, []byte("/Volume1")),
		pdu(".1.3.6.1.2.1.25.2.3.1.4.39", gosnmp.Integer, 8192),
		pdu(".1.3.6.1.2.1.25.2.3.1.5.39", gosnmp.Integer, 1000),
		pdu(".1.3.6.1.2.1.25.2.3.1.6.39", gosnmp.Integer, 875),
		pdu(".1.3.6.1.2.1.25.2.3.1.2.54", gosnmp.ObjectIdentifier, ".1.3.6.1.2.1.25.2.1.4"),
		pdu(".1.3.6.1.2.1.25.2.3.1.3.54", gosnmp.OctetString, []byte("/Volume1/@DockerData")),
		pdu(".1.3.6.1.2.1.25.2.3.1.4.54", gosnmp.Integer, 8192),
		pdu(".1.3.6.1.2.1.25.2.3.1.5.54", gosnmp.Integer, 1000),
		pdu(".1.3.6.1.2.1.25.2.3.1.6.54", gosnmp.Integer, 875),
	}
	volumes := parseSNMPVolumes(values)
	if len(volumes) != 1 || volumes[0].Name != "/Volume1" || volumes[0].CapacityBytes != 8_192_000 || volumes[0].State != "warning" || math.Abs(volumes[0].UsedPercentage-87.5) > 0.01 {
		t.Fatalf("unexpected SNMP volume projection: %#v", volumes)
	}
}

func TestParseSNMPDevicesDistinguishesPhysicalAndRAIDTopology(t *testing.T) {
	values := []gosnmp.SnmpPDU{
		pdu(".1.3.6.1.2.1.25.3.2.1.3.393232", gosnmp.OctetString, []byte("SCSI disk (/dev/sda)")),
		pdu(".1.3.6.1.2.1.25.3.2.1.3.393248", gosnmp.OctetString, []byte("RAID disk (/dev/md0)")),
		pdu(".1.3.6.1.2.1.25.3.2.1.3.262146", gosnmp.OctetString, []byte("network interface eth0")),
	}
	disks, pools := parseSNMPDevices(values)
	if len(disks) != 1 || disks[0].Name != "/dev/sda" || disks[0].SMART != "unavailable" {
		t.Fatalf("unexpected physical disks: %#v", disks)
	}
	if len(pools) != 1 || pools[0].Name != "/dev/md0" || pools[0].State != "unknown" {
		t.Fatalf("unexpected RAID topology: %#v", pools)
	}
}

func TestParseSNMPTemperaturesAppliesDocumentedUnitsAndThresholds(t *testing.T) {
	values := []gosnmp.SnmpPDU{
		pdu(".1.3.6.1.4.1.2021.13.16.2.1.2.7", gosnmp.OctetString, []byte("CPU sensor")),
		pdu(".1.3.6.1.4.1.2021.13.16.2.1.3.7", gosnmp.Integer, 76500),
	}
	temperatures := parseSNMPTemperatures(values)
	if len(temperatures) != 1 || temperatures[0].Celsius != 76.5 || temperatures[0].State != "warning" {
		t.Fatalf("unexpected temperature projection: %#v", temperatures)
	}
}

func TestHealthStatusDoesNotTreatPartialEvidenceAsHealthy(t *testing.T) {
	status := model.ManagedHealthStatus{
		Coverage: model.ManagedHealthCoverage{Disks: "verified", RAID: "partial", Temperature: "unsupported", Capacity: "verified", Firmware: "partial"},
		Volumes:  []model.ManagedVolumeHealth{{Name: "/Volume1", UsedPercentage: 20, State: "healthy"}},
	}
	if got := deriveHealthStatus(status); got != "partial" {
		t.Fatalf("partial evidence was overstated as %q", got)
	}
	status.Pools = []model.ManagedPoolHealth{{Name: "/dev/md0", State: "degraded"}}
	if got := deriveHealthStatus(status); got != "attention" {
		t.Fatalf("degraded RAID was not actionable: %q", got)
	}
	status.Pools[0].State = "rebuilding"
	if got := deriveHealthStatus(status); got != "attention" {
		t.Fatalf("active RAID rebuild was not surfaced for review: %q", got)
	}
}

func TestNormalizeHealthReportRecomputesSafetyCriticalStates(t *testing.T) {
	temperature := 42.0
	report := normalizeHealthReport(healthReport{
		Coverage:     model.ManagedHealthCoverage{Disks: "verified", RAID: "verified", Temperature: "verified", Capacity: "verified", Firmware: "verified"},
		Disks:        []model.ManagedDiskHealth{{Name: "/dev/sda", State: "healthy", SMART: "failed", TemperatureC: &temperature}},
		Pools:        []model.ManagedPoolHealth{{Name: "/dev/md0", State: "healthy", MemberCount: 2, ActiveCount: 1}},
		Volumes:      []model.ManagedVolumeHealth{{Name: "/Volume1", CapacityBytes: 1000, AvailableBytes: 40, UsedPercentage: 5, State: "healthy"}},
		Temperatures: []model.ManagedTemperature{{Name: "disk", Kind: "disk", Celsius: 61, State: "healthy"}},
	})
	if report.Disks[0].State != "failed" || report.Pools[0].State != "degraded" || report.Volumes[0].State != "critical" || report.Volumes[0].UsedPercentage != 96 || report.Temperatures[0].State != "critical" {
		t.Fatalf("unsafe helper states were trusted instead of recomputed: %#v", report)
	}
}

func pdu(name string, kind gosnmp.Asn1BER, value any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: kind, Value: value}
}
