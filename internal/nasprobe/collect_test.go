package nasprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"testing"
)

func TestParseMDStatIdentifiesHealthyDegradedAndRebuildingPools(t *testing.T) {
	contents := `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976630336 blocks super 1.2 [2/2] [UU]

md1 : active raid1 sda2[0]
      8380416 blocks super 1.2 [2/1] [U_]

md2 : active raid5 sda3[0] sdb3[1] sdc3[2]
      1000 blocks [3/3] [UUU]
      [===>.................] recovery = 18.0%
`
	pools := parseMDStat(contents)
	if len(pools) != 3 {
		t.Fatalf("got %d pools: %#v", len(pools), pools)
	}
	if pools[0].Name != "/dev/md0" || pools[0].State != "healthy" || pools[0].MemberCount != 2 || pools[0].ActiveCount != 2 {
		t.Fatalf("unexpected healthy pool: %#v", pools[0])
	}
	if pools[1].State != "degraded" || pools[1].ActiveCount != 1 {
		t.Fatalf("unexpected degraded pool: %#v", pools[1])
	}
	if pools[2].State != "rebuilding" {
		t.Fatalf("unexpected rebuilding pool: %#v", pools[2])
	}
}

func TestParseDFKeepsTopLevelVolumesAndUsesAvailableCapacity(t *testing.T) {
	output := []byte(`Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/vg0/lv0 1000000 760000 240000 76% /Volume1
/dev/vg0/lv0 1000000 760000 240000 76% /Volume1/@DockerData
`)
	volumes := parseDF(output)
	if len(volumes) != 1 || volumes[0].Name != "/Volume1" || volumes[0].CapacityBytes != 1_024_000_000 || math.Abs(volumes[0].UsedPercentage-76) > 0.001 || volumes[0].State != "healthy" {
		t.Fatalf("unexpected volumes: %#v", volumes)
	}
}

func TestParseSMARTHonorsStandbyAndHealthWithoutSerialProjection(t *testing.T) {
	state, temperature, ok := parseSMART([]byte(`{"smart_status":{"passed":true},"temperature":{"current":42},"serial_number":"must-not-be-decoded"}`))
	if !ok || state != "healthy" || temperature == nil || *temperature != 42 {
		t.Fatalf("unexpected SMART result: %q %#v %t", state, temperature, ok)
	}
	state, temperature, ok = parseSMART([]byte(`{"power_mode":"STANDBY"}`))
	if !ok || state != "standby" || temperature != nil {
		t.Fatalf("standby disk was not preserved: %q %#v %t", state, temperature, ok)
	}
}

func TestReportSchemaCannotContainSensitiveInventory(t *testing.T) {
	report := collect(t.Context(), t.TempDir(), func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	contents, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"serial", "share", "account", "community", "password", "address"} {
		if bytes.Contains(bytes.ToLower(contents), []byte(forbidden)) {
			t.Fatalf("report schema unexpectedly contains %q: %s", forbidden, contents)
		}
	}
}

func TestFirmwareFromReleaseUsesVersionAndBuildOnly(t *testing.T) {
	contents := "NAME=TOS\nVERSION_ID=5.1.73\nBUILD_NUMBER=00078\nSERIAL=private\n"
	if value := firmwareFromRelease(contents); value != "5.1.73-00078" {
		t.Fatalf("unexpected firmware version %q", value)
	}
}

func TestGenericBoardDescriptionIsNotPresentedAsNASModel(t *testing.T) {
	if usableModel("Realtek Bleeding Edge EVB (2GB spi) Pure NAS") {
		t.Fatal("generic development-board description was accepted as the appliance model")
	}
	if !usableModel("F4-212") {
		t.Fatal("friendly appliance model was rejected")
	}
}
