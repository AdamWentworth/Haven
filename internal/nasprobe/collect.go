// Package nasprobe gathers a deliberately small, read-only NAS health report.
// It does not enumerate accounts, shares, filenames, network settings, or disk
// serial numbers. All command paths and arguments are fixed by HAVEN.
package nasprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/healthpolicy"
	"github.com/AdamWentworth/haven/internal/model"
)

const maximumEvidenceBytes = 256 << 10

var (
	physicalDiskName = regexp.MustCompile(`^(sd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+)$`)
	mdHeaderPattern  = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*:\s*(active|inactive)\s+([A-Za-z0-9_.-]+)(?:\s|$)`)
	mdCountPattern   = regexp.MustCompile(`\[([0-9]+)\/([0-9]+)\]`)
	mdMembersPattern = regexp.MustCompile(`\[([U_]+)\]`)
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

// Collect gathers the current report. Missing optional platform capabilities
// become explicit coverage states rather than fabricated healthy results.
func Collect(ctx context.Context) model.ManagedHealthReport {
	return collect(ctx, "/", runCommand)
}

func collect(ctx context.Context, root string, run commandRunner) model.ManagedHealthReport {
	report := model.ManagedHealthReport{Coverage: model.ManagedHealthCoverage{
		Disks: "unavailable", RAID: "unavailable", Temperature: "unsupported", Capacity: "unavailable", Firmware: "unavailable",
	}}
	report.System = collectSystem(root)
	if report.System.FirmwareVersion != "" {
		report.Coverage.Firmware = "verified"
	} else if report.System.KernelVersion != "" {
		report.Coverage.Firmware = "partial"
	}

	report.Pools, report.Coverage.RAID = collectPools(root)
	report.Volumes, report.Coverage.Capacity = collectVolumes(ctx, run)
	report.Disks, report.Temperatures, report.Coverage.Disks = collectDisks(ctx, root, run)
	systemTemperatures := collectThermalZones(root)
	report.Temperatures = append(report.Temperatures, systemTemperatures...)
	if len(report.Temperatures) > 0 {
		report.Coverage.Temperature = "verified"
	}
	sort.Slice(report.Temperatures, func(left, right int) bool { return report.Temperatures[left].Name < report.Temperatures[right].Name })
	return report
}

func collectSystem(root string) model.ManagedSystemHealth {
	system := model.ManagedSystemHealth{}
	system.KernelVersion = readTrimmed(root, "proc/sys/kernel/osrelease", 160)
	if value := readTrimmed(root, "proc/uptime", 128); value != "" {
		if seconds, err := strconv.ParseFloat(strings.Fields(value)[0], 64); err == nil && seconds >= 0 {
			uptime := int64(seconds)
			system.UptimeSeconds = &uptime
		}
	}
	for _, name := range []string{"etc/model", "etc.defaults/model", "proc/device-tree/model", "sys/firmware/devicetree/base/model"} {
		if value := readTrimmed(root, name, 80); usableModel(value) {
			system.Model = value
			break
		}
	}
	for _, name := range []string{"etc/terramaster-release", "etc/tos-release", "etc/TOS_VERSION", "etc/tos-version", "etc.defaults/VERSION", "etc/version", "etc/VERSION", "etc/os-release"} {
		if value := firmwareFromRelease(readTrimmed(root, name, 4096)); value != "" {
			system.FirmwareVersion = value
			break
		}
	}
	return system
}

func usableModel(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower != "" && !strings.Contains(lower, "bleeding edge") && !strings.Contains(lower, "evaluation board") && !strings.Contains(lower, " evb")
}

func firmwareFromRelease(contents string) string {
	if contents == "" {
		return ""
	}
	values := map[string]string{}
	for _, line := range strings.Split(contents, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			values[strings.TrimSpace(strings.ToUpper(key))] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	version := firstValue(values, "TOS_VERSION", "VERSION_ID", "VERSION", "PRODUCT_VERSION")
	build := firstValue(values, "BUILD_NUMBER", "BUILD_ID", "BUILD")
	if version != "" {
		if build != "" && build != version && !strings.Contains(version, build) {
			return bounded(version+"-"+build, 80)
		}
		return bounded(version, 80)
	}
	if pretty := firstValue(values, "PRETTY_NAME"); strings.Contains(strings.ToUpper(pretty), "TOS") {
		return bounded(pretty, 80)
	}
	line := strings.TrimSpace(strings.SplitN(contents, "\n", 2)[0])
	if len(strings.Fields(line)) <= 4 && (strings.Contains(line, ".") || strings.Contains(strings.ToUpper(line), "TOS")) {
		return bounded(line, 80)
	}
	return ""
}

func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func collectPools(root string) ([]model.ManagedPoolHealth, string) {
	contents := readTrimmed(root, "proc/mdstat", maximumEvidenceBytes)
	if contents == "" {
		return nil, "unavailable"
	}
	return parseMDStat(contents), "verified"
}

func parseMDStat(contents string) []model.ManagedPoolHealth {
	lines := strings.Split(contents, "\n")
	var pools []model.ManagedPoolHealth
	for index := 0; index < len(lines); index++ {
		match := mdHeaderPattern.FindStringSubmatch(strings.TrimSpace(lines[index]))
		if len(match) == 0 {
			continue
		}
		pool := model.ManagedPoolHealth{Name: "/dev/" + match[1], RAIDLevel: strings.ToLower(match[3]), State: "healthy"}
		block := strings.TrimSpace(lines[index])
		for next := index + 1; next < len(lines); next++ {
			trimmed := strings.TrimSpace(lines[next])
			if mdHeaderPattern.MatchString(trimmed) || trimmed == "" {
				break
			}
			block += " " + trimmed
		}
		if count := mdCountPattern.FindStringSubmatch(block); len(count) == 3 {
			pool.MemberCount, _ = strconv.Atoi(count[1])
			pool.ActiveCount, _ = strconv.Atoi(count[2])
		}
		if members := mdMembersPattern.FindStringSubmatch(block); len(members) == 2 {
			pool.MemberCount = len(members[1])
			pool.ActiveCount = strings.Count(members[1], "U")
		}
		lower := strings.ToLower(block)
		switch {
		case match[2] == "inactive":
			pool.State = "failed"
		case strings.Contains(lower, "recovery"), strings.Contains(lower, "resync"), strings.Contains(lower, "reshape"), strings.Contains(lower, "check ="):
			pool.State = "rebuilding"
		case pool.MemberCount > 0 && pool.ActiveCount < pool.MemberCount:
			pool.State = "degraded"
		}
		pools = append(pools, pool)
	}
	sort.Slice(pools, func(left, right int) bool { return pools[left].Name < pools[right].Name })
	return pools
}

func collectVolumes(ctx context.Context, run commandRunner) ([]model.ManagedVolumeHealth, string) {
	path := firstExecutable("/bin/df", "/usr/bin/df")
	if path == "" {
		return nil, "unavailable"
	}
	output, err := run(ctx, path, "-Pk")
	if err != nil {
		return nil, "unavailable"
	}
	volumes := parseDF(output)
	if len(volumes) == 0 {
		return nil, "unsupported"
	}
	return volumes, "verified"
}

func parseDF(output []byte) []model.ManagedVolumeHealth {
	var volumes []model.ManagedVolumeHealth
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), maximumEvidenceBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		mount := strings.ReplaceAll(fields[len(fields)-1], `\040`, " ")
		if !topLevelVolume(mount) {
			continue
		}
		blocks, blocksErr := strconv.ParseUint(fields[len(fields)-5], 10, 64)
		available, availableErr := strconv.ParseUint(fields[len(fields)-3], 10, 64)
		capacity, capacityOK := multiply(blocks, 1024)
		availableBytes, availableOK := multiply(available, 1024)
		if blocksErr != nil || availableErr != nil || !capacityOK || !availableOK || capacity == 0 || availableBytes > capacity {
			continue
		}
		usedPercentage := float64(capacity-availableBytes) * 100 / float64(capacity)
		volumes = append(volumes, model.ManagedVolumeHealth{
			Name: mount, CapacityBytes: capacity, AvailableBytes: availableBytes,
			UsedPercentage: usedPercentage, State: healthpolicy.CapacityState(usedPercentage),
		})
	}
	sort.Slice(volumes, func(left, right int) bool { return volumes[left].Name < volumes[right].Name })
	return volumes
}

func topLevelVolume(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	if !strings.HasPrefix(value, "/Volume") {
		return false
	}
	remainder := strings.TrimPrefix(value, "/")
	return !strings.Contains(remainder, "/")
}

func collectDisks(ctx context.Context, root string, run commandRunner) ([]model.ManagedDiskHealth, []model.ManagedTemperature, string) {
	entries, err := os.ReadDir(filepath.Join(root, "sys/block"))
	if err != nil {
		return nil, nil, "unavailable"
	}
	smartctl := firstExecutable("/usr/sbin/smartctl", "/usr/bin/smartctl", "/sbin/smartctl")
	coverage := "verified"
	var disks []model.ManagedDiskHealth
	var temperatures []model.ManagedTemperature
	for _, entry := range entries {
		name := entry.Name()
		if !physicalDiskName.MatchString(name) {
			continue
		}
		disk := model.ManagedDiskHealth{Name: "/dev/" + name, Model: readTrimmed(root, filepath.Join("sys/block", name, "device/model"), 120), State: "observed", SMART: "unavailable"}
		if sectors, parseErr := strconv.ParseUint(readTrimmed(root, filepath.Join("sys/block", name, "size"), 64), 10, 64); parseErr == nil {
			if bytes, ok := multiply(sectors, 512); ok {
				disk.CapacityBytes = &bytes
			}
		}
		if smartctl == "" {
			coverage = "partial"
		} else {
			output, commandErr := run(ctx, smartctl, "-j", "-H", "-A", "-n", "standby,3", disk.Name)
			smart, temperature, parsed := parseSMART(output)
			if parsed {
				disk.SMART = smart
				switch smart {
				case "healthy":
					disk.State = "healthy"
				case "failed":
					disk.State = "failed"
				case "standby":
					disk.State = "standby"
				default:
					coverage = "partial"
				}
				if temperature != nil {
					disk.TemperatureC = temperature
					temperatures = append(temperatures, model.ManagedTemperature{Name: disk.Name, Celsius: *temperature, Kind: "disk", State: healthpolicy.TemperatureState("disk", *temperature), DriveStandby: smart == "standby"})
				}
			} else {
				_ = commandErr
				coverage = "partial"
			}
		}
		disks = append(disks, disk)
	}
	if len(disks) == 0 {
		return nil, nil, "unsupported"
	}
	sort.Slice(disks, func(left, right int) bool { return disks[left].Name < disks[right].Name })
	return disks, temperatures, coverage
}

type smartDocument struct {
	PowerMode   string `json:"power_mode"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current json.Number `json:"current"`
	} `json:"temperature"`
	ATAAttributes *struct {
		Table []struct {
			Name string `json:"name"`
			Raw  struct {
				Value json.Number `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

func parseSMART(output []byte) (string, *float64, bool) {
	if len(output) == 0 || len(output) > maximumEvidenceBytes {
		return "unavailable", nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var document smartDocument
	if err := decoder.Decode(&document); err != nil {
		return "unavailable", nil, false
	}
	if strings.Contains(strings.ToUpper(document.PowerMode), "STANDBY") || strings.Contains(strings.ToUpper(document.PowerMode), "SLEEP") {
		return "standby", nil, true
	}
	state := "unavailable"
	if document.SmartStatus != nil {
		state = "failed"
		if document.SmartStatus.Passed {
			state = "healthy"
		}
	}
	temperature := numberFloat(document.Temperature)
	if temperature == nil && document.ATAAttributes != nil {
		for _, attribute := range document.ATAAttributes.Table {
			name := strings.ToLower(attribute.Name)
			if strings.Contains(name, "temperature") {
				if value, err := attribute.Raw.Value.Float64(); err == nil && plausibleTemperature(value) {
					temperature = &value
					break
				}
			}
		}
	}
	return state, temperature, true
}

func numberFloat(value *struct {
	Current json.Number `json:"current"`
}) *float64 {
	if value == nil {
		return nil
	}
	result, err := value.Current.Float64()
	if err != nil || !plausibleTemperature(result) {
		return nil
	}
	return &result
}

func plausibleTemperature(value float64) bool { return value >= -20 && value <= 150 }

func collectThermalZones(root string) []model.ManagedTemperature {
	entries, err := filepath.Glob(filepath.Join(root, "sys/class/thermal/thermal_zone*"))
	if err != nil {
		return nil
	}
	var temperatures []model.ManagedTemperature
	for _, entry := range entries {
		raw, err := strconv.ParseFloat(readTrimmed("/", filepath.Join(entry, "temp"), 64), 64)
		if err != nil {
			continue
		}
		if raw > 1000 {
			raw /= 1000
		}
		if !plausibleTemperature(raw) {
			continue
		}
		name := readTrimmed("/", filepath.Join(entry, "type"), 120)
		if name == "" {
			name = filepath.Base(entry)
		}
		temperatures = append(temperatures, model.ManagedTemperature{Name: name, Celsius: raw, Kind: "system", State: healthpolicy.TemperatureState("system", raw)})
	}
	return temperatures
}

func runCommand(ctx context.Context, path string, arguments ...string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, path, arguments...)
	var output limitedBuffer
	output.remaining = maximumEvidenceBytes
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	return output.Bytes(), err
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	if len(value) > buffer.remaining {
		return 0, errors.New("evidence exceeds limit")
	}
	written, err := buffer.Buffer.Write(value)
	buffer.remaining -= written
	return written, err
}

func firstExecutable(paths ...string) string {
	for _, path := range paths {
		if information, err := os.Stat(path); err == nil && information.Mode().IsRegular() && information.Mode().Perm()&0o111 != 0 {
			return path
		}
	}
	return ""
}

func readTrimmed(root, name string, maximum int) string {
	path := name
	if !filepath.IsAbs(name) {
		path = filepath.Join(root, filepath.FromSlash(name))
	}
	handle, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer handle.Close()
	contents, err := io.ReadAll(io.LimitReader(handle, int64(maximum)+1))
	if err != nil || len(contents) > maximum {
		return ""
	}
	return bounded(strings.TrimSpace(strings.TrimRight(string(contents), "\x00")), maximum)
}

func bounded(value string, maximum int) string {
	value = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 0x20 && character != '\n' && character != '\t' {
			return -1
		}
		return character
	}, value))
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func multiply(left, right uint64) (uint64, bool) {
	if right != 0 && left > ^uint64(0)/right {
		return 0, false
	}
	return left * right, true
}

// ValidateReport applies structural constraints before output. The hub repeats
// its own validation because the helper response crosses a trust boundary.
func ValidateReport(report model.ManagedHealthReport) error {
	if len(report.Disks) > 16 || len(report.Pools) > 16 || len(report.Volumes) > 32 || len(report.Temperatures) > 32 {
		return fmt.Errorf("health report exceeds structural limits")
	}
	return nil
}
