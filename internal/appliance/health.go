package appliance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/healthpolicy"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/gosnmp/gosnmp"
	"golang.org/x/crypto/ssh"
)

const (
	maximumCommunityBytes  = 256
	maximumPrivateKeyBytes = 64 << 10
	maximumHealthJSONBytes = 128 << 10
	maximumSNMPValues      = 256
)

var devicePathPattern = regexp.MustCompile(`/dev/[A-Za-z0-9._/-]+`)

type healthReport = model.ManagedHealthReport

func probeManagedHealth(ctx context.Context, address string, definition model.ManagedHealthDefinition, checkedAt time.Time) model.ManagedHealthStatus {
	status := model.ManagedHealthStatus{
		Provider: definition.Provider, LastCheckedAt: timePointer(checkedAt),
		Coverage: unknownCoverage(), Status: "unavailable",
	}
	snmpReport, snmpErr := probeSNMPHealth(ctx, address, definition)
	if snmpErr == nil {
		applyHealthReport(&status, snmpReport)
	}
	sshReport, sshErr := probeSSHHealth(ctx, address, definition)
	if sshErr == nil {
		applyHealthReport(&status, sshReport)
	}
	if snmpErr != nil && sshErr != nil {
		status.ErrorClass = "health-sources-unavailable"
		return status
	}
	if sshErr != nil {
		status.ErrorClass = "ssh-health-unavailable"
	}
	if snmpErr != nil {
		status.ErrorClass = "snmp-health-unavailable"
	}
	status.Status = deriveHealthStatus(status)
	return status
}

func probeSNMPHealth(ctx context.Context, address string, definition model.ManagedHealthDefinition) (healthReport, error) {
	community, err := readBoundedSecret(definition.CommunityFile, maximumCommunityBytes)
	if err != nil {
		return healthReport{}, errors.New("SNMP credential unavailable")
	}
	client := &gosnmp.GoSNMP{
		Target: address, Port: uint16(definition.SNMPPort), Community: community,
		Version: gosnmp.Version2c, Timeout: 2 * time.Second, Retries: 1,
		MaxRepetitions: 16,
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return healthReport{}, ctx.Err()
		}
		if remaining < client.Timeout {
			client.Timeout = remaining
		}
	}
	if err := client.Connect(); err != nil {
		return healthReport{}, errors.New("SNMP connection failed")
	}
	defer client.Conn.Close()

	systemPacket, err := client.Get([]string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.3.0", // sysUpTime
	})
	if err != nil || systemPacket == nil || systemPacket.Error != gosnmp.NoError {
		return healthReport{}, errors.New("SNMP system evidence unavailable")
	}
	report := healthReport{Coverage: model.ManagedHealthCoverage{
		Disks: "partial", RAID: "partial", Temperature: "unsupported", Capacity: "unsupported", Firmware: "partial",
	}}
	for _, variable := range systemPacket.Variables {
		switch strings.TrimPrefix(variable.Name, ".") {
		case "1.3.6.1.2.1.1.1.0":
			report.System.KernelVersion = boundedText(snmpString(variable), 160)
		case "1.3.6.1.2.1.1.3.0":
			if ticks, ok := snmpUint64(variable); ok {
				seconds := int64(ticks / 100)
				report.System.UptimeSeconds = &seconds
			}
		}
	}

	storageValues, storageErr := boundedSNMPWalk(client, ".1.3.6.1.2.1.25.2.3.1")
	if storageErr == nil {
		report.Volumes = parseSNMPVolumes(storageValues)
		if len(report.Volumes) > 0 {
			report.Coverage.Capacity = "verified"
		}
	}
	deviceValues, deviceErr := boundedSNMPWalk(client, ".1.3.6.1.2.1.25.3.2.1")
	if deviceErr == nil {
		report.Disks, report.Pools = parseSNMPDevices(deviceValues)
	}
	temperatureValues, temperatureErr := boundedSNMPWalk(client, ".1.3.6.1.4.1.2021.13.16.2.1")
	if temperatureErr == nil {
		report.Temperatures = parseSNMPTemperatures(temperatureValues)
		if len(report.Temperatures) > 0 {
			report.Coverage.Temperature = "verified"
		}
	}
	return report, nil
}

func probeSSHHealth(ctx context.Context, address string, definition model.ManagedHealthDefinition) (healthReport, error) {
	privateKey, err := readBoundedFile(definition.SSHPrivateKeyFile, maximumPrivateKeyBytes)
	if err != nil {
		return healthReport{}, errors.New("SSH credential unavailable")
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return healthReport{}, errors.New("SSH credential invalid")
	}
	configuration := &ssh.ClientConfig{
		User:              definition.SSHUsername,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != definition.SSHHostKeySHA256 {
				return errors.New("SSH host key does not match configured pin")
			}
			return nil
		},
		Timeout: 3 * time.Second,
	}
	endpoint := net.JoinHostPort(address, strconv.Itoa(definition.SSHPort))
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return healthReport{}, errors.New("SSH connection failed")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(6 * time.Second))
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, endpoint, configuration)
	if err != nil {
		return healthReport{}, errors.New("SSH authentication failed")
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return healthReport{}, errors.New("SSH session unavailable")
	}
	defer session.Close()
	var output boundedBuffer
	output.remaining = maximumHealthJSONBytes
	session.Stdout = &output
	session.Stderr = io.Discard
	if err := session.Run("/usr/local/sbin/haven-nas-probe"); err != nil {
		return healthReport{}, errors.New("SSH health command failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var report healthReport
	if err := decoder.Decode(&report); err != nil {
		return healthReport{}, errors.New("SSH health response invalid")
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return healthReport{}, errors.New("SSH health response has trailing data")
	}
	return normalizeHealthReport(report), nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (writer *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > writer.remaining {
		return 0, errors.New("health response exceeds limit")
	}
	written, err := writer.buffer.Write(value)
	writer.remaining -= written
	return written, err
}

func (writer *boundedBuffer) Bytes() []byte { return writer.buffer.Bytes() }

func boundedSNMPWalk(client *gosnmp.GoSNMP, root string) ([]gosnmp.SnmpPDU, error) {
	values := make([]gosnmp.SnmpPDU, 0)
	errLimit := errors.New("SNMP result limit exceeded")
	err := client.BulkWalk(root, func(value gosnmp.SnmpPDU) error {
		if len(values) >= maximumSNMPValues {
			return errLimit
		}
		values = append(values, value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

type snmpStorageRow struct {
	typeOID           string
	name              string
	allocationUnits   uint64
	size, used        uint64
	hasUnits, hasSize bool
	hasUsed           bool
}

func parseSNMPVolumes(values []gosnmp.SnmpPDU) []model.ManagedVolumeHealth {
	rows := make(map[string]*snmpStorageRow)
	for _, value := range values {
		column, index, ok := tableCell(value.Name, ".1.3.6.1.2.1.25.2.3.1")
		if !ok {
			continue
		}
		row := rows[index]
		if row == nil {
			row = &snmpStorageRow{}
			rows[index] = row
		}
		switch column {
		case 2:
			row.typeOID = snmpString(value)
		case 3:
			row.name = boundedText(snmpString(value), 120)
		case 4:
			row.allocationUnits, row.hasUnits = snmpUint64(value)
		case 5:
			row.size, row.hasSize = snmpUint64(value)
		case 6:
			row.used, row.hasUsed = snmpUint64(value)
		}
	}
	volumes := make([]model.ManagedVolumeHealth, 0)
	for _, row := range rows {
		if row.typeOID != ".1.3.6.1.2.1.25.2.1.4" || !managedVolumePath(row.name) || !row.hasUnits || !row.hasSize || !row.hasUsed || row.size == 0 {
			continue
		}
		capacity, ok := safeMultiply(row.size, row.allocationUnits)
		if !ok {
			continue
		}
		used, ok := safeMultiply(row.used, row.allocationUnits)
		if !ok || used > capacity {
			continue
		}
		percentage := float64(used) * 100 / float64(capacity)
		volumes = append(volumes, model.ManagedVolumeHealth{
			Name: row.name, CapacityBytes: capacity, AvailableBytes: capacity - used,
			UsedPercentage: percentage, State: capacityState(percentage),
		})
	}
	sort.Slice(volumes, func(left, right int) bool { return volumes[left].Name < volumes[right].Name })
	return volumes
}

func managedVolumePath(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	return strings.HasPrefix(value, "/Volume") && !strings.Contains(strings.TrimPrefix(value, "/"), "/")
}

func parseSNMPDevices(values []gosnmp.SnmpPDU) ([]model.ManagedDiskHealth, []model.ManagedPoolHealth) {
	descriptions := make(map[string]string)
	for _, value := range values {
		column, index, ok := tableCell(value.Name, ".1.3.6.1.2.1.25.3.2.1")
		if ok && column == 3 {
			descriptions[index] = boundedText(snmpString(value), 120)
		}
	}
	var disks []model.ManagedDiskHealth
	var pools []model.ManagedPoolHealth
	for _, description := range descriptions {
		name := devicePathPattern.FindString(description)
		lower := strings.ToLower(description)
		switch {
		case strings.Contains(lower, "raid disk"):
			pools = append(pools, model.ManagedPoolHealth{Name: name, State: "unknown"})
		case strings.Contains(lower, "scsi disk") || strings.Contains(lower, "sata disk"):
			disks = append(disks, model.ManagedDiskHealth{Name: name, State: "observed", SMART: "unavailable"})
		}
	}
	sort.Slice(disks, func(left, right int) bool { return disks[left].Name < disks[right].Name })
	sort.Slice(pools, func(left, right int) bool { return pools[left].Name < pools[right].Name })
	return disks, pools
}

type snmpTemperatureRow struct {
	name     string
	value    uint64
	hasValue bool
}

func parseSNMPTemperatures(values []gosnmp.SnmpPDU) []model.ManagedTemperature {
	rows := make(map[string]*snmpTemperatureRow)
	for _, value := range values {
		column, index, ok := tableCell(value.Name, ".1.3.6.1.4.1.2021.13.16.2.1")
		if !ok {
			continue
		}
		row := rows[index]
		if row == nil {
			row = &snmpTemperatureRow{}
			rows[index] = row
		}
		switch column {
		case 2:
			row.name = boundedText(snmpString(value), 120)
		case 3:
			row.value, row.hasValue = snmpUint64(value)
		}
	}
	var temperatures []model.ManagedTemperature
	for _, row := range rows {
		if row.name == "" || !row.hasValue || row.value > 200000 {
			continue
		}
		celsius := float64(row.value) / 1000
		temperatures = append(temperatures, model.ManagedTemperature{Name: row.name, Celsius: celsius, Kind: "system", State: temperatureState("system", celsius)})
	}
	sort.Slice(temperatures, func(left, right int) bool { return temperatures[left].Name < temperatures[right].Name })
	return temperatures
}

func tableCell(name, root string) (int, string, bool) {
	name = "." + strings.TrimPrefix(name, ".")
	root = "." + strings.TrimPrefix(root, ".")
	remainder := strings.TrimPrefix(name, root+".")
	parts := strings.SplitN(remainder, ".", 2)
	if remainder == name || len(parts) != 2 || parts[1] == "" {
		return 0, "", false
	}
	column, err := strconv.Atoi(parts[0])
	return column, parts[1], err == nil
}

func snmpString(value gosnmp.SnmpPDU) string {
	switch typed := value.Value.(type) {
	case []byte:
		return strings.TrimSpace(string(typed))
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func snmpUint64(value gosnmp.SnmpPDU) (uint64, bool) {
	integer := gosnmp.ToBigInt(value.Value)
	if integer == nil || integer.Sign() < 0 || !integer.IsUint64() {
		return 0, false
	}
	return integer.Uint64(), true
}

func readBoundedSecret(file string, maximum int64) (string, error) {
	value, err := readBoundedFile(file, maximum)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(value))
	if len(secret) < 24 || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("secret is empty or malformed")
	}
	return secret, nil
}

func readBoundedFile(file string, maximum int64) ([]byte, error) {
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	information, err := handle.Stat()
	if err != nil || !information.Mode().IsRegular() || information.Size() <= 0 || information.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(handle, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, errors.New("file exceeds bounded size")
	}
	return contents, nil
}

func applyHealthReport(status *model.ManagedHealthStatus, report healthReport) {
	report = normalizeHealthReport(report)
	if report.System.Model != "" {
		status.System.Model = report.System.Model
	}
	if report.System.FirmwareVersion != "" {
		status.System.FirmwareVersion = report.System.FirmwareVersion
	}
	if report.System.KernelVersion != "" {
		status.System.KernelVersion = report.System.KernelVersion
	}
	if report.System.UptimeSeconds != nil {
		status.System.UptimeSeconds = report.System.UptimeSeconds
	}
	mergeCoverage(&status.Coverage, report.Coverage)
	if len(report.Disks) > 0 {
		status.Disks = report.Disks
	}
	if len(report.Pools) > 0 {
		status.Pools = report.Pools
	}
	if len(report.Volumes) > 0 {
		status.Volumes = report.Volumes
	}
	if len(report.Temperatures) > 0 {
		status.Temperatures = report.Temperatures
	}
}

func normalizeHealthReport(report healthReport) healthReport {
	report.System.Model = boundedText(report.System.Model, 80)
	report.System.FirmwareVersion = boundedText(report.System.FirmwareVersion, 80)
	report.System.KernelVersion = boundedText(report.System.KernelVersion, 160)
	if len(report.Disks) > 16 {
		report.Disks = report.Disks[:16]
	}
	if len(report.Pools) > 16 {
		report.Pools = report.Pools[:16]
	}
	if len(report.Volumes) > 32 {
		report.Volumes = report.Volumes[:32]
	}
	if len(report.Temperatures) > 32 {
		report.Temperatures = report.Temperatures[:32]
	}
	for index := range report.Disks {
		report.Disks[index].Name = boundedText(report.Disks[index].Name, 80)
		report.Disks[index].Model = boundedText(report.Disks[index].Model, 120)
		report.Disks[index].State = normalizedState(report.Disks[index].State)
		report.Disks[index].SMART = normalizedState(report.Disks[index].SMART)
		if report.Disks[index].SMART == "failed" {
			report.Disks[index].State = "failed"
		} else if report.Disks[index].SMART == "healthy" && report.Disks[index].State == "observed" {
			report.Disks[index].State = "healthy"
		}
		if temperature := report.Disks[index].TemperatureC; temperature != nil && (*temperature < -20 || *temperature > 150) {
			report.Disks[index].TemperatureC = nil
			report.Coverage.Temperature = "partial"
		}
	}
	for index := range report.Pools {
		report.Pools[index].Name = boundedText(report.Pools[index].Name, 80)
		report.Pools[index].RAIDLevel = boundedText(report.Pools[index].RAIDLevel, 40)
		report.Pools[index].State = normalizedState(report.Pools[index].State)
		if report.Pools[index].MemberCount < 0 || report.Pools[index].ActiveCount < 0 || report.Pools[index].ActiveCount > report.Pools[index].MemberCount {
			report.Pools[index].MemberCount = 0
			report.Pools[index].ActiveCount = 0
			report.Pools[index].State = "unavailable"
			report.Coverage.RAID = "partial"
		} else if report.Pools[index].MemberCount > 0 && report.Pools[index].ActiveCount < report.Pools[index].MemberCount && report.Pools[index].State != "failed" && report.Pools[index].State != "rebuilding" {
			report.Pools[index].State = "degraded"
		}
	}
	for index := range report.Volumes {
		report.Volumes[index].Name = boundedText(report.Volumes[index].Name, 120)
		if report.Volumes[index].CapacityBytes == 0 || report.Volumes[index].AvailableBytes > report.Volumes[index].CapacityBytes {
			report.Volumes[index].UsedPercentage = 0
			report.Volumes[index].State = "unavailable"
			report.Coverage.Capacity = "partial"
		} else {
			report.Volumes[index].UsedPercentage = float64(report.Volumes[index].CapacityBytes-report.Volumes[index].AvailableBytes) * 100 / float64(report.Volumes[index].CapacityBytes)
			report.Volumes[index].State = capacityState(report.Volumes[index].UsedPercentage)
		}
	}
	validTemperatures := report.Temperatures[:0]
	for index := range report.Temperatures {
		temperature := report.Temperatures[index]
		temperature.Name = boundedText(temperature.Name, 120)
		temperature.Kind = boundedText(temperature.Kind, 32)
		if temperature.Name == "" || temperature.Celsius < -20 || temperature.Celsius > 150 {
			report.Coverage.Temperature = "partial"
			continue
		}
		temperature.State = temperatureState(temperature.Kind, temperature.Celsius)
		validTemperatures = append(validTemperatures, temperature)
	}
	report.Temperatures = validTemperatures
	report.Coverage.Disks = normalizedCoverage(report.Coverage.Disks)
	report.Coverage.RAID = normalizedCoverage(report.Coverage.RAID)
	report.Coverage.Temperature = normalizedCoverage(report.Coverage.Temperature)
	report.Coverage.Capacity = normalizedCoverage(report.Coverage.Capacity)
	report.Coverage.Firmware = normalizedCoverage(report.Coverage.Firmware)
	return report
}

func mergeCoverage(target *model.ManagedHealthCoverage, source model.ManagedHealthCoverage) {
	if coverageRank(source.Disks) > coverageRank(target.Disks) {
		target.Disks = source.Disks
	}
	if coverageRank(source.RAID) > coverageRank(target.RAID) {
		target.RAID = source.RAID
	}
	if coverageRank(source.Temperature) > coverageRank(target.Temperature) {
		target.Temperature = source.Temperature
	}
	if coverageRank(source.Capacity) > coverageRank(target.Capacity) {
		target.Capacity = source.Capacity
	}
	if coverageRank(source.Firmware) > coverageRank(target.Firmware) {
		target.Firmware = source.Firmware
	}
}

func coverageRank(value string) int {
	switch normalizedCoverage(value) {
	case "verified":
		return 4
	case "partial":
		return 3
	case "unsupported":
		return 2
	default:
		return 1
	}
}

func normalizedCoverage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified", "partial", "unsupported", "unavailable":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unavailable"
	}
}

func normalizedState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "healthy", "observed", "standby", "warning", "critical", "degraded", "failed", "rebuilding", "unavailable":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func unknownCoverage() model.ManagedHealthCoverage {
	return model.ManagedHealthCoverage{Disks: "unavailable", RAID: "unavailable", Temperature: "unavailable", Capacity: "unavailable", Firmware: "unavailable"}
}

func deriveHealthStatus(status model.ManagedHealthStatus) string {
	for _, disk := range status.Disks {
		if healthStateAttention(disk.State) || healthStateAttention(disk.SMART) {
			return "attention"
		}
	}
	for _, pool := range status.Pools {
		if healthStateAttention(pool.State) {
			return "attention"
		}
	}
	for _, volume := range status.Volumes {
		if healthStateAttention(volume.State) {
			return "attention"
		}
	}
	for _, temperature := range status.Temperatures {
		if healthStateAttention(temperature.State) {
			return "attention"
		}
	}
	coverage := status.Coverage
	if coverage.Disks != "verified" || coverage.RAID != "verified" || coverage.Temperature != "verified" || coverage.Capacity != "verified" || coverage.Firmware != "verified" {
		return "partial"
	}
	return "healthy"
}

func healthStateAttention(value string) bool {
	switch value {
	case "warning", "critical", "degraded", "failed", "rebuilding":
		return true
	default:
		return false
	}
}

func capacityState(percentage float64) string {
	return healthpolicy.CapacityState(percentage)
}

func temperatureState(kind string, celsius float64) string {
	return healthpolicy.TemperatureState(kind, celsius)
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value))
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func safeMultiply(left, right uint64) (uint64, bool) {
	if left == 0 || right == 0 {
		return 0, true
	}
	maximum := ^uint64(0)
	if left > maximum/right {
		return 0, false
	}
	return left * right, true
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}
