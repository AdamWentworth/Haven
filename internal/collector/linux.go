package collector

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

type LinuxCollector struct {
	runner   CommandRunner
	readFile func(string) ([]byte, error)
	stat     func(string) (os.FileInfo, error)
	hostname func() (string, error)
	glob     func(string) ([]string, error)
}

func NewLinuxCollector(runner CommandRunner) *LinuxCollector {
	return &LinuxCollector{
		runner:   runner,
		readFile: os.ReadFile,
		stat:     os.Stat,
		hostname: os.Hostname,
		glob:     filepath.Glob,
	}
}

func (collector *LinuxCollector) Collect(ctx context.Context) model.SecuritySnapshot {
	notices := []model.CollectorNotice{}
	snapshot := model.SecuritySnapshot{
		CollectedAt:      time.Now().UTC(),
		Device:           collector.device(),
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          notices,
	}

	updates := collector.updates(ctx, &notices)
	firewall := collector.firewall(&notices)
	ssh := collector.ssh(ctx, &notices)
	services := collector.services(ctx, &notices)
	automaticUpdates := collector.automaticUpdates(ctx, &notices)
	appArmor := collector.appArmor(ctx, &notices)
	timeSync := collector.timeSync(ctx, &notices)
	storage := collector.storage(ctx, &notices)
	snapshot.LinuxBaseline = &model.LinuxBaseline{
		Updates:          updates,
		Firewall:         firewall,
		SSH:              ssh,
		Services:         services,
		AutomaticUpdates: automaticUpdates,
		AppArmor:         appArmor,
		TimeSync:         timeSync,
		Storage:          storage,
	}
	if firewall != nil {
		snapshot.FirewallProfiles = []model.FirewallProfileStatus{{
			Name:                  strings.ToUpper(firewall.Provider),
			Enabled:               firewall.Active,
			DefaultInboundAction:  firewall.DefaultInboundAction,
			DefaultOutboundAction: firewall.DefaultOutboundAction,
		}}
	}
	snapshot.Connections = collector.connections(ctx, &notices)
	snapshot.Notices = notices
	return snapshot
}

func (collector *LinuxCollector) device() model.DeviceSummary {
	hostName, err := collector.hostname()
	if err != nil || strings.TrimSpace(hostName) == "" {
		hostName = "Unknown Linux device"
	}
	operatingSystem := "Linux"
	if contents, err := collector.readFile("/etc/os-release"); err == nil {
		values := parseKeyValueFile(contents)
		if value := strings.Trim(values["PRETTY_NAME"], `"`); value != "" {
			operatingSystem = value
		}
	}
	var uptimeSeconds *int64
	if contents, err := collector.readFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(contents))
		if len(fields) > 0 {
			if seconds, parseErr := strconv.ParseFloat(fields[0], 64); parseErr == nil && seconds >= 0 {
				value := int64(seconds)
				uptimeSeconds = &value
			}
		}
	}
	return model.DeviceSummary{HostName: hostName, OperatingSystem: operatingSystem, Architecture: runtime.GOARCH, UptimeSeconds: uptimeSeconds}
}

func (collector *LinuxCollector) updates(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxUpdateStatus {
	status := &model.LinuxUpdateStatus{}
	pendingReboot := false
	if _, err := collector.stat("/var/run/reboot-required"); err == nil {
		pendingReboot = true
	} else if !errors.Is(err, os.ErrNotExist) {
		addNotice(notices, "Ubuntu servicing", "information", "Pending-restart state could not be verified.")
	}
	status.PendingReboot = &pendingReboot

	output, err := collector.runner.Run(ctx, "/usr/lib/update-notifier/apt-check")
	if err != nil {
		addNotice(notices, "Ubuntu servicing", "information", "Available package updates could not be counted.")
		return status
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ";")
	if len(parts) != 2 {
		addNotice(notices, "Ubuntu servicing", "information", "The update checker returned an unfamiliar response.")
		return status
	}
	pending, pendingErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	security, securityErr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if pendingErr != nil || securityErr != nil || pending < 0 || security < 0 {
		addNotice(notices, "Ubuntu servicing", "information", "The update checker returned invalid package counts.")
		return status
	}
	status.PendingPackageCount = intPointer(pending)
	status.PendingSecurityPackageCount = intPointer(security)
	return status
}

func (collector *LinuxCollector) firewall(notices *[]model.CollectorNotice) *model.LinuxFirewallStatus {
	status := &model.LinuxFirewallStatus{Provider: "ufw"}
	contents, err := collector.readFile("/etc/ufw/ufw.conf")
	if err != nil {
		addNotice(notices, "Linux firewall", "information", "UFW state could not be read without expanding the agent's privileges.")
		return status
	}
	values := parseKeyValueFile(contents)
	if enabled, ok := parseYesNo(values["ENABLED"]); ok {
		status.Active = boolPointer(enabled)
	}
	if defaults, err := collector.readFile("/etc/default/ufw"); err == nil {
		policies := parseKeyValueFile(defaults)
		status.DefaultInboundAction = normalizeFirewallPolicy(policies["DEFAULT_INPUT_POLICY"])
		status.DefaultOutboundAction = normalizeFirewallPolicy(policies["DEFAULT_OUTPUT_POLICY"])
	}
	return status
}

func (collector *LinuxCollector) ssh(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxSSHStatus {
	status := &model.LinuxSSHStatus{}
	if value, ok := collector.systemdState(ctx, "ssh.service", "active", "inactive", "failed"); ok {
		status.ServerRunning = boolPointer(value == "active")
	} else {
		addNotice(notices, "OpenSSH", "information", "The SSH service state could not be verified.")
	}

	settings, effective := collector.effectiveSSHSettings(ctx)
	status.PasswordAuthentication = settings["passwordauthentication"]
	status.PermitRootLogin = settings["permitrootlogin"]
	status.PublicKeyAuthentication = settings["pubkeyauthentication"]
	if !effective && status.ServerRunning != nil && *status.ServerRunning {
		addNotice(notices, "OpenSSH", "information", "HAVEN read explicit SSH configuration but could not calculate every effective default without privileged host-key access.")
	}
	return status
}

func (collector *LinuxCollector) effectiveSSHSettings(ctx context.Context) (map[string]string, bool) {
	output, err := collector.runner.Run(ctx, "/usr/sbin/sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1")
	if err == nil {
		return parseSSHOutput(output), true
	}
	settings := map[string]string{}
	collector.readSSHConfig("/etc/ssh/sshd_config", settings, map[string]bool{})
	return settings, false
}

func (collector *LinuxCollector) readSSHConfig(path string, settings map[string]string, visited map[string]bool) {
	clean := filepath.Clean(path)
	if visited[clean] {
		return
	}
	visited[clean] = true
	contents, err := collector.readFile(clean)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "match" {
			break
		}
		if key == "include" {
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(clean), pattern)
				}
				matches, _ := collector.glob(pattern)
				for _, match := range matches {
					collector.readSSHConfig(match, settings, visited)
				}
			}
			continue
		}
		if key != "passwordauthentication" && key != "permitrootlogin" && key != "pubkeyauthentication" {
			continue
		}
		if _, exists := settings[key]; !exists {
			settings[key] = strings.ToLower(fields[1])
		}
	}
}

func (collector *LinuxCollector) services(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxServiceStatus {
	output, err := collector.runner.Run(ctx, "systemctl", "--failed", "--no-legend", "--plain")
	if err != nil && len(strings.TrimSpace(string(output))) == 0 {
		addNotice(notices, "systemd", "information", "Failed service count could not be verified.")
		return &model.LinuxServiceStatus{}
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return &model.LinuxServiceStatus{FailedUnitCount: intPointer(count)}
}

func (collector *LinuxCollector) automaticUpdates(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxAutomaticUpdateStatus {
	status := &model.LinuxAutomaticUpdateStatus{}
	if value, ok := collector.systemdState(ctx, "unattended-upgrades.service", "enabled", "disabled", "masked", "static"); ok {
		enabled := value == "enabled" || value == "static"
		status.Enabled = &enabled
	}
	if value, ok := collector.systemdState(ctx, "unattended-upgrades.service", "active", "inactive", "failed"); ok {
		active := value == "active"
		status.Active = &active
	}
	if status.Enabled == nil && status.Active == nil {
		addNotice(notices, "Automatic updates", "information", "Unattended-upgrades state could not be verified.")
	}
	return status
}

func (collector *LinuxCollector) appArmor(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxAppArmorStatus {
	_, err := collector.runner.Run(ctx, "aa-status", "--enabled")
	if err == nil {
		return &model.LinuxAppArmorStatus{Enabled: boolPointer(true)}
	}
	if strings.Contains(strings.ToLower(err.Error()), "executable file not found") {
		addNotice(notices, "AppArmor", "information", "AppArmor tooling is not installed, so enforcement could not be verified.")
		return &model.LinuxAppArmorStatus{}
	}
	return &model.LinuxAppArmorStatus{Enabled: boolPointer(false)}
}

func (collector *LinuxCollector) timeSync(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxTimeSyncStatus {
	output, err := collector.runner.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		addNotice(notices, "Time synchronization", "information", "Network time synchronization could not be verified.")
		return &model.LinuxTimeSyncStatus{}
	}
	value, ok := parseYesNo(strings.TrimSpace(string(output)))
	if !ok {
		return &model.LinuxTimeSyncStatus{}
	}
	return &model.LinuxTimeSyncStatus{Synchronized: &value}
}

func (collector *LinuxCollector) storage(ctx context.Context, notices *[]model.CollectorNotice) *model.LinuxStorageStatus {
	output, err := collector.runner.Run(ctx, "df", "-Pk", "/")
	if err != nil {
		addNotice(notices, "Storage", "information", "Root filesystem capacity could not be verified.")
		return &model.LinuxStorageStatus{MountPoint: "/"}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		return &model.LinuxStorageStatus{MountPoint: "/"}
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return &model.LinuxStorageStatus{MountPoint: "/"}
	}
	totalKB, totalErr := strconv.ParseInt(fields[1], 10, 64)
	availableKB, availableErr := strconv.ParseInt(fields[3], 10, 64)
	usedPercent, percentErr := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
	status := &model.LinuxStorageStatus{MountPoint: fields[5]}
	if totalErr == nil && totalKB >= 0 {
		status.CapacityBytes = int64Pointer(totalKB * 1024)
	}
	if availableErr == nil && availableKB >= 0 {
		status.AvailableBytes = int64Pointer(availableKB * 1024)
	}
	if percentErr == nil && usedPercent >= 0 && usedPercent <= 100 {
		status.UsedPercentage = floatPointer(usedPercent)
	}
	return status
}

func (collector *LinuxCollector) connections(ctx context.Context, notices *[]model.CollectorNotice) []model.NetworkConnection {
	output, err := collector.runner.Run(ctx, "ss", "-H", "-tanp")
	if err != nil {
		addNotice(notices, "TCP endpoints", "information", "Listening and established TCP endpoints could not be collected.")
		return []model.NetworkConnection{}
	}
	connections := []model.NetworkConnection{}
	for _, line := range strings.Split(string(output), "\n") {
		if connection, ok := parseSSLine(line); ok {
			connections = append(connections, connection)
			if len(connections) == 250 {
				break
			}
		}
	}
	return connections
}

func (collector *LinuxCollector) systemdState(ctx context.Context, unit string, accepted ...string) (string, bool) {
	command := "is-active"
	if accepted[0] == "enabled" {
		command = "is-enabled"
	}
	output, _ := collector.runner.Run(ctx, "systemctl", command, unit)
	value := strings.TrimSpace(string(output))
	for _, candidate := range accepted {
		if value == candidate {
			return value, true
		}
	}
	return "", false
}

func parseKeyValueFile(contents []byte) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values
}

func parseSSHOutput(output []byte) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "passwordauthentication" || key == "permitrootlogin" || key == "pubkeyauthentication" {
			values[key] = strings.ToLower(fields[1])
		}
	}
	return values
}

func parseSSLine(line string) (model.NetworkConnection, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return model.NetworkConnection{}, false
	}
	state := strings.ToLower(fields[0])
	if state != "listen" && state != "estab" && state != "established" {
		return model.NetworkConnection{}, false
	}
	localAddress, localPort, localOK := parseLinuxEndpoint(fields[3])
	remoteAddress, remotePort, remoteOK := parseLinuxEndpoint(fields[4])
	if !localOK || !remoteOK {
		return model.NetworkConnection{}, false
	}
	connection := model.NetworkConnection{
		Protocol:      "TCP",
		LocalAddress:  localAddress,
		LocalPort:     localPort,
		RemoteAddress: remoteAddress,
		RemotePort:    remotePort,
		State:         map[string]string{"listen": "Listen", "estab": "Established", "established": "Established"}[state],
	}
	processFields := strings.Join(fields[5:], " ")
	if start := strings.Index(processFields, `(("`); start >= 0 {
		nameStart := start + 3
		if nameEnd := strings.Index(processFields[nameStart:], `"`); nameEnd >= 0 {
			connection.ProcessName = processFields[nameStart : nameStart+nameEnd]
		}
	}
	if start := strings.Index(processFields, "pid="); start >= 0 {
		value := processFields[start+4:]
		if end := strings.IndexAny(value, ",)"); end >= 0 {
			value = value[:end]
		}
		connection.ProcessID, _ = strconv.Atoi(value)
	}
	return connection, true
}

func parseLinuxEndpoint(value string) (string, int, bool) {
	if strings.HasSuffix(value, ":*") {
		host := strings.Trim(strings.TrimSuffix(value, ":*"), "[]")
		return host, 0, true
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		number, parseErr := strconv.Atoi(port)
		return strings.TrimSuffix(host, "%lo"), number, parseErr == nil
	}
	separator := strings.LastIndex(value, ":")
	if separator < 0 {
		return "", 0, false
	}
	host := strings.Trim(value[:separator], "[]")
	host = strings.TrimSuffix(host, "%lo")
	port, err := strconv.Atoi(value[separator+1:])
	return host, port, err == nil
}

func parseYesNo(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "1", "enabled", "active":
		return true, true
	case "no", "false", "0", "disabled", "inactive":
		return false, true
	default:
		return false, false
	}
}

func normalizeFirewallPolicy(value string) string {
	switch strings.ToUpper(strings.Trim(value, `"' `)) {
	case "DROP", "REJECT", "DENY":
		return "Block"
	case "ACCEPT", "ALLOW":
		return "Allow"
	default:
		return value
	}
}

func addNotice(notices *[]model.CollectorNotice, source, severity, message string) {
	*notices = append(*notices, model.CollectorNotice{Source: source, Severity: severity, Message: message})
}

func boolPointer(value bool) *bool        { return &value }
func intPointer(value int) *int           { return &value }
func int64Pointer(value int64) *int64     { return &value }
func floatPointer(value float64) *float64 { return &value }
