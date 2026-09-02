package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/workload"
)

type fakeCommandRunner struct {
	outputs map[string][]byte
	errors  map[string]error
}

func (runner fakeCommandRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, arguments...), "\x00")
	return runner.outputs[key], runner.errors[key]
}

func TestLinuxCollectorBuildsPrivacyBoundedHostSnapshot(t *testing.T) {
	command := func(name string, arguments ...string) string {
		return strings.Join(append([]string{name}, arguments...), "\x00")
	}
	runner := fakeCommandRunner{outputs: map[string][]byte{
		command("/usr/lib/update-notifier/apt-check"):                                                                   []byte("13;0"),
		command("systemctl", "is-active", "ssh.service"):                                                                []byte("active\n"),
		command("/usr/sbin/sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"):                                []byte("passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\npubkeyauthentication yes\n"),
		command("systemctl", "--failed", "--no-legend", "--plain"):                                                      []byte("certbot.service loaded failed failed Certbot\n"),
		command("systemctl", "is-enabled", "unattended-upgrades.service"):                                               []byte("enabled\n"),
		command("systemctl", "is-active", "unattended-upgrades.service"):                                                []byte("active\n"),
		command("systemctl", "--user", "list-sockets", "--no-legend", "--no-pager", "--plain", "--all", "--show-types"): []byte("127.0.0.1:8081 Stream binderledger-localhost-proxy@8081.socket binderledger-localhost-proxy@8081.service\n"),
		command("aa-status", "--enabled"):                                                                               []byte{},
		command("timedatectl", "show", "-p", "NTPSynchronized", "--value"):                                              []byte("yes\n"),
		command("df", "-Pk", "/"):                                                                                       []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda3 100000 30000 70000 30% /\n"),
		command("ss", "-H", "-tanpe"):                                                                                   []byte("LISTEN 0 4096 192.0.2.77:8443 0.0.0.0:* users:((\"caddy\",pid=42,fd=3)) cgroup:/user.slice/user-1000.slice/user@1000.service/init.scope\nESTAB 0 0 192.0.2.77:22 198.51.100.10:51000 users:((\"sshd\",pid=55,fd=4)) cgroup:/system.slice/ssh.service\nLISTEN 0 4096 127.0.0.1:8081 0.0.0.0:* cgroup:/user.slice/user-1000.slice/user@1000.service/init.scope\n"),
		command("ss", "-H", "-uanpe"):                                                                                   []byte("UNCONN 0 0 0.0.0.0:51822 0.0.0.0:*\n"),
	}, errors: map[string]error{}}
	files := map[string][]byte{
		"/etc/os-release":   []byte("PRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n"),
		"/proc/uptime":      []byte("86401.50 100.00\n"),
		"/proc/42/cgroup":   []byte("0::/system.slice/caddy.service\n"),
		"/etc/ufw/ufw.conf": []byte("ENABLED=yes\n"),
		"/etc/default/ufw":  []byte("DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"),
	}
	collector := NewLinuxCollector(runner)
	collector.hostname = func() (string, error) { return "adam-ubuntu", nil }
	collector.readFile = func(path string) ([]byte, error) {
		if contents, ok := files[path]; ok {
			return contents, nil
		}
		return nil, os.ErrNotExist
	}
	collector.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	snapshot := collector.Collect(context.Background())
	if snapshot.Device.HostName != "adam-ubuntu" || snapshot.Device.OperatingSystem != "Ubuntu 24.04.4 LTS" {
		t.Fatalf("unexpected Linux identity: %#v", snapshot.Device)
	}
	if snapshot.LinuxBaseline == nil || snapshot.LinuxBaseline.Updates == nil || *snapshot.LinuxBaseline.Updates.PendingPackageCount != 13 {
		t.Fatalf("update status was not collected: %#v", snapshot.LinuxBaseline)
	}
	if snapshot.LinuxBaseline.Firewall == nil || snapshot.LinuxBaseline.Firewall.Active == nil || !*snapshot.LinuxBaseline.Firewall.Active {
		t.Fatalf("firewall status was not collected: %#v", snapshot.LinuxBaseline.Firewall)
	}
	if snapshot.LinuxBaseline.SSH.PasswordAuthentication != "no" || snapshot.LinuxBaseline.SSH.KeyboardInteractiveAuthentication != "no" || snapshot.LinuxBaseline.SSH.PermitRootLogin != "prohibit-password" {
		t.Fatalf("SSH posture was not collected: %#v", snapshot.LinuxBaseline.SSH)
	}
	if len(snapshot.Connections) != 4 || snapshot.Connections[0].ProcessName != "caddy" || snapshot.Connections[0].SystemdUnit != "caddy.service" || snapshot.Connections[1].State != "Established" || snapshot.Connections[2].SystemdUnit != "binderledger-localhost-proxy@8081.service" || snapshot.Connections[3].Protocol != "UDP" || snapshot.Connections[3].State != "Bound" {
		t.Fatalf("network endpoints were not mapped: %#v", snapshot.Connections)
	}
	if snapshot.LinuxBaseline.Services == nil || len(snapshot.LinuxBaseline.Services.FailedUnits) != 1 || snapshot.LinuxBaseline.Services.FailedUnits[0] != "certbot.service" {
		t.Fatalf("failed systemd units were not mapped: %#v", snapshot.LinuxBaseline.Services)
	}
	if len(snapshot.Notices) != 0 {
		t.Fatalf("healthy fake collection returned notices: %#v", snapshot.Notices)
	}
}

func TestLinuxCollectorTrustsCompleteExplicitGlobalSSHSettings(t *testing.T) {
	command := func(name string, arguments ...string) string {
		return strings.Join(append([]string{name}, arguments...), "\x00")
	}
	runner := fakeCommandRunner{
		outputs: map[string][]byte{command("systemctl", "is-active", "ssh.service"): []byte("active\n")},
		errors:  map[string]error{command("/usr/sbin/sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"): errors.New("host keys unavailable")},
	}
	files := map[string][]byte{
		"/etc/ssh/sshd_config":                           []byte("Include /etc/ssh/sshd_config.d/*.conf\n"),
		"/etc/ssh/sshd_config.d/00-haven-hardening.conf": []byte("PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\n"),
	}
	collector := NewLinuxCollector(runner)
	collector.readFile = func(path string) ([]byte, error) {
		if contents, ok := files[filepath.ToSlash(path)]; ok {
			return contents, nil
		}
		return nil, os.ErrNotExist
	}
	collector.glob = func(string) ([]string, error) {
		return []string{"/etc/ssh/sshd_config.d/00-haven-hardening.conf"}, nil
	}

	notices := []model.CollectorNotice{}
	status := collector.ssh(context.Background(), &notices)
	if status.PasswordAuthentication != "no" || status.KeyboardInteractiveAuthentication != "no" || status.PermitRootLogin != "no" || status.PublicKeyAuthentication != "yes" {
		t.Fatalf("explicit SSH hardening was not collected: %#v", status)
	}
	if len(notices) != 0 {
		t.Fatalf("complete explicit SSH settings should not be described as unverified: %#v", notices)
	}
}

func TestSanitizeSystemdUnitName(t *testing.T) {
	for _, value := range []string{"certbot.service", "docker-worker-1.service", `dev-disk\\x2dby.mount`} {
		if got := sanitizeSystemdUnitName(value); got != value {
			t.Fatalf("expected %q to remain unchanged, got %q", value, got)
		}
	}
	if got := sanitizeSystemdUnitName("bad unit.service"); got != "" {
		t.Fatalf("unsafe unit name was retained: %q", got)
	}
}

func TestParseSystemdUnitFromSocketCgroup(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"ino:11956 cgroup:/system.slice/glances.service <->", "glances.service"},
		{"cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/binderledger-localhost-proxy@8081.service", "binderledger-localhost-proxy@8081.service"},
		{"cgroup:/user.slice/user-1000.slice/user@1000.service/init.scope", ""},
		{"cgroup:/system.slice/docker-example.scope", ""},
	} {
		if got := parseSystemdUnit(test.input); got != test.want {
			t.Fatalf("parseSystemdUnit(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestParseSystemdUnitFromProcCgroup(t *testing.T) {
	value := "0::/user.slice/user-1000.slice/user@1000.service/app.slice/binderledger-localhost-proxy@8081.service\n"
	if got := parseProcSystemdUnit(value); got != "binderledger-localhost-proxy@8081.service" {
		t.Fatalf("unexpected process cgroup unit: %q", got)
	}
}

func TestParseUserSocketOwners(t *testing.T) {
	owners := parseUserSocketOwners([]byte("127.0.0.1:8081 Stream example-proxy@8081.socket example-proxy@8081.service\n[::1]:5353 Datagram example-discovery.socket -\n/run/user/1000/bus Stream dbus.socket dbus.service\n"))
	if owners[systemdSocketKey("TCP", "127.0.0.1", 8081)] != "example-proxy@8081.service" {
		t.Fatalf("stream socket owner was not parsed: %#v", owners)
	}
	if owners[systemdSocketKey("UDP", "::1", 5353)] != "example-discovery.socket" {
		t.Fatalf("datagram socket owner was not parsed: %#v", owners)
	}
	if len(owners) != 2 {
		t.Fatalf("non-network sockets should be ignored: %#v", owners)
	}
}

func TestLinuxCollectorKeepsUnavailableSignalsUnknown(t *testing.T) {
	runner := fakeCommandRunner{outputs: map[string][]byte{}, errors: map[string]error{}}
	collector := NewLinuxCollector(runner)
	collector.hostname = func() (string, error) { return "linux-host", nil }
	collector.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
	collector.stat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
	collector.glob = func(string) ([]string, error) { return nil, errors.New("unavailable") }

	snapshot := collector.Collect(context.Background())
	if snapshot.LinuxBaseline.Firewall.Active != nil {
		t.Fatal("unavailable firewall state must remain unknown")
	}
	if len(snapshot.Notices) == 0 {
		t.Fatal("collector limitations must remain visible")
	}
}

func TestLinuxCollectorReadsSanitizedWorkloadInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-inventory.json")
	inventory := model.WorkloadInventory{
		Runtime: "docker", CollectedAt: time.Now().UTC(),
		Workloads: []model.ContainerWorkload{{
			Name: "haven_hub", Image: "ghcr.io/adamwentworth/haven-hub:sha-example", Project: "haven", Service: "hub", State: "running", Health: "healthy",
			Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 5443, Published: true, HostAddress: "192.0.2.77", HostPort: 5443}},
		}},
	}
	if err := workload.WriteFile(path, inventory); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HAVEN_WORKLOAD_INVENTORY_PATH", path)
	notices := []model.CollectorNotice{}
	got := NewLinuxCollector(fakeCommandRunner{}).workloads(&notices)
	if got == nil || len(got.Workloads) != 1 || got.Workloads[0].Name != "haven_hub" {
		t.Fatalf("workload inventory was not collected: %#v", got)
	}
	if len(notices) != 0 {
		t.Fatalf("a fresh inventory should not create a notice: %#v", notices)
	}
}

func TestParseLinuxIPv6Endpoint(t *testing.T) {
	address, port, ok := parseLinuxEndpoint("[::1]:443")
	if !ok || address != "::1" || port != 443 {
		t.Fatalf("unexpected endpoint parse: %q %d %t", address, port, ok)
	}
	address, port, ok = parseLinuxEndpoint("[::]:*")
	if !ok || address != "::" || port != 0 {
		t.Fatalf("unexpected wildcard endpoint parse: %q %d %t", address, port, ok)
	}
	address, port, ok = parseLinuxEndpoint("[::ffff:192.0.2.77]:8443")
	if !ok || address != "192.0.2.77" || port != 8443 {
		t.Fatalf("unexpected IPv4-mapped endpoint parse: %q %d %t", address, port, ok)
	}
	address, port, ok = parseLinuxEndpoint("[fe80::1%enp2s0]:5353")
	if !ok || address != "fe80::1" || port != 5353 {
		t.Fatalf("unexpected zoned endpoint parse: %q %d %t", address, port, ok)
	}
}
