package collector

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
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
		command("/usr/lib/update-notifier/apt-check"):                                    []byte("13;0"),
		command("systemctl", "is-active", "ssh.service"):                                 []byte("active\n"),
		command("/usr/sbin/sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"): []byte("passwordauthentication no\npermitrootlogin prohibit-password\npubkeyauthentication yes\n"),
		command("systemctl", "--failed", "--no-legend", "--plain"):                       []byte("certbot.service loaded failed failed Certbot\n"),
		command("systemctl", "is-enabled", "unattended-upgrades.service"):                []byte("enabled\n"),
		command("systemctl", "is-active", "unattended-upgrades.service"):                 []byte("active\n"),
		command("aa-status", "--enabled"):                                                []byte{},
		command("timedatectl", "show", "-p", "NTPSynchronized", "--value"):               []byte("yes\n"),
		command("df", "-Pk", "/"):                                                        []byte("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda3 100000 30000 70000 30% /\n"),
		command("ss", "-H", "-tanp"):                                                     []byte("LISTEN 0 4096 192.0.2.77:8443 0.0.0.0:* users:((\"caddy\",pid=42,fd=3))\nESTAB 0 0 192.0.2.77:22 198.51.100.10:51000 users:((\"sshd\",pid=55,fd=4))\n"),
	}, errors: map[string]error{}}
	files := map[string][]byte{
		"/etc/os-release":   []byte("PRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n"),
		"/proc/uptime":      []byte("86401.50 100.00\n"),
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
	if snapshot.LinuxBaseline.SSH.PasswordAuthentication != "no" || snapshot.LinuxBaseline.SSH.PermitRootLogin != "prohibit-password" {
		t.Fatalf("SSH posture was not collected: %#v", snapshot.LinuxBaseline.SSH)
	}
	if len(snapshot.Connections) != 2 || snapshot.Connections[0].ProcessName != "caddy" || snapshot.Connections[1].State != "Established" {
		t.Fatalf("TCP endpoints were not mapped: %#v", snapshot.Connections)
	}
	if len(snapshot.Notices) != 0 {
		t.Fatalf("healthy fake collection returned notices: %#v", snapshot.Notices)
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

func TestParseLinuxIPv6Endpoint(t *testing.T) {
	address, port, ok := parseLinuxEndpoint("[::1]:443")
	if !ok || address != "::1" || port != 443 {
		t.Fatalf("unexpected endpoint parse: %q %d %t", address, port, ok)
	}
	address, port, ok = parseLinuxEndpoint("[::]:*")
	if !ok || address != "::" || port != 0 {
		t.Fatalf("unexpected wildcard endpoint parse: %q %d %t", address, port, ok)
	}
}
