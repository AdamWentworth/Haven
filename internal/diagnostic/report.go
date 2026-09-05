package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/agent"
	"github.com/AdamWentworth/haven/internal/buildinfo"
	"github.com/AdamWentworth/haven/internal/trust"
)

const SchemaVersion = 1

type State string

const (
	StatePass       State = "pass"
	StateConfigured State = "configured"
	StateWarning    State = "warning"
	StateFail       State = "fail"
)

type Check struct {
	ID       string `json:"id"`
	Area     string `json:"area"`
	Title    string `json:"title"`
	State    State  `json:"state"`
	Summary  string `json:"summary"`
	Guidance string `json:"guidance,omitempty"`
}

type RecoveryPlan struct {
	Principle    string   `json:"principle"`
	Preserved    []string `json:"preserved"`
	Reinitialize []string `json:"reinitialize"`
	Checklist    []string `json:"checklist"`
}

type Summary struct {
	Passing  int `json:"passing"`
	Advisory int `json:"advisory"`
	Failed   int `json:"failed"`
}

type Report struct {
	SchemaVersion int          `json:"schemaVersion"`
	Kind          string       `json:"kind"`
	Status        string       `json:"status"`
	Version       string       `json:"version"`
	Revision      string       `json:"revision"`
	GeneratedAt   time.Time    `json:"generatedAt"`
	Summary       Summary      `json:"summary"`
	Checks        []Check      `json:"checks"`
	Recovery      RecoveryPlan `json:"recovery"`
}

type HubOptions struct {
	StateDirectory        string
	DataPath              string
	PublicOrigin          string
	DashboardAddress      string
	AgentAddress          string
	AgentServerNames      []string
	Production            bool
	LocalCollection       bool
	ManagedAppliances     int
	ManagedApplianceError bool
	StoreProbe            func(context.Context) error
	Now                   time.Time
}

func Hub(ctx context.Context, options HubOptions) Report {
	checks := []Check{
		stateDirectoryCheck(options.StateDirectory),
		databaseCheck(ctx, options.DataPath, options.StoreProbe),
		keyMaterialCheck(options.StateDirectory, options.Production),
		pkiCheck(options.StateDirectory, options.AgentServerNames, options.Now),
		ownerAccessCheck(options.PublicOrigin, options.Production),
		listenerCheck("dashboard-boundary", "Access boundary", "Dashboard listener", options.DashboardAddress, false),
		listenerCheck("agent-boundary", "Agent transport", "Agent ingestion listener", options.AgentAddress, true),
		collectionCheck(options.LocalCollection),
		applianceCheck(options.ManagedAppliances, options.ManagedApplianceError),
	}
	return newReport("hub", checks, options.Now)
}

func Agent(_ context.Context, directory, installation string, now time.Time) Report {
	checks := []Check{}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		checks = append(checks, Check{ID: "agent-state", Area: "Durable state", Title: "Agent state directory", State: StateFail, Summary: "The enrolled agent state directory is unavailable.", Guidance: "Install or re-enroll the agent using a new one-time enrollment token."})
	} else {
		checks = append(checks, Check{ID: "agent-state", Area: "Durable state", Title: "Agent state directory", State: StatePass, Summary: "The enrolled agent state directory is present."})
	}

	client, loadErr := agent.Load(directory)
	if loadErr != nil {
		checks = append(checks, Check{ID: "agent-configuration", Area: "Enrollment", Title: "Agent configuration", State: StateFail, Summary: "The enrolled agent configuration could not be validated.", Guidance: "Repair the installation or re-enroll this device; do not copy another device's identity."})
	} else {
		config := client.Config()
		checks = append(checks, Check{ID: "agent-configuration", Area: "Enrollment", Title: "Agent configuration", State: StatePass, Summary: "The device identity, display label, and HTTPS hub target are structurally valid."})
		if config.Sequence > 0 {
			checks = append(checks, Check{ID: "accepted-report", Area: "Reporting", Title: "Accepted report state", State: StatePass, Summary: "This agent has recorded at least one report accepted by its hub."})
		} else {
			checks = append(checks, Check{ID: "accepted-report", Area: "Reporting", Title: "Accepted report state", State: StateWarning, Summary: "No accepted report has been recorded in this local identity yet.", Guidance: "Run one report after enrollment and confirm the device becomes current in HAVEN."})
		}
	}
	checks = append(checks, agentIdentityCheck(directory, now))
	checks = append(checks, installationCheck(installation))
	return newReport("agent", checks, now)
}

func newReport(kind string, checks []Check, now time.Time) Report {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	summary := Summary{}
	for _, check := range checks {
		switch check.State {
		case StatePass, StateConfigured:
			summary.Passing++
		case StateWarning:
			summary.Advisory++
		case StateFail:
			summary.Failed++
		}
	}
	status := "ready"
	if summary.Failed > 0 {
		status = "not-ready"
	} else if summary.Advisory > 0 {
		status = "review"
	}
	return Report{SchemaVersion: SchemaVersion, Kind: kind, Status: status, Version: buildinfo.Version, Revision: buildinfo.Revision, GeneratedAt: now.UTC(), Summary: summary, Checks: checks, Recovery: redactedRecoveryPlan()}
}

func stateDirectoryCheck(directory string) Check {
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return Check{ID: "state-directory", Area: "Durable state", Title: "State directory", State: StateFail, Summary: "The configured state directory is unavailable.", Guidance: "Restore the complete state directory or initialize a clean hub before starting HAVEN."}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Check{ID: "state-directory", Area: "Durable state", Title: "State directory", State: StateWarning, Summary: "The state directory exists but its Unix mode permits access beyond its owner.", Guidance: "Restrict the state directory to its service account before storing owner data."}
	}
	return Check{ID: "state-directory", Area: "Durable state", Title: "State directory", State: StatePass, Summary: "The private application state directory is present."}
}

func databaseCheck(ctx context.Context, path string, probe func(context.Context) error) Check {
	if probe != nil {
		if err := probe(ctx); err != nil {
			return Check{ID: "database", Area: "Durable state", Title: "SQLite store", State: StateFail, Summary: "The running hub could not complete a database readiness check.", Guidance: "Inspect storage availability and restore from a known-good state backup if necessary."}
		}
		return Check{ID: "database", Area: "Durable state", Title: "SQLite store", State: StatePass, Summary: "The running hub completed its database readiness check."}
	}
	file, err := os.Open(path)
	if err != nil {
		return Check{ID: "database", Area: "Durable state", Title: "SQLite store", State: StateFail, Summary: "The configured database file is not readable.", Guidance: "Restore the complete state directory or initialize a clean hub."}
	}
	header := make([]byte, 16)
	_, readErr := io.ReadFull(file, header)
	_ = file.Close()
	if readErr != nil || string(header) != "SQLite format 3\x00" {
		return Check{ID: "database", Area: "Durable state", Title: "SQLite store", State: StateFail, Summary: "The configured database file does not have a valid SQLite header.", Guidance: "Do not start the hub against this file; restore a known-good complete state directory."}
	}
	return Check{ID: "database", Area: "Durable state", Title: "SQLite store", State: StateConfigured, Summary: "The configured database file is present and readable; offline doctor does not migrate or modify it."}
}

func keyMaterialCheck(directory string, production bool) Check {
	if !production {
		return Check{ID: "protected-material", Area: "Durable state", Title: "Protected owner material", State: StateConfigured, Summary: "Synthetic mode does not require owner credential and notebook keys."}
	}
	names := []string{"auth-credential.key", "account-notebook.key", "browser-site-reviews.key", "push-subscription.key", "vapid-keys.json"}
	missing := 0
	for _, name := range names {
		if info, err := os.Stat(filepath.Join(directory, name)); err != nil || info.IsDir() {
			missing++
		}
	}
	if missing > 0 {
		return Check{ID: "protected-material", Area: "Durable state", Title: "Protected owner material", State: StateFail, Summary: "One or more required credential, notebook, or notification key files are unavailable.", Guidance: "Restore the entire matching state directory; never reconstruct or publish individual secret files."}
	}
	return Check{ID: "protected-material", Area: "Durable state", Title: "Protected owner material", State: StatePass, Summary: "Required credential, notebook, review, and notification key files are present."}
}

func pkiCheck(directory string, serverNames []string, now time.Time) Check {
	names := []string{"ca.crt", "ca.key", "server.crt", "server.key"}
	missing := 0
	for _, name := range names {
		if info, err := os.Stat(filepath.Join(directory, "pki", name)); err != nil || info.IsDir() {
			missing++
		}
	}
	if missing > 0 {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub's mutual-TLS identity set is incomplete.", Guidance: "Restore the matching PKI directory. Replacing it requires deliberate agent re-enrollment."}
	}
	caCertificatePEM, caCertErr := os.ReadFile(filepath.Join(directory, "pki", "ca.crt"))
	caKeyPEM, caKeyErr := os.ReadFile(filepath.Join(directory, "pki", "ca.key"))
	serverCertificatePEM, serverCertErr := os.ReadFile(filepath.Join(directory, "pki", "server.crt"))
	serverKeyPEM, serverKeyErr := os.ReadFile(filepath.Join(directory, "pki", "server.key"))
	if caCertErr != nil || caKeyErr != nil || serverCertErr != nil || serverKeyErr != nil {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub's mutual-TLS identity set could not be read.", Guidance: "Restore the complete matching PKI directory; do not regenerate individual files."}
	}
	if _, err := tls.X509KeyPair(caCertificatePEM, caKeyPEM); err != nil {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub authority certificate and private key do not form a valid pair.", Guidance: "Restore the complete matching PKI directory; do not regenerate individual files."}
	}
	serverPair, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil || len(serverPair.Certificate) == 0 {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub agent-endpoint certificate and private key do not form a valid pair.", Guidance: "Restore the complete matching PKI directory or deliberately rotate and re-enroll every agent."}
	}
	caBlock, _ := pem.Decode(caCertificatePEM)
	if caBlock == nil {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub authority certificate is not valid PEM.", Guidance: "Restore the complete matching PKI directory."}
	}
	caCertificate, caParseErr := x509.ParseCertificate(caBlock.Bytes)
	serverCertificate, serverParseErr := x509.ParseCertificate(serverPair.Certificate[0])
	if caParseErr != nil || serverParseErr != nil {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The hub mutual-TLS certificates could not be parsed.", Guidance: "Restore the complete matching PKI directory."}
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := serverCertificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The agent-endpoint certificate is not currently valid under the stored hub authority.", Guidance: "Inspect certificate expiry and rotate the complete trust set deliberately before re-enrolling agents."}
	}
	for _, serverName := range serverNames {
		if err := serverCertificate.VerifyHostname(strings.TrimSpace(serverName)); err != nil {
			return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateFail, Summary: "The agent-endpoint certificate does not cover every configured private server name.", Guidance: "Rotate the server identity deliberately before using the changed endpoint; preserve the authority when possible."}
		}
	}
	if serverCertificate.NotAfter.Sub(now) < 30*24*time.Hour {
		return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StateWarning, Summary: "The agent-endpoint identity is valid but its server certificate expires within 30 days.", Guidance: "Plan a controlled hub certificate rotation and verify every enrolled agent before expiry."}
	}
	return Check{ID: "agent-pki", Area: "Agent transport", Title: "Agent trust authority", State: StatePass, Summary: "The complete mutual-TLS authority and server identity set is present."}
}

func ownerAccessCheck(origin string, production bool) Check {
	if !production {
		return Check{ID: "owner-origin", Area: "Access boundary", Title: "Owner origin", State: StateConfigured, Summary: "Synthetic mode uses a development access boundary."}
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Check{ID: "owner-origin", Area: "Access boundary", Title: "Owner origin", State: StateFail, Summary: "The owner access origin is not a valid HTTPS origin.", Guidance: "Configure one stable private HTTPS origin before registering passkeys."}
	}
	if parsed.Scheme == "http" && parsed.Hostname() == "localhost" {
		return Check{ID: "owner-origin", Area: "Access boundary", Title: "Owner origin", State: StateConfigured, Summary: "Owner access uses the browser's loopback development-origin exception; production still requires private HTTPS."}
	}
	if parsed.Scheme != "https" {
		return Check{ID: "owner-origin", Area: "Access boundary", Title: "Owner origin", State: StateFail, Summary: "The owner access origin is not a valid HTTPS origin.", Guidance: "Configure one stable private HTTPS origin before registering passkeys."}
	}
	return Check{ID: "owner-origin", Area: "Access boundary", Title: "Owner origin", State: StatePass, Summary: "Owner access is anchored to one stable HTTPS origin for passkeys and session cookies."}
}

func listenerCheck(id, area, title, address string, agentEndpoint bool) Check {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return Check{ID: id, Area: area, Title: title, State: StateFail, Summary: "The listener address is invalid.", Guidance: "Use an explicit host and port in the private deployment configuration."}
	}
	state := StateConfigured
	summary := "The listener uses an explicit host and port. Network reachability still depends on the host firewall and reverse proxy."
	if agentEndpoint {
		summary = "The agent endpoint uses an explicit host and port; mutual TLS authenticates enrolled reporters."
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		summary += " It is bound to all interfaces."
	}
	return Check{ID: id, Area: area, Title: title, State: state, Summary: summary, Guidance: "Confirm host-firewall scope whenever deployment networking changes."}
}

func collectionCheck(local bool) Check {
	if local {
		return Check{ID: "collection-mode", Area: "Lifecycle", Title: "Collection mode", State: StateConfigured, Summary: "The hub also collects posture from its own operating system."}
	}
	return Check{ID: "collection-mode", Area: "Lifecycle", Title: "Collection mode", State: StatePass, Summary: "The hub is in agent-only mode, keeping platform collection in enrolled native agents."}
}

func applianceCheck(count int, invalid bool) Check {
	if invalid {
		return Check{ID: "appliance-config", Area: "Lifecycle", Title: "Managed appliances", State: StateFail, Summary: "The configured managed-appliance definition could not be validated.", Guidance: "Validate the private definition on the hub without copying its addresses or credentials into public diagnostics."}
	}
	if count == 0 {
		return Check{ID: "appliance-config", Area: "Lifecycle", Title: "Managed appliances", State: StateConfigured, Summary: "No managed-appliance definitions are configured; this capability is optional."}
	}
	return Check{ID: "appliance-config", Area: "Lifecycle", Title: "Managed appliances", State: StatePass, Summary: fmt.Sprintf("%d managed-appliance definition(s) loaded without exposing their addresses or credentials.", count)}
}

func agentIdentityCheck(directory string, now time.Time) Check {
	caPEM, caErr := os.ReadFile(filepath.Join(directory, "ca.crt"))
	certificatePEM, certErr := os.ReadFile(filepath.Join(directory, "client.crt"))
	privateKeyPEM, keyErr := os.ReadFile(filepath.Join(directory, "client.key"))
	if caErr != nil || certErr != nil || keyErr != nil {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled agent certificate set is incomplete.", Guidance: "Re-enroll this device with a new one-time token; do not copy another device's identity."}
	}
	config, err := trust.AgentTLSConfig(caPEM, certificatePEM, privateKeyPEM)
	if err != nil || len(config.Certificates) != 1 {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled agent certificate set could not be validated.", Guidance: "Re-enroll this device with a new one-time token."}
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled agent certificate and private key do not form a valid pair.", Guidance: "Re-enroll this device with a new one-time token."}
	}
	caBlock, _ := pem.Decode(caPEM)
	clientCertificate, certErr := x509.ParseCertificate(certificate.Certificate[0])
	if caBlock == nil || certErr != nil {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled agent certificates could not be parsed.", Guidance: "Re-enroll this device with a new one-time token."}
	}
	caCertificate, caErr := x509.ParseCertificate(caBlock.Bytes)
	if caErr != nil {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled agent's trusted authority could not be parsed.", Guidance: "Re-enroll this device with a new one-time token."}
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := clientCertificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: StateFail, Summary: "The enrolled client certificate is not currently valid under its trusted hub authority.", Guidance: "Create a new one-time token and re-enroll this device."}
	}
	state := StatePass
	summary := "The trusted authority, client certificate, and private key form a valid identity set."
	guidance := ""
	if clientCertificate.NotAfter.Sub(now) < 30*24*time.Hour {
		state = StateWarning
		summary = "The enrolled identity is valid but its client certificate expires within 30 days."
		guidance = "Plan a controlled re-enrollment before the certificate expires."
	}
	return Check{ID: "agent-identity", Area: "Enrollment", Title: "Mutual-TLS identity", State: state, Summary: summary, Guidance: guidance}
}

func installationCheck(installation string) Check {
	installation = strings.TrimSpace(installation)
	if installation == "" || installation == "development" || installation == "interactive" {
		return Check{ID: "agent-installation", Area: "Lifecycle", Title: "Background installation", State: StateConfigured, Summary: "This interactive diagnostic binary cannot verify the external platform scheduler.", Guidance: "Use the read-only Windows task or Linux systemd status companion to verify scheduled execution."}
	}
	labels := map[string]string{"windows-task": "Windows Task Scheduler", "systemd-user": "a systemd user timer", "systemd-system": "a systemd system service"}
	label := labels[installation]
	if label == "" {
		label = "a bounded packaged installation"
	}
	return Check{ID: "agent-installation", Area: "Lifecycle", Title: "Background installation", State: StatePass, Summary: "Reporting is identified as running through " + label + "."}
}

func redactedRecoveryPlan() RecoveryPlan {
	return RecoveryPlan{
		Principle: "Source rebuilds the product; the complete private state directory preserves continuity. A clean start is always possible without restoring private state.",
		Preserved: []string{
			"Observation history, owner reviews, account notebook records, and notification destinations",
			"Owner passkey registrations and encrypted notebook access material",
			"Hub trust authority and the identities expected by already-enrolled agents",
			"Managed-appliance history stored in the hub database",
		},
		Reinitialize: []string{
			"Private hostnames, addresses, firewall scope, and reverse-proxy configuration",
			"Host-only deployment secrets and managed-appliance credentials",
			"Platform schedulers or services that run each native agent",
			"Browser trust for the private HTTPS authority and desktop-client origin",
			"Every agent identity when the previous hub trust authority is not restored",
		},
		Checklist: []string{
			"Clone the public repository and verify the documented toolchain and tests.",
			"Choose a clean initialization or restore one complete, matching private state directory.",
			"Reapply private deployment configuration outside the public repository.",
			"Start the hub and run haven-hub doctor before exposing the dashboard to the LAN.",
			"Install or repair each platform agent, then run haven-agent doctor locally.",
			"Confirm authenticated reports, firewalls, appliances, alerts, and owner access from the dashboard.",
		},
	}
}

func JSON(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func Text(report Report) string {
	var output strings.Builder
	fmt.Fprintf(&output, "HAVEN %s doctor (%s)\n", report.Kind, report.Status)
	fmt.Fprintf(&output, "Release %s · %d passing · %d advisory · %d failed\n\n", report.Version, report.Summary.Passing, report.Summary.Advisory, report.Summary.Failed)
	for _, check := range report.Checks {
		fmt.Fprintf(&output, "[%s] %s — %s\n", strings.ToUpper(string(check.State)), check.Title, check.Summary)
		if check.Guidance != "" {
			fmt.Fprintf(&output, "  Next: %s\n", check.Guidance)
		}
	}
	output.WriteString("\nRedacted recovery checklist\n")
	for index, step := range report.Recovery.Checklist {
		fmt.Fprintf(&output, "%d. %s\n", index+1, step)
	}
	return output.String()
}
