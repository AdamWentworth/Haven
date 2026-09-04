package appliance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const (
	maximumConfigBytes = 64 << 10
	maximumAppliances  = 16
	maximumServices    = 16
	FailureThreshold   = 2
	StaleAfter         = 35 * time.Minute
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
var sshUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var sshHostKeyPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

type configFile struct {
	Appliances []model.ManagedApplianceDefinition `json:"appliances"`
}

type StatusStore interface {
	SyncManagedAppliances(context.Context, []model.ManagedApplianceDefinition, time.Time) error
	RecordManagedApplianceProbe(context.Context, string, []model.ManagedServiceStatus, time.Time) error
	RecordManagedApplianceHealth(context.Context, string, model.ManagedHealthStatus, time.Time) error
	ListManagedAppliances(context.Context) ([]model.ManagedApplianceStatus, error)
}

type Monitor struct {
	store       StatusStore
	logger      *slog.Logger
	definitions []model.ManagedApplianceDefinition
	dialer      *net.Dialer
	now         func() time.Time
}

func LoadDefinitions(path string) ([]model.ManagedApplianceDefinition, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open managed-appliance configuration: %w", err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect managed-appliance configuration: %w", err)
	}
	if information.Size() > maximumConfigBytes {
		return nil, fmt.Errorf("managed-appliance configuration exceeds %d bytes", maximumConfigBytes)
	}

	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(file, maximumConfigBytes+1)))
	decoder.DisallowUnknownFields()
	var configured configFile
	if err := decoder.Decode(&configured); err != nil {
		return nil, fmt.Errorf("decode managed-appliance configuration: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return nil, err
	}
	if len(configured.Appliances) == 0 || len(configured.Appliances) > maximumAppliances {
		return nil, fmt.Errorf("managed-appliance configuration must contain 1 through %d appliances", maximumAppliances)
	}

	seenAppliances := make(map[string]struct{}, len(configured.Appliances))
	for applianceIndex := range configured.Appliances {
		definition := &configured.Appliances[applianceIndex]
		definition.ID = strings.ToLower(strings.TrimSpace(definition.ID))
		definition.DisplayName = strings.TrimSpace(definition.DisplayName)
		definition.Kind = strings.ToLower(strings.TrimSpace(definition.Kind))
		definition.Address = strings.TrimSpace(definition.Address)
		if !identifierPattern.MatchString(definition.ID) {
			return nil, fmt.Errorf("managed appliance %d has an invalid id", applianceIndex+1)
		}
		if _, exists := seenAppliances[definition.ID]; exists {
			return nil, fmt.Errorf("managed appliance id %q is duplicated", definition.ID)
		}
		seenAppliances[definition.ID] = struct{}{}
		if definition.DisplayName == "" || len(definition.DisplayName) > 80 {
			return nil, fmt.Errorf("managed appliance %q must have a display name of 1 through 80 characters", definition.ID)
		}
		if definition.Kind == "" || len(definition.Kind) > 32 {
			return nil, fmt.Errorf("managed appliance %q has an invalid kind", definition.ID)
		}
		address, err := netip.ParseAddr(definition.Address)
		if err != nil || !address.IsPrivate() || address.IsLoopback() || address.IsMulticast() {
			return nil, fmt.Errorf("managed appliance %q must use a literal private unicast address", definition.ID)
		}
		definition.Address = address.Unmap().String()
		if definition.Health != nil {
			health := definition.Health
			health.Provider = strings.ToLower(strings.TrimSpace(health.Provider))
			health.CommunityFile = strings.TrimSpace(health.CommunityFile)
			health.SSHUsername = strings.TrimSpace(health.SSHUsername)
			health.SSHPrivateKeyFile = strings.TrimSpace(health.SSHPrivateKeyFile)
			health.SSHHostKeySHA256 = strings.TrimSpace(health.SSHHostKeySHA256)
			if health.Provider != "terramaster-tos5" {
				return nil, fmt.Errorf("managed appliance %q has unsupported health provider %q", definition.ID, health.Provider)
			}
			if health.SNMPPort == 0 {
				health.SNMPPort = 161
			}
			if health.SNMPPort < 1 || health.SNMPPort > 65535 {
				return nil, fmt.Errorf("managed appliance %q has an invalid SNMP port", definition.ID)
			}
			if !safeMountedSecretPath(health.CommunityFile) {
				return nil, fmt.Errorf("managed appliance %q must use an absolute mounted SNMP community file", definition.ID)
			}
			if health.SSHPort == 0 {
				health.SSHPort = 9222
			}
			if health.SSHPort < 1 || health.SSHPort > 65535 {
				return nil, fmt.Errorf("managed appliance %q has an invalid SSH port", definition.ID)
			}
			if !sshUsernamePattern.MatchString(health.SSHUsername) {
				return nil, fmt.Errorf("managed appliance %q has an invalid SSH username", definition.ID)
			}
			if !safeMountedSecretPath(health.SSHPrivateKeyFile) {
				return nil, fmt.Errorf("managed appliance %q must use an absolute mounted SSH private-key file", definition.ID)
			}
			if !sshHostKeyPattern.MatchString(health.SSHHostKeySHA256) {
				return nil, fmt.Errorf("managed appliance %q must pin an SHA-256 SSH host-key fingerprint", definition.ID)
			}
		}
		if len(definition.Services) == 0 || len(definition.Services) > maximumServices {
			return nil, fmt.Errorf("managed appliance %q must declare 1 through %d services", definition.ID, maximumServices)
		}
		seenServices := make(map[string]struct{}, len(definition.Services))
		seenEndpoints := make(map[string]struct{}, len(definition.Services))
		for serviceIndex := range definition.Services {
			service := &definition.Services[serviceIndex]
			service.ID = strings.ToLower(strings.TrimSpace(service.ID))
			service.Name = strings.TrimSpace(service.Name)
			service.Protocol = strings.ToUpper(strings.TrimSpace(service.Protocol))
			if !identifierPattern.MatchString(service.ID) {
				return nil, fmt.Errorf("managed appliance %q service %d has an invalid id", definition.ID, serviceIndex+1)
			}
			if _, exists := seenServices[service.ID]; exists {
				return nil, fmt.Errorf("managed appliance %q service id %q is duplicated", definition.ID, service.ID)
			}
			seenServices[service.ID] = struct{}{}
			if service.Name == "" || len(service.Name) > 80 {
				return nil, fmt.Errorf("managed appliance %q service %q has an invalid name", definition.ID, service.ID)
			}
			if service.Protocol != "TCP" {
				return nil, fmt.Errorf("managed appliance %q service %q must use TCP", definition.ID, service.ID)
			}
			if service.Port < 1 || service.Port > 65535 {
				return nil, fmt.Errorf("managed appliance %q service %q has an invalid port", definition.ID, service.ID)
			}
			endpoint := fmt.Sprintf("%s:%d", service.Protocol, service.Port)
			if _, exists := seenEndpoints[endpoint]; exists {
				return nil, fmt.Errorf("managed appliance %q endpoint %s is duplicated", definition.ID, endpoint)
			}
			seenEndpoints[endpoint] = struct{}{}
		}
	}
	sort.Slice(configured.Appliances, func(left, right int) bool { return configured.Appliances[left].ID < configured.Appliances[right].ID })
	return configured.Appliances, nil
}

func safeMountedSecretPath(value string) bool {
	return strings.HasPrefix(value, "/run/secrets/") && path.Clean(value) == value && path.Base(value) != "." && len(value) <= 240
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("managed-appliance configuration contains more than one JSON value")
		}
		return fmt.Errorf("decode managed-appliance configuration: %w", err)
	}
	return nil
}

func NewMonitor(ctx context.Context, store StatusStore, logger *slog.Logger, definitions []model.ManagedApplianceDefinition) (*Monitor, error) {
	if store == nil {
		return nil, errors.New("managed-appliance status storage is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	monitor := &Monitor{
		store:       store,
		logger:      logger,
		definitions: append([]model.ManagedApplianceDefinition(nil), definitions...),
		dialer:      &net.Dialer{Timeout: 1500 * time.Millisecond},
		now:         time.Now,
	}
	if err := monitor.store.SyncManagedAppliances(ctx, monitor.definitions, monitor.now().UTC()); err != nil {
		return nil, fmt.Errorf("synchronize managed appliances: %w", err)
	}
	return monitor, nil
}

func (monitor *Monitor) Probe(ctx context.Context) error {
	for _, definition := range monitor.definitions {
		checkedAt := monitor.now().UTC()
		results := make([]model.ManagedServiceStatus, 0, len(definition.Services))
		for _, service := range definition.Services {
			results = append(results, monitor.probeService(ctx, definition.Address, service, checkedAt))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := monitor.store.RecordManagedApplianceProbe(ctx, definition.ID, results, checkedAt); err != nil {
			return fmt.Errorf("record managed appliance %q: %w", definition.ID, err)
		}
		if definition.Health != nil {
			health := probeManagedHealth(ctx, definition.Address, *definition.Health, checkedAt)
			if err := monitor.store.RecordManagedApplianceHealth(ctx, definition.ID, health, checkedAt); err != nil {
				return fmt.Errorf("record managed appliance %q health: %w", definition.ID, err)
			}
		}
	}
	return nil
}

func (monitor *Monitor) Status(ctx context.Context) ([]model.ManagedApplianceStatus, error) {
	return monitor.store.ListManagedAppliances(ctx)
}

func (monitor *Monitor) probeService(ctx context.Context, address string, service model.ManagedServiceDefinition, checkedAt time.Time) model.ManagedServiceStatus {
	status := model.ManagedServiceStatus{
		ID: service.ID, Name: service.Name, Protocol: service.Protocol, Port: service.Port,
		TLS: service.TLS, Required: service.Required, LastCheckedAt: &checkedAt,
	}
	endpoint := net.JoinHostPort(address, fmt.Sprintf("%d", service.Port))
	connection, err := monitor.dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		status.ErrorClass = classifyNetworkError(err)
		return status
	}
	defer connection.Close()
	if !service.TLS {
		status.Reachable = true
		return status
	}

	deadline := checkedAt.Add(3 * time.Second)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	// Keep Go's normal certificate verification enabled. When verification is
	// the only handshake failure, CertificateVerificationError still exposes
	// the unverified peer chain so HAVEN can report bounded certificate facts
	// without accepting an untrusted TLS session.
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: address,
	})
	handshakeErr := tlsConnection.HandshakeContext(ctx)
	peerCertificates := tlsConnection.ConnectionState().PeerCertificates
	if handshakeErr != nil {
		var verificationError *tls.CertificateVerificationError
		if !errors.As(handshakeErr, &verificationError) || len(verificationError.UnverifiedCertificates) == 0 {
			status.ErrorClass = "tls-handshake-failed"
			return status
		}
		peerCertificates = verificationError.UnverifiedCertificates
	}
	if len(peerCertificates) == 0 {
		status.ErrorClass = "certificate-unavailable"
		return status
	}
	leaf := peerCertificates[0]
	digest := sha256.Sum256(leaf.Raw)
	certificate := &model.ManagedCertificateStatus{
		Subject:     boundedCertificateName(leaf.Subject.String()),
		Issuer:      boundedCertificateName(leaf.Issuer.String()),
		Fingerprint: strings.ToUpper(hex.EncodeToString(digest[:])),
		NotBefore:   leaf.NotBefore.UTC(),
		NotAfter:    leaf.NotAfter.UTC(),
	}
	certificate.NameValid = leaf.VerifyHostname(address) == nil
	intermediates := x509.NewCertPool()
	for _, candidate := range peerCertificates[1:] {
		intermediates.AddCert(candidate)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates, CurrentTime: checkedAt})
	certificate.SystemTrust = verifyErr == nil
	status.Certificate = certificate
	status.Reachable = true
	return status
}

func boundedCertificateName(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func classifyNetworkError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection-refused"
	}
	return "unreachable"
}

func DeriveAlerts(appliances []model.ManagedApplianceStatus, evaluatedAt time.Time) []model.Alert {
	evaluatedAt = evaluatedAt.UTC()
	alerts := make([]model.Alert, 0)
	for _, appliance := range appliances {
		if appliance.LastCheckedAt != nil && evaluatedAt.Sub(appliance.LastCheckedAt.UTC()) > StaleAfter {
			alerts = append(alerts, model.Alert{
				ID: "appliance-stale:" + appliance.ID, InstanceID: "appliance-stale:" + appliance.ID + ":" + appliance.LastCheckedAt.UTC().Format(time.RFC3339Nano),
				DeviceID: "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-stale", Severity: "medium",
				Title: "Managed appliance checks are overdue", Summary: "HAVEN has not completed the configured appliance checks within the expected window.",
				Evidence: "Last hub check: " + appliance.LastCheckedAt.UTC().Format(time.RFC3339), StartedAt: appliance.LastCheckedAt.Add(StaleAfter),
			})
			continue
		}

		required := make([]model.ManagedServiceStatus, 0)
		for _, service := range appliance.Services {
			if service.Required {
				required = append(required, service)
			}
		}
		allRequiredDown := len(required) > 0
		for _, service := range required {
			if service.Reachable || service.ConsecutiveFailures < FailureThreshold {
				allRequiredDown = false
				break
			}
		}
		if allRequiredDown {
			startedAt := earliestFailure(required, evaluatedAt)
			alerts = append(alerts, model.Alert{
				ID: "appliance-unreachable:" + appliance.ID, InstanceID: "appliance-unreachable:" + appliance.ID + ":" + startedAt.Format(time.RFC3339Nano),
				DeviceID: "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-unreachable", Severity: "medium",
				Title: "Managed appliance is unreachable", Summary: "Every required service failed at least two consecutive hub checks. This may indicate an outage, network problem, or powered-off appliance.",
				Evidence: fmt.Sprintf("%d required services unavailable", len(required)), StartedAt: startedAt,
			})
		} else {
			for _, service := range required {
				if service.Reachable || service.ConsecutiveFailures < FailureThreshold {
					continue
				}
				startedAt := statusTime(service.LastChangedAt, evaluatedAt)
				alerts = append(alerts, model.Alert{
					ID: "appliance-service:" + appliance.ID + ":" + service.ID, InstanceID: "appliance-service:" + appliance.ID + ":" + service.ID + ":" + startedAt.Format(time.RFC3339Nano),
					DeviceID: "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-service", Severity: "medium",
					Title: service.Name + " is unavailable", Summary: "A required, explicitly configured appliance service failed at least two consecutive hub checks.",
					Evidence: fmt.Sprintf("%s %d · %s", service.Protocol, service.Port, service.ErrorClass), StartedAt: startedAt,
				})
			}
		}

		for _, service := range appliance.Services {
			if service.Certificate == nil || !service.Reachable {
				continue
			}
			remaining := service.Certificate.NotAfter.Sub(evaluatedAt)
			if remaining > 30*24*time.Hour {
				continue
			}
			severity := "low"
			title := service.Name + " certificate expires soon"
			if remaining <= 0 {
				severity = "medium"
				title = service.Name + " certificate has expired"
			} else if remaining <= 14*24*time.Hour {
				severity = "medium"
			}
			startedAt := service.Certificate.NotAfter.Add(-30 * 24 * time.Hour)
			alerts = append(alerts, model.Alert{
				ID:         "appliance-certificate:" + appliance.ID + ":" + service.ID,
				InstanceID: "appliance-certificate:" + appliance.ID + ":" + service.ID + ":" + service.Certificate.NotAfter.UTC().Format(time.RFC3339Nano) + ":" + severity,
				DeviceID:   "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-certificate", Severity: severity,
				Title: title, Summary: "The certificate presented by this explicitly configured private appliance is near the end of its validity period.",
				Evidence: "Expires: " + service.Certificate.NotAfter.UTC().Format(time.RFC3339), StartedAt: startedAt,
			})
		}
		alerts = append(alerts, deriveHealthAlerts(appliance, evaluatedAt)...)
	}
	return alerts
}

func deriveHealthAlerts(appliance model.ManagedApplianceStatus, evaluatedAt time.Time) []model.Alert {
	health := appliance.Health
	if health == nil || health.LastCheckedAt == nil {
		return nil
	}
	if health.Status == "unavailable" {
		if health.ConsecutiveFailures < FailureThreshold {
			return nil
		}
		startedAt := statusTime(health.LastChangedAt, *health.LastCheckedAt)
		return []model.Alert{{
			ID: "appliance-health:" + appliance.ID, InstanceID: "appliance-health:" + appliance.ID + ":" + timestampIdentity(startedAt),
			DeviceID: "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-health", Severity: "medium",
			Title: "NAS health telemetry is unavailable", Summary: "Both configured read-only NAS health sources failed at least two consecutive checks.",
			Evidence: health.ErrorClass, StartedAt: startedAt,
		}}
	}
	alerts := make([]model.Alert, 0)
	for _, disk := range health.Disks {
		state := disk.State
		if healthStateRank(disk.SMART) > healthStateRank(state) {
			state = disk.SMART
		}
		if !healthStateAttention(state) {
			continue
		}
		severity := healthSeverity(state)
		startedAt := statusTime(disk.LastChangedAt, *health.LastCheckedAt)
		alerts = append(alerts, healthAlert(appliance, "disk", disk.Name, severity, "NAS disk health needs attention", fmt.Sprintf("%s · device %s · SMART %s", disk.Model, disk.State, disk.SMART), startedAt))
	}
	for _, pool := range health.Pools {
		if !healthStateAttention(pool.State) && pool.State != "rebuilding" {
			continue
		}
		severity := healthSeverity(pool.State)
		startedAt := statusTime(pool.LastChangedAt, *health.LastCheckedAt)
		alerts = append(alerts, healthAlert(appliance, "raid", pool.Name, severity, "NAS storage pool needs attention", fmt.Sprintf("%s · %s · %d of %d members active", pool.RAIDLevel, pool.State, pool.ActiveCount, pool.MemberCount), startedAt))
	}
	for _, volume := range health.Volumes {
		if !healthStateAttention(volume.State) {
			continue
		}
		severity := healthSeverity(volume.State)
		startedAt := statusTime(volume.LastChangedAt, *health.LastCheckedAt)
		alerts = append(alerts, healthAlert(appliance, "capacity", volume.Name, severity, "NAS volume capacity needs attention", fmt.Sprintf("%s is %.1f%% used", volume.Name, volume.UsedPercentage), startedAt))
	}
	for _, temperature := range health.Temperatures {
		if !healthStateAttention(temperature.State) {
			continue
		}
		severity := healthSeverity(temperature.State)
		startedAt := statusTime(temperature.LastChangedAt, *health.LastCheckedAt)
		alerts = append(alerts, healthAlert(appliance, "temperature", temperature.Name, severity, "NAS temperature needs attention", fmt.Sprintf("%s is %.1f°C", temperature.Name, temperature.Celsius), startedAt))
	}
	return alerts
}

func healthAlert(appliance model.ManagedApplianceStatus, kind, name, severity, title, evidence string, startedAt time.Time) model.Alert {
	id := "appliance-" + kind + ":" + appliance.ID + ":" + componentIdentity(name)
	return model.Alert{
		ID: id, InstanceID: id + ":" + timestampIdentity(startedAt) + ":" + severity,
		DeviceID: "appliance:" + appliance.ID, DeviceName: appliance.DisplayName, Kind: "appliance-" + kind, Severity: severity,
		Title: title, Summary: "A read-only NAS health observation crossed HAVEN's reviewed warning threshold.", Evidence: strings.TrimSpace(evidence), StartedAt: startedAt,
	}
}

func healthStateRank(state string) int {
	switch state {
	case "critical", "failed":
		return 3
	case "warning", "degraded":
		return 2
	case "rebuilding":
		return 1
	default:
		return 0
	}
}

func healthSeverity(state string) string {
	if state == "critical" || state == "failed" || state == "degraded" {
		return "high"
	}
	return "medium"
}

func componentIdentity(name string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return fmt.Sprintf("%x", digest[:6])
}

func timestampIdentity(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func earliestFailure(services []model.ManagedServiceStatus, fallback time.Time) time.Time {
	earliest := fallback
	for _, service := range services {
		candidate := statusTime(service.LastChangedAt, fallback)
		if earliest.Equal(fallback) || candidate.Before(earliest) {
			earliest = candidate
		}
	}
	return earliest
}

func statusTime(value *time.Time, fallback time.Time) time.Time {
	if value == nil {
		return fallback.UTC()
	}
	return value.UTC()
}
