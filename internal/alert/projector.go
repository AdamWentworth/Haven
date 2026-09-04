package alert

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/posture"
	"github.com/AdamWentworth/haven/internal/storage"
)

const maximumEventContext = 100

type Projector struct {
	store *storage.Store
	now   func() time.Time
}

type DeviceObservation struct {
	Device           model.DeviceRecord
	Snapshot         *model.SecuritySnapshot
	ExpectedServices []storage.ExpectedService
	Listeners        []storage.ObservedListener
	FindingReviews   []storage.FindingReview
}

type logicalListener struct {
	key          string
	protocol     string
	port         int
	bindScope    string
	addresses    []string
	processes    []string
	systemdUnits []string
}

func NewProjector(store *storage.Store) *Projector {
	return &Projector{store: store, now: time.Now}
}

// Current derives alerts from the same server-owned device, posture, listener,
// and owner-baseline facts used by the authenticated dashboard API.
func (projector *Projector) Current(ctx context.Context, demoMode bool) ([]model.Alert, error) {
	now := projector.now().UTC()
	devices, err := projector.store.ListDevices(ctx, now)
	if err != nil {
		return nil, err
	}
	events, err := projector.store.ListSecurityEvents(ctx, "", maximumEventContext, demoMode)
	if err != nil {
		return nil, err
	}
	observations := make([]DeviceObservation, 0, len(devices))
	for _, device := range devices {
		if (device.TrustState == "synthetic") != demoMode || device.TrustState == "revoked" {
			continue
		}
		detail, err := projector.store.DeviceDetail(ctx, device.ID, now)
		if err != nil {
			return nil, fmt.Errorf("load alert device %s: %w", device.ID, err)
		}
		if detail.Snapshot != nil {
			evaluated := posture.Evaluate(*detail.Snapshot, now)
			detail.Snapshot = &evaluated
		}
		expected, err := projector.store.ListExpectedServicesIncludingExpired(ctx, device.ID)
		if err != nil {
			return nil, fmt.Errorf("load alert service baseline for %s: %w", device.ID, err)
		}
		listeners, err := projector.store.ListObservedListeners(ctx, device.ID)
		if err != nil {
			return nil, fmt.Errorf("load alert listener history for %s: %w", device.ID, err)
		}
		reviews, err := projector.store.ListFindingReviews(ctx, device.ID)
		if err != nil {
			return nil, fmt.Errorf("load alert finding reviews for %s: %w", device.ID, err)
		}
		observations = append(observations, DeviceObservation{Device: device, Snapshot: detail.Snapshot, ExpectedServices: expected, Listeners: listeners, FindingReviews: reviews})
	}
	return Derive(observations, events, storage.EnrolledDeviceStaleAfter, now), nil
}

// Derive is pure so alert hypotheses can be exercised with fixed evidence in
// tests. It never performs discovery, threat scoring, or network scanning.
func Derive(devices []DeviceObservation, events []model.SecurityEvent, freshnessAllowance time.Duration, evaluatedAt time.Time) []model.Alert {
	evaluatedAt = evaluatedAt.UTC()
	orderedEvents := append([]model.SecurityEvent(nil), events...)
	sort.SliceStable(orderedEvents, func(left, right int) bool {
		if orderedEvents[left].OccurredAt.Equal(orderedEvents[right].OccurredAt) {
			return orderedEvents[left].ID > orderedEvents[right].ID
		}
		return orderedEvents[left].OccurredAt.After(orderedEvents[right].OccurredAt)
	})
	opened := make(map[string]model.SecurityEvent)
	for _, event := range orderedEvents {
		key := event.DeviceID + ":" + event.FindingID
		if event.Kind == "opened" {
			if _, exists := opened[key]; !exists {
				opened[key] = event
			}
		}
	}

	alerts := make([]model.Alert, 0)
	for _, device := range devices {
		if device.Device.Status == "stale" {
			lastSeen := device.Device.EnrolledAt
			if device.Device.LastSeenAt != nil {
				lastSeen = *device.Device.LastSeenAt
			}
			startedAt := lastSeen.Add(freshnessAllowance)
			alerts = append(alerts, model.Alert{
				ID:         "stale-agent:" + device.Device.ID,
				InstanceID: "stale-agent:" + device.Device.ID + ":" + timestampIdentity(lastSeen),
				DeviceID:   device.Device.ID,
				DeviceName: device.Device.DisplayName,
				Kind:       "stale-agent",
				Severity:   "medium",
				Title:      "Authenticated agent report is overdue",
				Summary:    fmt.Sprintf("HAVEN has not received a report within the server's %d-minute freshness allowance.", int(freshnessAllowance.Minutes())),
				Evidence:   "Last authenticated contact: " + lastSeen.UTC().Format(time.RFC3339),
				StartedAt:  startedAt,
			})
		} else if device.Device.Status == "awaiting-first-report" {
			enrolledAt := device.Device.EnrolledAt
			alerts = append(alerts, model.Alert{
				ID:         "awaiting-agent:" + device.Device.ID,
				InstanceID: "awaiting-agent:" + device.Device.ID + ":" + timestampIdentity(enrolledAt),
				DeviceID:   device.Device.ID,
				DeviceName: device.Device.DisplayName,
				Kind:       "awaiting-agent",
				Severity:   "low",
				Title:      "Enrolled device has not reported yet",
				Summary:    "The identity is enrolled, but HAVEN has not accepted its first authenticated observation.",
				Evidence:   "Enrolled: " + enrolledAt.UTC().Format(time.RFC3339),
				StartedAt:  enrolledAt,
			})
		}

		if device.Snapshot == nil {
			continue
		}
		for _, finding := range device.Snapshot.Findings {
			if findingReviewSuppressesAlert(finding.ID, device.FindingReviews, evaluatedAt) {
				continue
			}
			startedAt := device.Snapshot.CollectedAt
			if event, exists := opened[device.Device.ID+":"+finding.ID]; exists && !event.OccurredAt.IsZero() {
				startedAt = event.OccurredAt
			}
			alerts = append(alerts, model.Alert{
				ID:         "finding:" + device.Device.ID + ":" + finding.ID,
				InstanceID: "finding:" + device.Device.ID + ":" + finding.ID + ":" + timestampIdentity(startedAt) + ":" + finding.Severity,
				DeviceID:   device.Device.ID,
				DeviceName: device.Device.DisplayName,
				Kind:       "finding",
				Severity:   finding.Severity,
				Title:      finding.Title,
				Summary:    finding.Summary,
				Evidence:   "Current evaluated endpoint posture",
				StartedAt:  startedAt,
			})
		}

		var workloads *model.WorkloadInventory
		if device.Snapshot.LinuxBaseline != nil {
			workloads = device.Snapshot.LinuxBaseline.Workloads
		}
		activeServices := activeExpectedServices(device.ExpectedServices, evaluatedAt)
		for _, listener := range logicalListeners(device.Snapshot.Connections) {
			if listener.bindScope == storage.BindScopeLocal || anyExpectedServiceMatches(listener, activeServices, workloads) {
				continue
			}
			startedAt := device.Snapshot.CollectedAt
			for _, observed := range device.Listeners {
				if observed.Present && observed.Protocol == listener.protocol && observed.Port == listener.port && observed.BindScope == listener.bindScope {
					startedAt = observed.AppearedAt
					break
				}
			}
			endpointBaselines := matchingEndpointBaselines(listener, activeServices)
			drift := len(endpointBaselines) > 0
			expiredExpectation := latestExpiredExpectedServiceMatch(listener, device.ExpectedServices, workloads, evaluatedAt)
			owners := ownerEvidence(listener, workloads)
			ownerRevision := "owner-unavailable"
			if len(owners) > 0 {
				canonical := make([]string, 0, len(owners))
				for _, owner := range owners {
					canonical = append(canonical, canonicalOwner(owner, false))
				}
				ownerRevision = strings.Join(canonical, "|")
			}
			endpointName := fmt.Sprintf("%s %d", listener.protocol, listener.port)
			if service := networkServiceLabel(listener.protocol, listener.port); service != "" {
				endpointName += " (" + service + ")"
			}
			kind := "new-service"
			title := "Unreviewed service appeared on " + endpointName
			summary := "A currently listening non-local service is not covered by an owner-approved baseline. This requires review but is not, by itself, evidence of Internet exposure or compromise."
			if expiredExpectation != nil {
				kind = "expired-service-expectation"
				title = "Temporary approval expired for " + endpointName
				summary = "A time-bounded service expectation expired while the listener remained active. Review it again, renew it temporarily, make it permanent, or stop the service."
				startedAt = expiredExpectation.ExpiresAt.UTC()
			} else if drift {
				kind = "service-drift"
				title = "Service attribution changed for " + endpointName
				summary = "The port and bind scope match an owner-approved baseline, but its current process, system-service, or workload attribution does not."
			}
			evidence := bindScopeLabel(listener.bindScope) + " · owner unavailable"
			if len(owners) > 0 {
				evidence = bindScopeLabel(listener.bindScope) + " · " + strings.Join(owners, ", ")
			}
			if expiredExpectation != nil {
				evidence = "Expectation \"" + expiredExpectation.Label + "\" expired " + expiredExpectation.ExpiresAt.UTC().Format(time.RFC3339) + " · " + evidence
			}
			alerts = append(alerts, model.Alert{
				ID:         kind + ":" + device.Device.ID + ":" + listener.key,
				InstanceID: kind + ":" + device.Device.ID + ":" + listener.key + ":" + timestampIdentity(startedAt) + ":" + ownerRevision,
				DeviceID:   device.Device.ID,
				DeviceName: device.Device.DisplayName,
				Kind:       kind,
				Severity:   "medium",
				Title:      title,
				Summary:    summary,
				Evidence:   evidence,
				StartedAt:  startedAt,
			})
		}
	}

	severityOrder := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(alerts, func(left, right int) bool {
		if severityOrder[alerts[left].Severity] != severityOrder[alerts[right].Severity] {
			return severityOrder[alerts[left].Severity] < severityOrder[alerts[right].Severity]
		}
		if !alerts[left].StartedAt.Equal(alerts[right].StartedAt) {
			return alerts[left].StartedAt.After(alerts[right].StartedAt)
		}
		return alerts[left].ID < alerts[right].ID
	})
	return alerts
}

func findingReviewSuppressesAlert(findingID string, reviews []storage.FindingReview, evaluatedAt time.Time) bool {
	for _, review := range reviews {
		if review.FindingID != findingID {
			continue
		}
		switch review.State {
		case "accepted-risk":
			return true
		case "snoozed":
			return review.SnoozedUntil != nil && review.SnoozedUntil.After(evaluatedAt)
		default:
			return false
		}
	}
	return false
}

func logicalListeners(connections []model.NetworkConnection) []logicalListener {
	grouped := make(map[string]*logicalListener)
	for _, connection := range connections {
		state := strings.ToLower(strings.TrimSpace(connection.State))
		if state != "listen" && state != "open" && state != "bound" {
			continue
		}
		protocol := strings.ToUpper(strings.TrimSpace(connection.Protocol))
		if protocol != "UDP" {
			protocol = "TCP"
		}
		scope := listenerBindScope(connection.LocalAddress)
		key := fmt.Sprintf("%s:%d:%s", protocol, connection.LocalPort, scope)
		listener := grouped[key]
		if listener == nil {
			listener = &logicalListener{key: key, protocol: protocol, port: connection.LocalPort, bindScope: scope}
			grouped[key] = listener
		}
		listener.addresses = appendUnique(listener.addresses, normalizeAddress(connection.LocalAddress))
		listener.processes = appendUnique(listener.processes, strings.TrimSpace(connection.ProcessName))
		listener.systemdUnits = appendUnique(listener.systemdUnits, strings.TrimSpace(connection.SystemdUnit))
	}
	listeners := make([]logicalListener, 0, len(grouped))
	for _, listener := range grouped {
		sort.Strings(listener.addresses)
		sort.Strings(listener.processes)
		sort.Strings(listener.systemdUnits)
		listeners = append(listeners, *listener)
	}
	sort.Slice(listeners, func(left, right int) bool { return listeners[left].key < listeners[right].key })
	return listeners
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func listenerBindScope(value string) string {
	address := normalizeAddress(value)
	if address == "" || address == "*" || address == "0.0.0.0" || address == "::" {
		return storage.BindScopeWildcard
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return storage.BindScopeSpecific
	}
	parsed = parsed.Unmap()
	if parsed.IsLoopback() {
		return storage.BindScopeLocal
	}
	if parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return storage.BindScopePrivate
	}
	return storage.BindScopeSpecific
}

func normalizeAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if separator := strings.LastIndex(value, "%"); separator >= 0 {
		value = value[:separator]
	}
	if parsed, err := netip.ParseAddr(value); err == nil {
		return parsed.Unmap().String()
	}
	return strings.ToLower(value)
}

func matchingEndpointBaselines(listener logicalListener, services []storage.ExpectedService) []storage.ExpectedService {
	matching := make([]storage.ExpectedService, 0)
	for _, service := range services {
		if endpointMatches(listener, service) {
			matching = append(matching, service)
		}
	}
	return matching
}

func activeExpectedServices(services []storage.ExpectedService, evaluatedAt time.Time) []storage.ExpectedService {
	active := make([]storage.ExpectedService, 0, len(services))
	for _, service := range services {
		if service.ExpiresAt == nil || service.ExpiresAt.After(evaluatedAt) {
			active = append(active, service)
		}
	}
	return active
}

func latestExpiredExpectedServiceMatch(listener logicalListener, services []storage.ExpectedService, inventory *model.WorkloadInventory, evaluatedAt time.Time) *storage.ExpectedService {
	var latest *storage.ExpectedService
	for index := range services {
		service := &services[index]
		if service.ExpiresAt == nil || service.ExpiresAt.After(evaluatedAt) || !expectedServiceMatches(listener, *service, inventory) {
			continue
		}
		if latest == nil || service.ExpiresAt.After(*latest.ExpiresAt) {
			latest = service
		}
	}
	return latest
}

func endpointMatches(listener logicalListener, service storage.ExpectedService) bool {
	portEnd := service.PortEnd
	if portEnd == 0 {
		portEnd = service.Port
	}
	return service.Protocol == listener.protocol && listener.port >= service.Port && listener.port <= portEnd && (service.BindScope == storage.BindScopeAny || service.BindScope == listener.bindScope)
}

func anyExpectedServiceMatches(listener logicalListener, services []storage.ExpectedService, inventory *model.WorkloadInventory) bool {
	for _, service := range services {
		if expectedServiceMatches(listener, service, inventory) {
			return true
		}
	}
	return false
}

func expectedServiceMatches(listener logicalListener, service storage.ExpectedService, inventory *model.WorkloadInventory) bool {
	if !endpointMatches(listener, service) {
		return false
	}
	ownerConstrained := len(service.ProcessNames) > 0 || len(service.WorkloadNames) > 0 || len(service.SystemdUnits) > 0
	if !ownerConstrained {
		return true
	}
	if !ownerDimensionMatches(listener.processes, service.ProcessNames, true) {
		return false
	}
	if !ownerDimensionMatches(workloadNames(listener, inventory), service.WorkloadNames, false) {
		return false
	}
	if !systemdOwnerDimensionMatches(listener.systemdUnits, service.SystemdUnits, len(service.WorkloadNames) > 0, inventory) {
		return false
	}
	return true
}

func ownerDimensionMatches(observed, expected []string, executable bool) bool {
	if len(observed) == 0 || len(expected) == 0 {
		return len(observed) == len(expected)
	}
	allowed := make(map[string]struct{}, len(expected))
	for _, value := range expected {
		allowed[canonicalOwner(value, executable)] = struct{}{}
	}
	for _, value := range observed {
		if _, exists := allowed[canonicalOwner(value, executable)]; !exists {
			return false
		}
	}
	return true
}

func systemdOwnerDimensionMatches(observed, expected []string, workloadConstrained bool, inventory *model.WorkloadInventory) bool {
	if len(expected) == 0 && workloadConstrained && inventory != nil && strings.EqualFold(inventory.Runtime, "docker") && len(observed) > 0 {
		for _, unit := range observed {
			if canonicalOwner(unit, false) != "docker.service" {
				return false
			}
		}
		return true
	}
	return ownerDimensionMatches(observed, expected, false)
}

func workloadNames(listener logicalListener, inventory *model.WorkloadInventory) []string {
	if inventory == nil {
		return nil
	}
	workloads := make([]string, 0)
	for _, workload := range inventory.Workloads {
		for _, binding := range workload.Ports {
			if !binding.Published || strings.ToUpper(binding.Protocol) != listener.protocol || binding.HostPort != listener.port {
				continue
			}
			address := normalizeAddress(binding.HostAddress)
			if address == "" || address == "0.0.0.0" || address == "::" {
				if listener.bindScope != storage.BindScopeWildcard {
					continue
				}
			} else if !contains(listener.addresses, address) {
				continue
			}
			workloads = appendUnique(workloads, workload.Name)
			break
		}
	}
	sort.Strings(workloads)
	return workloads
}

func ownerEvidence(listener logicalListener, inventory *model.WorkloadInventory) []string {
	owners := make([]string, 0, len(listener.processes)+len(listener.systemdUnits))
	for _, process := range listener.processes {
		owners = append(owners, "process "+process)
	}
	for _, unit := range listener.systemdUnits {
		owners = append(owners, "service "+unit)
	}
	for _, workload := range workloadNames(listener, inventory) {
		owners = append(owners, "workload "+workload)
	}
	sort.Strings(owners)
	return owners
}

func canonicalOwner(value string, executable bool) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if executable {
		value = strings.TrimSuffix(value, ".exe")
	}
	return value
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func bindScopeLabel(scope string) string {
	return map[string]string{
		storage.BindScopeAny:      "Any bind",
		storage.BindScopeLocal:    "This host only",
		storage.BindScopePrivate:  "Private address",
		storage.BindScopeWildcard: "All interfaces",
		storage.BindScopeSpecific: "Specific address",
	}[scope]
}

func networkServiceLabel(protocol string, port int) string {
	return map[string]string{
		"TCP:22":    "SSH",
		"TCP:53":    "DNS",
		"UDP:53":    "DNS",
		"UDP:67":    "DHCP",
		"TCP:80":    "HTTP",
		"TCP:443":   "HTTPS",
		"TCP:445":   "SMB",
		"TCP:3389":  "Remote Desktop",
		"TCP:4070":  "Spotify",
		"TCP:5228":  "push messaging",
		"TCP:8096":  "Jellyfin",
		"TCP:8443":  "HAVEN",
		"UDP:51822": "WireGuard",
	}[fmt.Sprintf("%s:%d", strings.ToUpper(protocol), port)]
}

func timestampIdentity(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
