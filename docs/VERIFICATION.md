# HAVEN verification strategy

HAVEN treats security statements as testable claims. A green test does not prove that an endpoint is uncompromised; it shows that the implementation behaves according to a documented rule for the supplied evidence.

## Claim-to-test map

| Claim | Evidence boundary | Automated guardrail |
| --- | --- | --- |
| A 15-minute agent is not stale during ordinary scheduling jitter | Server-owned freshness policy and authenticated `last_seen_at` | Go storage boundary tests at 16 and 21 minutes; runtime API test prevents the browser threshold from drifting from the server |
| IPv4 and IPv6 wildcard sockets represent one logical service when protocol, port, and scope match | Current endpoint report | Frontend listener-grouping tests require one logical listener with two raw sockets |
| An owner-constrained expectation cannot hide a differently owned service | Current process, systemd-unit, or sanitized workload attribution plus owner-approved configuration | Frontend tests reject extra processes, wrong services, absent workload evidence, wrong protocol, and wrong bind scope |
| A mirrored enrolled-device connection is one relationship | Latest authenticated reports from both endpoints | Frontend relationship tests require correct inbound SSH direction and one canonical socket identity |
| Public remote addresses are not exposed by the network summary | Live connection report | Frontend privacy test requires the relationship projection to say `Internet` and contain no destination address |
| A private peer seen in traffic is not automatically trusted | Current private destination and explicit enrolled inventory | Frontend test requires `observed` rather than `enrolled` |
| A resolved finding is not a current alert | Current evaluated snapshot plus lifecycle events | Alert tests ignore historical resolved events when the finding is absent from current posture |
| A changed service owner is distinct from a new port | Approved endpoint baseline plus current attribution | Alert tests require `service-drift` when protocol, port, and scope match but owner evidence does not |
| Desktop notifications do not repeat on every poll | Stable alert identity plus recurrence-specific instance identity in browser-local storage | Notification tests require one notification per medium/high instance, no low interruption, and recurrence after resolution |
| Historical storage does not become a household activity log | Persisted observation payload | Go storage tests require live connections and workload metadata to remain memory-only |
| Public source stays portfolio-safe | Staged repository content | The PowerShell public-repository scan runs before commits and in CI |

## Required local gates

```powershell
go test .\...
go vet .\...

Set-Location .\web
npm ci
npm run test:coverage
npm run build
npm audit --audit-level=high
Set-Location ..

pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

The frontend coverage gate applies to the security projection modules rather than presentational React markup. CI additionally runs Go's race detector across every package. Production deployment remains blocked until all gates pass and an immutable image is published for the exact commit.

## Interpretation limits

- Endpoint-reported facts may be false if that endpoint is already compromised.
- A listening socket does not establish router reachability or public Internet exposure.
- An expected service is an owner decision, not a malware exception or a guarantee of safety.
- An alert is a prompt to review a changed fact; it is not a threat verdict.
- Browser notifications operate only while HAVEN is open. Background notification delivery requires a separately reviewed service boundary.
