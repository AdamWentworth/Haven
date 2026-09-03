# HAVEN verification strategy

HAVEN treats security statements as testable claims. A green test does not prove that an endpoint is uncompromised; it shows that the implementation behaves according to a documented rule for the supplied evidence.

## Claim-to-test map

| Claim | Evidence boundary | Automated guardrail |
| --- | --- | --- |
| A 15-minute agent is not stale during ordinary scheduling jitter | Server-owned freshness policy and authenticated `last_seen_at` | Go storage boundary tests at 16 and 21 minutes; runtime API test prevents the browser threshold from drifting from the server |
| IPv4 and IPv6 wildcard sockets represent one logical service when protocol, port, and scope match | Current endpoint report | Frontend listener-grouping tests require one logical listener with two raw sockets |
| An owner-constrained expectation cannot hide a differently owned service | Current process, systemd-unit, and sanitized workload attribution plus owner-approved configuration | Go and TypeScript consume the same contract fixtures and require every observed owner category to be approved, including mixed-owner listeners; Docker's own service unit is accepted as runtime support evidence for legacy Docker-workload rules, while unrelated services still drift; only an explicitly owner-free port rule is unconstrained |
| A mirrored enrolled-device connection is one relationship | Latest authenticated reports from both endpoints | Frontend relationship tests require correct inbound SSH direction and one canonical socket identity |
| Public remote addresses are not exposed by the network summary | Live connection report | Frontend privacy test requires the relationship projection to say `Internet` and contain no destination address |
| A private peer seen in traffic is not automatically trusted | Current private destination and explicit enrolled inventory | Frontend test requires `observed` rather than `enrolled` |
| The browser and background delivery use the same alert policy | Authenticated `/api/alerts` response from the hub-owned projector | Go projector and API contract tests require current findings, lifecycle start time, freshness, and listener state to appear through the server projection |
| A resolved finding is not a current alert | Current evaluated snapshot plus lifecycle events | Go alert tests ignore historical events when the finding is absent from current posture and select the latest open recurrence when it returns |
| A changed service owner is distinct from a new port | Approved endpoint baseline plus current attribution | Go alert tests require `service-drift` when protocol, port, and scope match but owner evidence does not |
| Temporary service trust ends without an open browser and can be renewed safely | Hub clock plus SQLite expectation expiration | Storage tests require expiration and renewal to survive a hub restart, API tests bound temporary trust to 30 days, Go alert tests require each expiration to create a distinct review lifecycle, and TypeScript tests fail closed for expired or invalid timestamps |
| A dynamic Avahi port range does not trust unrelated high ports | Current UDP listener ownership and Linux ephemeral-port bounds | Frontend suggestion tests require every grouped listener to be owned by `avahi-daemon.service` and reject an unrelated owner in the same range |
| Enabling notifications does not replay existing alerts | Current medium/high instances at destination creation | Delivery tests require those instances to receive `baseline` receipts without invoking a sender |
| Notifications do not repeat after a hub restart or every-minute evaluation | Stable alert identity plus recurrence-specific instance identity and per-destination SQLite receipt | Delivery tests require one notification per instance and a new notification only when recurrence identity changes |
| Low-severity review items do not interrupt | Server-owned current severity | Delivery tests mix low and medium alerts and require calls only for the medium instance |
| A transient push outage does not create a tight retry loop | Durable attempt count and `next_attempt_at` | Delivery tests require no second attempt before the one-minute first backoff and a retry when it becomes due |
| An expired browser endpoint does not remain active | Push-service `410 Gone` response | Delivery tests require the encrypted destination and cascading receipts to be removed |
| Push cannot target a literal or resolved private address | Validated HTTPS hostname plus guarded outbound dial | Validation tests reject literal-IP endpoints and private, loopback, and link-local resolved addresses |
| Lock-screen content does not expose finding details | Fixed server-generated payload schema | Delivery tests require the title and summary to be absent and the generic open-HAVEN prompt to be present |
| Push capability endpoints are not stored or returned as plaintext | AES-GCM subscription ciphertext plus endpoint hash | Notification tests inspect stored/status records and require the capability hostname to remain absent |
| Historical storage does not become a household activity log | Persisted observation payload | Go storage tests require live connections and workload metadata to remain memory-only |
| Scheduled Windows reporting does not allocate a console | GUI-subsystem reporter plus Windows child-process creation flags | Windows CI tests require hidden startup state and `CREATE_NO_WINDOW`, then inspects the built reporter's PE subsystem before an image may publish |
| Public source stays portfolio-safe | Staged repository content | The PowerShell public-repository scan runs before commits and in CI |

## Required local gates

```powershell
go test .\...
go vet .\...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

Set-Location .\web
npm ci
npm run test:coverage
npm run build
npm audit --audit-level=high
Set-Location ..

pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

The frontend coverage gate applies to the live network and browser-protocol modules rather than presentational React markup. Go tests cover the server-owned alert and delivery policy. CI additionally runs Go's race detector and the Go vulnerability database scanner across every reachable package. Production deployment remains blocked until all gates pass and an immutable image is published for the exact commit.

Web Push behavior follows the [W3C Push API](https://www.w3.org/TR/push-api/), [RFC 8030 delivery protocol](https://www.rfc-editor.org/rfc/rfc8030), and [RFC 8291 message encryption](https://www.rfc-editor.org/rfc/rfc8291). The service worker uses the browser's standard push event and persistent notification boundary; it does not cache HAVEN's authenticated pages or observations.

## Interpretation limits

- Endpoint-reported facts may be false if that endpoint is already compromised.
- A listening socket does not establish router reachability or public Internet exposure.
- An expected service is an owner decision, not a malware exception or a guarantee of safety.
- An alert is a prompt to review a changed fact; it is not a threat verdict.
- A push-service acceptance response proves only that the service accepted the encrypted message, not that a person saw the notification.
- Web Push hides payload contents from the delivery service but does not hide subscription or delivery metadata.
- Browser and operating-system support, background policies, notification permissions, and lock-screen settings can still prevent display.
