# HAVEN verification strategy

HAVEN treats security statements as testable claims. A green test does not prove that an endpoint is uncompromised; it shows that the implementation behaves according to a documented rule for the supplied evidence.

## Claim-to-test map

| Claim | Evidence boundary | Automated guardrail |
| --- | --- | --- |
| One missed 15-minute agent run does not create a false stale alert | Server-owned freshness policy and authenticated `last_seen_at` | Go storage boundary tests at 34 and 36 minutes; runtime API test prevents the browser threshold from drifting from the server |
| A transient report failure does not silently discard a valid observation | Certificate-bound observation ID and monotonic sequence | Agent integration tests require a bounded retry after a transient hub response; storage tests accept only the exact duplicate idempotently and reject conflicting sequence reuse |
| Hub readiness is not declared when persistence is unavailable | SQLite connection required by every useful hub operation | Health endpoint tests close persistence and require HTTP 503 plus `not-ready` rather than an unconditional success |
| The displayed release can be tied to the deployed source | Shared build version and linker-injected revision | Health/runtime API tests require both values; frontend Settings and footer render the authenticated runtime identity |
| A reporting endpoint can be tied to a bounded agent build | Certificate-bound observation plus optional agent metadata | Agent integration and SQLite tests retain version, revision, installation kind, schema, capabilities, and notice count; validation rejects duplicate or unbounded metadata |
| Updating the hub does not strand existing enrolled endpoints | Optional metadata extension on observation schema 2 | Storage and integration tests continue accepting a report with no agent metadata and the fleet UI presents it as legacy maintenance |
| Build drift does not become a threat claim | Server-derived compatibility state separate from device freshness and findings | Go and TypeScript lifecycle tests require current/legacy/drift classifications without changing endpoint status or active alerts |
| Endpoint artifacts correspond to an explicit source revision | Cross-platform build matrix, embedded revision, manifest, and SHA-256 file | CI builds four reporter variants from `GITHUB_SHA`, verifies Windows GUI subsystem behavior, and uploads only after public verification succeeds |
| Account notes do not become plaintext database or audit records | Whole-profile AES-256-GCM envelope plus privacy-bounded audit contract | Go service tests inspect raw SQLite records for provider, identifier, and note fragments; API tests require decrypted round trips while audit details omit all account content |
| Account ciphertext cannot be reassigned to another profile | Opaque profile ID authenticated as encryption context | Go tests copy valid ciphertext under a different identity and require decryption to fail closed |
| A long-lived dashboard session cannot silently retrieve private account notes | Fresh WebAuthn reauthentication plus a session-bound scoped grant | Go tests require a grant for account reads, reject the same token under another session, enforce idle expiration, and revoke it on account lock or sign-out; rendered UI tests require a locked gate before profiles load |
| The account notebook has no secret-ingestion contract | Strict profile schema and bounded free text | API tests reject unknown password fields and recognizable authenticator setup links; UI tests require a prominent no-secrets warning and verify there is no password-value input |
| Structured review facts do not weaken the secret boundary | Bounded encrypted review-detail lines | Go validation tests reject recognizable secret formats and duplicate facts; ciphertext tests require both review facts and context notes to remain absent from raw storage |
| Provider branding does not create a tracking request | Locally bundled icon paths plus a local monogram fallback | Rendered UI tests require the known-provider SVG mark; the implementation contains no remote logo URL |
| Browser review cannot become cookie or history surveillance | Bounded manifest/state projection with no private-content fields | Collector tests require serialized output to omit raw extension IDs and host patterns; the model rejects unknown permission text and raw site patterns; storage tests strip the entire browser object from historical observations |
| Extension capability wording does not become a malware verdict | Browser-declared permissions reduced to reviewed categories | Posture tests summarize counts and disabled platform protection without creating browser findings; rendered UI tests state the interpretation limit and never render correlation fingerprints |
| Browser metadata cannot exhaust or inject arbitrary facts into the hub | File-size/profile/extension limits plus strict authenticated-message validation | Go tests reject oversized or multi-value JSON, invalid fingerprints, duplicate identities, unrecognized capabilities, and out-of-schema access categories |
| The native dashboard cannot invoke local Node, filesystem, shell, or arbitrary IPC capabilities | Sandboxed Electron renderer with no preload bridge | Desktop and frontend contract tests require Node integration off, context isolation and sandboxing on, no preload/IPC/shell API, exact-origin navigation, denied popups, and explicit permission handling |
| Packaged desktop protections match the documented boundary | Electron executable fuse table | CI builds the Windows package and reads the produced executable, requiring Node launch and injection fuses disabled plus encrypted cookies, embedded-ASAR integrity, and ASAR-only loading enabled |
| Installing HAVEN does not create a second trust boundary | Same-origin standalone manifest plus the existing service worker | Manifest contract tests require root-scoped same-origin launch paths and local icons; hook tests require the browser-owned install event before offering installation |
| Installability does not create an authenticated offline cache | Push-only service worker | Contract tests reject a fetch handler or Cache API use, while service-worker registration tests require no notification-permission call |
| Account guidance follows only owner-recorded facts | Deterministic checklist projection | Go tests pin suggestions for disabled two-step verification, reused passwords, missing recovery, missing backup-code readiness, weak-only factors, unknown fields, and stale reviews without producing threat alerts |
| Portfolio account examples cannot expose or mutate real data | Server-owned synthetic fixtures and demo mutation refusal | API and rendered UI tests require invented demo identities, exclude live account text, and hide editing controls |
| Direct navigation does not lose console state or bypass route validation | History API routes plus server index fallback | Rendered React tests exercise top-level, device, and deep-linked history routes; parser tests cover encoded identifiers, unsupported sections, and malformed escapes |
| IPv4 and IPv6 wildcard sockets represent one logical service when protocol, port, and scope match | Current endpoint report | Frontend listener-grouping tests require one logical listener with two raw sockets |
| An owner-constrained expectation cannot hide a differently owned service | Current process, systemd-unit, and sanitized workload attribution plus owner-approved configuration | Go and TypeScript consume the same contract fixtures and require every observed owner category to be approved, including mixed-owner listeners; Docker's own service unit is accepted as runtime support evidence for legacy Docker-workload rules, while unrelated services still drift; only an explicitly owner-free port rule is unconstrained |
| A mirrored enrolled-device connection is one relationship | Latest authenticated reports from both endpoints | Frontend relationship tests require correct inbound SSH direction and one canonical socket identity |
| Public remote addresses are not exposed by the network summary | Live connection report | Frontend privacy test requires the relationship projection to say `Internet` and contain no destination address |
| A private peer seen in traffic is not automatically trusted | Current private destination and explicit enrolled inventory | Frontend test requires `observed` rather than `enrolled` |
| The browser and background delivery use the same alert policy | Authenticated `/api/alerts` response from the hub-owned projector | Go projector and API contract tests require current findings, lifecycle start time, freshness, and listener state to appear through the server projection |
| A resolved finding is not a current alert | Current evaluated snapshot plus lifecycle events | Go alert tests ignore historical events when the finding is absent from current posture and select the latest open recurrence when it returns |
| Owner review changes interruption, not observed fact | Current finding plus the latest owner review and hub clock | Go policy/API tests suppress accepted-risk findings and active snoozes; frontend tests keep them out of reminder and review-count surfaces while retaining acknowledged findings and expired snoozes |
| Remote service presence is not itself a threat | Windows and Linux effective service posture | Go policy tests require unsafe properties for remote-access findings; a running Windows OpenSSH service is configured inventory, matching Linux policy |
| Physical-loss posture is not mislabeled as network or malware risk | Windows BitLocker status | Go policy tests retain BitLocker state as neutral data-at-rest inventory without deriving an actionable finding when it is off |
| Appliance monitoring cannot become an accidental LAN scanner | Private managed-appliance configuration | Go configuration tests reject hostnames, ranges, public addresses, UDP probes, duplicate endpoints, and unknown discovery-like fields |
| A transient or optional appliance outage does not create notification noise | Current hub-observed appliance checks | Go alert tests require two consecutive required-service failures, collapse a fully unreachable appliance to one alert, and keep optional services quiet |
| Appliance credentials cannot enter configuration, observations, or history | Private file-backed secrets plus current normalized health report | Strict JSON tests reject inline communities and relative secret paths; the model has no credential field; SQLite tests persist only normalized current evidence and bounded error classes |
| Partial NAS telemetry is not overstated as healthy | Explicit per-category coverage from independent SNMP and SSH sources | Go and TypeScript tests require partial, unsupported, and unavailable evidence to remain non-healthy without fabricating a threat |
| NAS health thresholds stay consistent and reviewable | Current normalized disk, RAID, volume, and thermal evidence | Shared Go policy tests pin exact capacity and temperature boundaries; alert tests require degraded/rebuilding RAID and failed SMART to remain actionable |
| Appliance helper output remains privacy bounded | Fixed helper schema and allowlisted collectors | Tests require the JSON schema to omit serial, share, account, community, password, and address fields; parsers retain only top-level volumes and physical/RAID devices |
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
| Historical storage does not become a household activity log | Persisted observation payload | Go storage tests require live connections, workload metadata, and browser inventory to remain memory-only |
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

Set-Location .\desktop
npm ci
npm test
npm run check
npm audit --audit-level=high
npm run dist:windows
npm run verify:fuses
Set-Location ..

pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

The frontend coverage gate includes every executable TypeScript and React module, with higher per-module thresholds for the security-sensitive network and browser-push projections. Rendered UI tests exercise navigation and automatically detectable serious accessibility problems. Go tests cover the server-owned alert, storage, retry, readiness, and delivery policies. CI additionally runs Go's race detector, the Go vulnerability database scanner, and CodeQL for Go and TypeScript. Production deployment remains blocked until all gates pass and an immutable image is published for the exact commit.

Web Push behavior follows the [W3C Push API](https://www.w3.org/TR/push-api/), [RFC 8030 delivery protocol](https://www.rfc-editor.org/rfc/rfc8030), and [RFC 8291 message encryption](https://www.rfc-editor.org/rfc/rfc8291). The service worker uses the browser's standard push event and persistent notification boundary; it does not cache HAVEN's authenticated pages or observations.

## Interpretation limits

- Endpoint-reported facts may be false if that endpoint is already compromised.
- A listening socket does not establish router reachability or public Internet exposure.
- An expected service is an owner decision, not a malware exception or a guarantee of safety.
- An alert is a prompt to review a changed fact; it is not a threat verdict.
- A push-service acceptance response proves only that the service accepted the encrypted message, not that a person saw the notification.
- Web Push hides payload contents from the delivery service but does not hide subscription or delivery metadata.
- Browser and operating-system support, background policies, notification permissions, and lock-screen settings can still prevent display.
