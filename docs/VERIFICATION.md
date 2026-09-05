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
| Provider-session review does not become provider access | Four fixed owner-reported checks plus static official links | Go tests validate the bounded statuses, dates, and checklist combinations; UI tests require the no-cookie/no-token boundary and known-provider link; no provider credential or OAuth field exists |
| Provider-session details remain encrypted and backward compatible | Existing whole-profile AES-GCM envelope with optional new fields | Ciphertext tests require session statuses/checks to remain absent from SQLite; legacy records without session fields normalize to `unknown` rather than failing decryption |
| Provider branding does not create a tracking request | Locally bundled icon paths plus a local monogram fallback | Rendered UI tests require the known-provider SVG mark; the implementation contains no remote logo URL |
| Browser extension review cannot expose raw identifiers or browsing content | Bounded manifest/state projection with no private-content fields | Collector tests require serialized output to omit raw extension IDs and host patterns; the model rejects unknown permission text and raw site patterns; storage tests strip the entire browser object from historical observations |
| Chrome site-data review cannot become credential extraction | Fixed read-only aggregate query with no credential columns | Collector tests seed recognizable cookie names, plaintext values, encrypted bytes, account email, and account display name, then require all except the explicit Chrome profile label to be absent from serialized output while domain/count metadata remains available; the same test requires Chrome's chooser label to override a generic profile-local label, and model tests enforce profile, domain, count, time, and global bounds |
| Routine Chrome site-data review cannot become durable browsing history | Current authenticated observation only | Storage tests strip the complete browser-security object before SQLite history; the extension baseline and evaluated posture ignore profile labels and cookie domains; UI tests require the live-only boundary |
| Owner curation cannot silently become a cookie vault | Separate authenticated-encryption envelope containing only a profile fingerprint, domain, and one of four fixed decisions | Service tests scan SQLite files to require domains and decisions to be absent from plaintext; API tests reject unknown credential-shaped fields, require current live evidence before a new decision, omit domains from audit history, and support explicit removal |
| Cookie metadata is not overstated as a logged-in session | Domain-level evidence with explicit session-signal, owner classifications, and conservative age heuristics | Pure-function tests require the stronger signal tier to combine session-scoped, Secure, and HTTP-only aggregates, automatically assign every site to one evidence group without input, keep age review independent, and exclude protected or deferred sites from cleanup; rendered UI tests require all three groups, all four decisions, optional search, explicit reset, the distinction between cookie presence and provider authentication, and guided cleanup wording; no provider request, logout, or cookie-clearing capability exists |
| An extension change cannot be swallowed by a failed report or fabricated beyond current evidence | Endpoint baseline committed only after hub acceptance plus strict matching against current extension facts | Session-watch tests require a silent first baseline, quiet version-only changes, delayed commit, and bounded capability deltas; model tests reject unmatched names, access, or permissions |
| Extension capability wording does not become a malware verdict | Browser-declared permissions reduced to reviewed categories | Posture tests create review findings only for defined meaningful changes, assign severity from explicit capability evidence, and rendered UI tests state the interpretation limit without rendering correlation fingerprints |
| Chrome session-defense evidence does not become cookie surveillance | Two fixed policy values plus a bounded seven-day event count | Windows collector contract tests require the exact policy names, Chrome-source Application event 257, a 50-event cap, and no event message/property serialization; model tests enforce count/state consistency |
| Chrome verification failures are not overstated as compromise | Count-only operating-system evidence | Posture and rendered UI tests require explicit wording that the signal can be incompatibility or an attempted bypass and is not proof of malware |
| Browser hardening does not turn ordinary logged-in use into a failing posture | Deterministic projection of existing protection and extension evidence | Pure-function tests require radically different cookie volumes and sign-in hints to produce identical hardening results; rendered UI states that logged-in sites and cookie counts do not affect the result |
| A high-capability extension is reviewable without being labeled malicious | Validated friendly name, browser identity, site-access category, and allowlisted capabilities | Pure-function and rendered UI tests summarize required and optional exposure separately, exclude disabled extensions, require a one-time-review boundary, and forbid a malware or threat verdict in the projection |
| Incident guidance does not become a recurring alarm | Static, trigger-bounded response sequence | Rendered UI requires named concrete triggers, explicitly rejects normal logged-in sessions as a trigger, and presents containment, clean-device recovery, investigation, and reimaging as a finite sequence |
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
| Reusable presentation does not inherit one household's device, workload, or custom VPN labels | Runtime UI and alert label maps | Frontend and Go portability tests reject personal runtime names and require deployment-specific ports to remain unlabeled until owner review |
| An installed desktop client cannot be redirected by runtime environment changes | Build-generated exact HTTPS origin module | Desktop tests reject HTTP, credentials, paths, queries, and fragments; the frontend package contract requires the generated origin to be included in the ASAR boundary |
| Release-number drift is not confused with protocol incompatibility | Server validation of the observation schema followed by fleet presentation | Go and frontend lifecycle tests require an accepted different-version reporter to remain healthy and protocol compatible without an update review |
| Diagnostics cannot become a private-configuration export | Fixed check schema containing conclusions and public guidance only | Go redaction tests seed private paths, origins, device labels, identities, and key contents, then require both text and JSON output to omit them |
| Running doctor cannot initialize, migrate, repair, or enroll | Offline file inspection for the hub and existing-identity validation for the agent | Command tests point doctor at absent state and require no directory or identity to be created; database-header tests avoid the migrating application store |
| Certificate presence is not mistaken for a valid identity | Matching key pairs and current X.509 chain verification | Diagnostic tests construct a valid hub authority and enrolled client, while missing or invalid continuity material fails closed |
| Operational diagnostics remain owner-only and ephemeral | Authenticated API route with no-store response policy | Hub tests require authentication when configured, reject anonymous reads, and require `Cache-Control: no-store`; rendered UI tests exercise the System & Recovery workspace |
| Recovery guidance does not imply that public source restores private state | Fixed separation of product, deployment, and state layers | Go tests require the redacted plan to distinguish a complete matching state restore from private-network reconfiguration and agent re-enrollment |

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
