# HAVEN threat model

This document defines HAVEN's security boundary before it becomes a multi-device or privileged application.

## Assets to protect

- Security observations about household devices
- Process names, addresses, ports, services, and installed-software metadata
- Future account-security posture records
- Device identities and future client certificates
- The integrity of findings, policies, audit history, and updates

HAVEN must not store passwords, session cookies, authenticator seeds, recovery-code contents, or general-purpose remote-administration credentials.

## Current boundary

Milestone 0.10 performs continuous collection, explainable baseline evaluation, privacy-bounded finding and listener transition tracking, authenticated device reporting, owner-reviewed expected-service classification, explicit report freshness/lifecycle presentation, hub-owned fact-based active-alert derivation, opt-in encrypted Web Push delivery, live Docker workload and Linux systemd-unit attribution, a derived network-wide overview, and an authenticated local action boundary. The overview distinguishes enrolled devices from observed-only private endpoints and grouped Internet relationships. It uses only the latest live connection reports, performs no active discovery, and persists no remote endpoint or relationship history. Suggested baseline entries are derived only from bounded platform roles and the current live observation; nothing is classified until the owner approves it. Alerts are review prompts based on current evidence, not intrusion verdicts or Internet-reachability claims. On Windows, the collector launches one fixed, internally defined PowerShell script with no user-controlled commands or parameters. The two available controls also select fixed internal PowerShell commands for a Defender quick scan or security-intelligence update; browser text is never interpolated into them.

The owner registers one or more discoverable passkeys through the cross-platform WebAuthn standard. Windows Hello, platform biometric providers, synchronized phone passkeys, and hardware security keys are authenticator choices rather than HAVEN dependencies. The first passkey requires a one-time local CLI code; the same short-lived mechanism provides local recovery. A signed-in owner can add or remove passkeys, but cannot remove the final credential without a replacement.

Passkey credential data is encrypted at rest with a random key outside the repository. Session and anti-forgery tokens are random; only hashes are stored in SQLite. Trusted-browser sessions expire after 30 days. Mutating routes require an authenticated session, an exact configured Origin, and a matching anti-forgery cookie/header pair. Sensitive actions additionally require a fresh passkey assertion that issues a two-minute, single-use authorization bound to the current session and exact capability. Authentication attempts are rate limited.

The agent endpoint uses TLS 1.3. Enrollment tokens are random, short-lived, one-time values; each accepted certificate has a distinct key and device identity. Observation identity, device identity, sequence, timestamp, schema, media type, body size, and request rate are validated. Revoked devices cannot submit reports.

The Windows scheduled reporter runs as the enrolled interactive user at that user's highest available run level so read-only collectors can inspect protected posture signals. It uses a separate GUI-subsystem binary so Task Scheduler does not allocate a visible console. Fixed Windows child processes set hidden startup state and `CREATE_NO_WINDOW`; those presentation flags grant no additional authority. The interactive console binary remains separate so enrollment errors and diagnostic output are not hidden from the owner.

SQLite and private keys are stored outside the source tree. Historical records exclude live connection and workload details and expire after a bounded period. Development Compose publishes only the dashboard to host loopback. The production profile binds exact private addresses for its dashboard, DNS, and agent listeners and does not expose them through public ingress.

Baseline history contains only bounded posture and counts. HAVEN does not retain administrator names, Windows update titles, Defender threat names, detected file or resource paths, BitLocker recovery keys, or other recovery material. A finding is a local rule evaluation, not proof of compromise or a substitute for native security guidance.

The activity ledger records only finding-opened and finding-resolved transitions using the already bounded finding text. Listener history is a separate bounded baseline containing protocol, port, bind scope, and timestamps; raw addresses, remote endpoints, process history, systemd ownership history, and payloads are not persisted. An approved expected-service record may contain a small owner-selected process, workload, or systemd-unit allowlist and an optional expiration of at most 30 days, but this is configuration metadata rather than observation history; audit summaries deliberately omit those names. Expiration is enforced by the hub and changes only HAVEN's interpretation—it never stops a process, opens a port, or edits a firewall. Active alerts are recomputed by the hub and are not persisted as a second history. Durable delivery records contain identities, bounded result classifications, attempt times, and status—not alert text or network evidence.

Background delivery is disabled until an authenticated owner explicitly grants browser permission and registers a destination through the anti-forgery-protected API. The Web Push capability endpoint and subscription keys are encrypted at rest with a separate random key outside SQLite. The push service receives an encrypted payload and can observe delivery metadata. To limit lock-screen disclosure, the plaintext contains only HAVEN's name, the owner-assigned device label, severity, and a prompt to open the authenticated dashboard; finding titles, summaries, ports, and endpoint evidence are excluded. Completed receipts expire after a bounded period. HAVEN does not register a privileged tray process or browser extension.

The network overview is a browser-side projection of the latest authenticated reports. Address matches can explain likely enrolled-device relationships, but they are not cryptographic proof that the peer at an address is the enrolled machine. Unmatched private endpoints remain visibly "observed only," are never promoted to trusted inventory, and are not retained as asset history in this milestone. Internet destinations are grouped to reduce noise rather than classified as benign.

Managed-appliance monitoring is opt-in deployment configuration, not LAN discovery. Configuration parsing accepts only literal private unicast addresses, explicit TCP ports, bounded identifiers, and a fixed schema. The hub retains the declared address plus current reachability, bounded error classification, timestamps, and presented certificate metadata. It does not send credentials, issue application requests, retain response bodies, inspect shares, or promote the appliance to authenticated endpoint status. TLS certificate collection deliberately completes an observation-only handshake and then reports system-chain and address-name validation separately; a private appliance's name mismatch is factual evidence rather than an automatic compromise claim.

## Principal threats

### A malicious website accesses the local API

Current mitigations:

- Bind the development hub to loopback.
- Do not enable CORS.
- Require a WebAuthn owner session for observation and control APIs while keeping only health and authentication ceremonies public.
- Require exact-origin and anti-forgery validation for every state-changing dashboard request.
- Return no authentication secrets.
- Send a restrictive Content Security Policy and related browser headers.
- Protect push destination enrollment and removal with the same authenticated exact-origin and anti-forgery boundary as other owner mutations.

Passkey verification provides the session boundary, and the current UI requires explicit confirmation for each Defender action. A later remote-action protocol must add fresh reauthorization and an independently authenticated native agent capability; loopback and private networking are not authentication.

### A compromised dashboard becomes a remote-administration tool

Current mitigations and requirements:

- Never expose arbitrary command, script, file-write, registry-write, or process-launch APIs.
- Model actions as provider-advertised named capabilities with strict schemas. The current Windows provider contains exactly two Defender operations; other operating systems require separate native providers.
- Separate read-only collection from any privileged helper.
- Require confirmation and reauthorization for sensitive operations.
- Give changes an expiry or rollback path where practical.
- Record the requester, target device, fixed action, parameters, and result.

### A compromised hub becomes the keys to the kingdom

Current and planned mitigations:

- Agents initiate outbound mutually authenticated connections.
- Each device receives a unique, revocable identity; enrollment credentials are one-time and short-lived.
- The hub CA key can authorize device identities and is therefore protected outside the repository, backed up deliberately, and never exposed through an API.
- Collection and privileged execution remain separate components.
- Privileged helpers accept only allowlisted actions and never a shell command.
- The hub stores no user passwords or device-administrator credentials.
- Browser access has independent application authentication and authorization.
- Push capability endpoints, subscription keys, and the VAPID private key stay in the private state directory, never the source repository or an API response.

### A compromised endpoint lies to HAVEN

An agent running on a compromised endpoint cannot be assumed to report trustworthy state. HAVEN will distinguish endpoint-reported observations, hub-observed reachability and certificate state, and independent network-sensor observations. Conflicts remain visible instead of being silently reconciled.

The native Ubuntu reporting service runs as the existing unprivileged deployment account because production automation cannot create a dedicated system identity without separate host authorization. Its user unit denies access to both Docker socket paths, exposes its home directory read-only except for the agent identity directory, enables `no-new-privileges`, and applies the filesystem, namespace, syscall, and kernel-tunable restrictions supported by an unprivileged systemd user manager. It never joins a privileged container and receives no command-execution channel from the hub. Linux socket attribution retains only a validated terminal `.service` or `.socket` name from live cgroup metadata or an exact match in the unprivileged user manager's bounded network-socket list. Generic user-manager identities are ignored, filesystem sockets, full cgroup paths, and command lines are discarded, and no unit ownership is written to observation history.

Docker socket access is effectively root-equivalent. A distinct one-shot inventory service receives that access, but only the local Unix address family; it has no IP-network access and exits before the reporter starts. Its fixed subcommand issues one container-list request and atomically writes a mode-0600 JSON file containing only allowlisted workload and port-attribution fields. The reporter validates that file as untrusted input. The exporter cannot receive browser parameters, send reports, invoke arbitrary Docker endpoints, or expose a control API. A compromised exporter could still control Docker while it runs, so this isolation reduces exposure but does not make socket access intrinsically safe.

### Collection invades household privacy

Mitigations and requirements:

- Obtain explicit consent before installing an agent on another person's device.
- Show exactly which fields each collector gathers.
- Keep live connection and workload details out of historical storage.
- Do not collect packet payloads, browsing content, keystrokes, screenshots, or documents.
- Allow a device owner to pause collection and revoke the device.
- Apply retention limits and support deletion by device.

### The hub container gains host control

Current mitigations:

- Run as a non-root user with a read-only root filesystem.
- Drop every Linux capability and enable `no-new-privileges`.
- Mount only the application-data volume and a bounded temporary filesystem.
- Avoid host networking, host process namespaces, devices, Docker socket access, and privileged mode.
- Do not attach persistent self-hosted GitHub Actions runners to the public repository. GitHub-hosted CI publishes immutable images; only the private HomeOps repository can schedule the fixed production deployment.

The native agent is not placed inside the hub container because observing a host from a container would require weakening this boundary.

### Supply-chain or update compromise

Planned mitigations:

- Pin direct dependencies and commit lock files.
- Run vulnerability and static-analysis checks in continuous integration.
- Keep the production image minimal and generate a software bill of materials for releases.
- Sign release artifacts and verify agent updates before installation.
- Never auto-install an unsigned agent, collector, or policy bundle.

### Background notification delivery becomes data exfiltration or SSRF

Current mitigations:

- Keep Web Push disabled by default and disclose that the browser-vendor service observes delivery metadata.
- Use standards-based payload encryption and keep lock-screen text generic.
- Encrypt subscription capability endpoints and key material at rest; never return endpoints through the status API or logs.
- Accept only HTTPS hostname endpoints on the standard port, resolve every address before dialing, reject private, loopback, link-local, multicast, and non-global destinations, disable proxy routing, and refuse redirects.
- Apply a fixed destination limit, payload schema, delivery timeout, maximum retry count, and exponential backoff.
- Remove destinations that return `404` or `410`; expire queued work when its alert instance is no longer current.
- Do not place arbitrary URLs, actions, scripts, credentials, finding details, or remote endpoints in notification payloads.

### Alert logic creates false certainty or notification fatigue

Current mitigations:

- Derive alerts only from named evidence sources: authenticated freshness state, current evaluated findings, listener appearance state, and owner-approved service expectations.
- Describe an unreviewed listener as a review requirement, never as malware or proof of public exposure.
- Keep low-severity items visible without desktop interruption.
- Deduplicate medium/high notifications with durable per-destination receipts keyed by stable alert identity plus recurrence-specific evidence.
- Publish the server-owned freshness threshold through the authenticated runtime API instead of duplicating it in browser logic.
- Test direction, deduplication, privacy projection, baseline ownership, lifecycle state, alert severity, subscription validation, baselining, retry delay, expiry, generic payload content, and notification recurrence in CI with enforced coverage thresholds.

## Security gates

Remote ingestion, remote access, privileged actions, agent auto-update, account-provider OAuth, and central deployment each require a design review and tests before release. No feature may bypass Defender tamper protection or disable a native firewall service.
