# HAVEN architecture

## Direction

HAVEN is a browser-first, agent-based personal security observatory.

```text
Windows agent ─┐
Linux agent ───┼── outbound mutually authenticated observations ──> HAVEN Hub
macOS agent ───┘                                                        │
                                                                        ├── SQLite
Private browser clients ─────────── private HTTPS ──────────────────────┘
        ▲                                                               │
        └──── encrypted Web Push via browser-vendor push service ────────┘
```

The hub owns persistence, policy, presentation, and future audit history. Native agents own platform collection. Agents initiate outbound communication; the hub never opens a management port on an endpoint.

The hub must not provide a general-purpose remote shell. Future actions are fixed, named capabilities with separate authorization, confirmation, audit, and rollback behavior.

## Technology decisions

| Area | Decision | Reason |
| --- | --- | --- |
| Hub | Go HTTP service | Small cross-platform binary, strong standard library, simple operations |
| Agents | Native Go services with platform modules | Shared protocol code without giving up native collection |
| UI | React, TypeScript, and Vite | Responsive browser access and maintainable dashboard state |
| Storage | SQLite in WAL mode | One hub process owns the database; no database port or second service |
| Hub packaging | Hardened Docker image and Compose | Matches the application server's operating model |
| Agent packaging | Windows Service, systemd, and launchd | Host visibility without privileged containers |
| Device authentication | Unique revocable certificates using mutual TLS | No shared household agent credential |
| User access | Private HTTPS plus application authentication | Network location alone is not an identity |
| Background alerts | Standards-based Web Push and a service worker | Cross-platform delivery without a privileged tray process or always-open page |
| Desktop shell | Optional Tauri wrapper | Reuse the web interface only if tray or native notifications justify it |

PostgreSQL becomes appropriate if HAVEN needs multiple hub writers, multiple hub replicas, sustained high-volume flow telemetry, multi-tenant hosting, or concurrency that batching cannot handle. Storage-specific behavior remains inside `internal/storage`, but supporting two engines simultaneously is not a current goal.

## Current milestone boundary

Milestone 0.12 extends the authenticated native-agent hub with bounded, read-only NAS health evidence:

- `haven-hub` serves a loopback dashboard, owns SQLite, and exposes a separate loopback TLS 1.3 agent listener. Native development may enable local collection; a containerized production hub disables it and never treats its ephemeral container hostname as a device.
- Enrollment uses a short-lived, one-time 256-bit token plus an ECDSA P-256 certificate request. The trusted CA certificate is transferred out of band.
- Every agent receives a unique 90-day client certificate whose URI identity must match its observation envelope and database record.
- Reports have a version, random identity, strictly increasing per-device sequence, and bounded timestamp. Replays, revoked devices, oversized bodies, unsupported versions, and excessive request rates are rejected.
- The hub removes raw connection and workload observations before persistence. It retains only a bounded listener baseline—protocol, port, bind scope, and appearance timestamps—so it can identify newly appearing or reappearing services without retaining remote endpoints, payloads, process history, or a deployment timeline. Separately, owner-approved expectation metadata may retain bounded process, workload, and systemd-unit allowlists so port ranges and ownership remain meaningful. There is no remote-control endpoint.
- The Linux collector asks `ss` for extended socket metadata and keeps only a sanitized terminal `.service` or `.socket` unit name. For socket-activated user services whose socket belongs to the generic user manager, it may read that same process's `/proc/<pid>/cgroup` entry or correlate the exact protocol/address/port with the unprivileged user manager's bounded socket list. Full cgroup paths, command lines, and historical process ownership are never retained.
- The Ubuntu reporter remains unable to open either Docker socket path. Before each report, a separate one-shot service queries the local Docker Engine over its Unix socket and writes a mode-0600, fixed-schema JSON file. It keeps only running workload names, image references, Compose project/service labels, state/health, and port mappings; it has no IP-network access and exits before the reporter reads the file.
- Docker socket access is root-equivalent authority. The exporter is therefore isolated from the network-facing reporting client and never accepts browser input, sends observations, performs container actions, or retains environment variables, commands, mounts, arbitrary labels, logs, IDs, or container network addresses.
- Development listeners remain loopback-only. The production profile publishes explicit private dashboard and agent listeners on the configured LAN address, never on an unconstrained wildcard.
- Observation schema version 2 adds privacy-bounded Windows posture. The hub derives checks and findings from raw signals so severity logic stays reviewable and consistent.
- Findings use explicit evidence and recommendations rather than a combined score. Unavailable data remains unknown, never healthy.
- When native local collection is enabled, the hub collects immediately at startup and on a bounded interval. Manual and scheduled collections are serialized so the fixed native collector cannot run concurrently with itself. Hub-only deployments select the latest authenticated enrolled-agent observation instead.
- The one-shot Windows reporter uses a distinct GUI-subsystem build when launched by Task Scheduler. Its fixed PowerShell collector and allowlisted Windows actions set both hidden-window startup state and `CREATE_NO_WINDOW`, preventing background collection from allocating a console or taking foreground focus. The interactive console build remains separate for enrollment and diagnostics.
- SQLite stores an append-only transition event only when an evaluated finding opens or resolves. Unchanged observations do not create activity noise.
- The browser combines the latest authenticated device observations into an owner-only coverage view. It derives enrolled-device relationships from matching live endpoint addresses, labels other private destinations as observed-only assets, and groups public destinations by source owner and destination service. This derived view is not persisted.
- A managed appliance is an explicit private deployment record, not an enrolled endpoint and not an automatically trusted observed asset. Credential-free TCP/TLS checks remain the default. An optional named health provider reads its SNMP community and SSH key from mounted files, pins the appliance's ED25519 host key, and invokes one fixed appliance-side command. It never follows results into discovery or grants the appliance endpoint-agent trust.
- The appliance helper has no command-line parameters and emits a fixed, bounded JSON report. It reads only kernel uptime/version, physical disk identity without serials, SMART health and temperature with a non-waking standby policy, Linux md state, top-level volume capacity, safe vendor release files, and thermal-zone values. Accounts, shares, filenames, network configuration, packet data, and arbitrary command output are excluded.
- Health coverage is explicit per category: verified, partial, unsupported, or unavailable. Partial evidence does not become healthy. Two total source failures are required for a telemetry-availability alert, while verified disk, RAID, capacity, and temperature thresholds produce component-specific alerts with stable transition identities.
- Network overview data does not grant trust, enroll a device, resolve a hostname, probe an address, or scan the LAN. Raw remote endpoints remain live-only and disappear after a hub restart until agents report again.
- The hub derives active alerts only from server-classified device freshness, current evaluated findings, owner finding reviews, persistent listener appearance timestamps, and owner-approved service expectations. Accepted-risk findings and currently snoozed findings stay visible in endpoint posture with their local review metadata but leave the interruptive active-alert projection; acknowledgements and expired snoozes remain active. The authenticated browser consumes that projection rather than implementing a second policy. A protocol/port/scope match whose current owner no longer satisfies its approved process, workload, or systemd-unit constraint is reported as service drift rather than silently trusted. Optional expectation expirations are enforced from hub time; if the same owner-constrained listener remains active, its exact expiration creates a new review and delivery instance.
- The authenticated runtime response publishes the server's device-freshness allowance. The browser does not independently guess the stale threshold.
- The hub reevaluates alerts every minute independently of dashboard activity. It queues one delivery per medium/high alert instance and enrolled push destination, persists the receipt before retrying, expires retries when the alert is no longer current, and leaves low-severity alerts visible without interruption.
- A browser explicitly grants notification permission and registers a standards-based Web Push subscription. Its capability endpoint and encryption keys are AES-GCM encrypted at rest using a random key outside SQLite; the VAPID identity is stored beside that key in the private state directory. The push endpoint never appears in an authenticated status response, audit detail, or log.
- The outbound sender accepts HTTPS hostnames on the standard port only, resolves every destination address before connecting, rejects private, loopback, link-local, multicast, and non-global addresses, and refuses redirects. This keeps a registered push endpoint from becoming a general server-side request primitive.
- Web Push encrypts the message for the browser subscription. The browser-vendor service can still observe delivery metadata, so enrollment is disabled by default and the UI states that tradeoff. Lock-screen content includes only the device label and severity, not the finding title, summary, port, owner, or endpoint evidence.
- A configured state distinguishes intentionally enabled services with verified compensating controls from both healthy defaults and actionable findings. The Windows collector can verify TPM readiness without elevation and summarizes RDP firewall scope without retaining rule names or network addresses.

The trusted inventory contains only the local collector and explicitly enrolled agents. HAVEN does not infer trust from sharing a network. The network overview keeps merely observed assets separate from enrolled devices, and another household member's device requires informed opt-in before an agent is installed.

Managed appliances form a third category: explicitly configured but not enrolled as general-purpose agents. The hub cannot establish their host firewall, malware-protection, or account posture. For an appliance with the optional health provider, it can establish only the disk, RAID, capacity, temperature, kernel, and safely exposed firmware facts in the fixed schema. Two consecutive required-service or total-health-source failures are necessary before an availability alert is derived. Optional visibility-only endpoints and missing-but-non-actionable coverage remain factual inventory and never create outage alerts.

Windows baseline collection stores configuration state and aggregate counts only. It excludes local administrator names, update titles, Defender threat names, detection resource paths, and BitLocker recovery material.

Collected state and actionable policy are deliberately separate. Windows reports whether BitLocker and OpenSSH are active, but HAVEN treats BitLocker-off as data-at-rest inventory rather than a network or malware alert and does not flag OpenSSH merely for running. Remote-access findings require an unsafe property such as weak authentication or an unrestricted firewall boundary. Accepted risks and active snoozes are omitted from alert, reminder, and review-count surfaces while the underlying collected fact remains available for auditability.

Private HTTPS publication, private DNS, bounded hub containers, consistent local backups, and private HomeOps-controlled CI/CD are explicit production components rather than assumptions hidden in local development. Browser authentication uses cross-platform WebAuthn passkeys, supports multiple authenticators and local recovery, and requires fresh confirmation for sensitive capabilities.

Platform-specific controls sit behind advertised capability providers. The local Windows provider currently exposes two fixed Defender operations. A future Ubuntu, macOS, or remote Windows agent must implement its own provider and authenticated action transport; the hub never translates an unsupported action into an arbitrary shell command.

## Storage and retention

Agents will send high-level observations to the hub, never SQL. The SQLite file remains on local storage beside its WAL files in a persistent container volume.

- Posture observations expire after 90 days by default; deployment configuration can shorten that period.
- Live TCP connection and Docker workload details are returned to the dashboard but removed before a snapshot is stored.
- Finding-transition events retain the privacy-bounded category, title, severity, and summary already present in posture history; they never copy connection details or excluded identifiers.
- Active-alert projection is recomputed hub state and is not another historical telemetry table. Finding lifecycles and bounded listener appearance records remain the durable evidence behind it. Push-delivery rows retain only alert and recurrence identities, destination identity, bounded result classifications, attempt times, and delivery state; they do not copy finding text or connection evidence.
- Push capability endpoints and subscription encryption keys are stored only inside AES-GCM ciphertext. VAPID and subscription-encryption keys live in the private state directory and must be backed up with the database. Completed delivery receipts expire after 90 days during reconciliation.
- Expected-service records are per-device owner metadata containing a friendly label, protocol, exact port or bounded range, bind expectation, optional approved process, workload, or systemd-unit owners, and an optional expiration no more than 30 days from approval. Suggestions are generated from the current live observation but are never saved automatically. Active API results omit expired rows while the alert projector retains their bounded expiration evidence. Single, renewal, and bulk changes are audited but do not start a service or alter a firewall.
- Managed-appliance persistence contains only normalized current service and health status, stable transition times, bounded failure classes, and public TLS certificate metadata. SNMP communities, SSH private keys, raw SNMP values, raw helper output, disk serials, and appliance account data are never written to SQLite.
- Packet payloads, browser content, keystrokes, screenshots, and document contents are never collected.
- Future high-volume network summaries receive shorter retention than posture changes.
- Account-security records contain status metadata, never passwords, recovery codes, authenticator seeds, cookies, or refresh tokens unless a separately reviewed integration makes a token unavoidable.
- Portfolio and demo modes use synthetic fixtures only.

## Hub container boundary

The production container contains the Go hub and compiled web assets. It runs as a non-root user with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a bounded temporary filesystem, and one writable data volume.

The public baseline Compose file publishes to host loopback. The private HomeOps production profile binds an explicit private address behind a dedicated TLS reverse proxy and local resolver. Real addresses, certificate identities, trust roots, and credentials remain untracked server state.

## Planned deployment stages

1. **Local foundation:** validate Windows collection, UI, persistence, privacy behavior, and container build.
2. **Trust foundation:** define versioned messages, enrollment, device certificates, mutual TLS, revocation, and replay resistance.
3. **Household pilot:** deploy the Dockerized hub through private authenticated access and enroll one native Windows agent.
4. **Native Linux monitoring:** enroll the Ubuntu application host through a boot-persistent, unprivileged service. Collect platform-specific update, firewall, SSH, AppArmor, time, service, storage, and TCP posture without granting the reporter Docker control.
5. **Host network explainability:** group listeners, track bounded appearance metadata, and let the owner classify expected services without changing host configuration.
6. **Workload attribution:** isolate root-equivalent runtime access in a fixed-output, one-shot exporter and correlate sanitized port mappings with live listeners.
7. **Baseline review:** generate high-confidence platform/process/workload suggestions, require explicit owner approval, and preserve ownership constraints across bounded port ranges.
8. **Linux service attribution:** correlate sanitized live socket owners with systemd units and let reviewed expectations constrain dynamic listeners to an approved service.
9. **Multi-platform:** add macOS and additional Linux agents with informed owner consent, preserving platform-specific security meaning.
10. **Network-wide explainability:** keep observed network assets separate from enrolled devices, then combine host listeners, firewall scope, router exposure, and privacy-bounded flow metadata.
11. **Narrow controls:** add separately privileged allowlisted actions only after the read-only system is trustworthy.
