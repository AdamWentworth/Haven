# HAVEN

**Home Asset Visibility, Events & Network Security**

HAVEN is a personal security observatory for home devices and networks. It presents native operating-system protections in one understandable console without trying to replace Microsoft Defender, host firewalls, or other trusted security controls.

HAVEN is pre-release software. The current milestone adds an installable desktop experience without introducing a privileged native shell or a second credential store. Its private account-security notebook remains a checklist—not a provider integration or secret vault—and HAVEN is not a replacement for native protection.

## Milestone 0.16 — Installable Desktop Experience

The current implementation provides:

- A Go hub with a responsive React and TypeScript dashboard embedded in its executable
- An installable application manifest and dedicated-window experience for compatible desktop browsers, using the same private HTTPS origin, passkeys, Web Push subscription, and hub-delivered updates
- A Settings installation panel that reports whether HAVEN is already installed, ready for the browser install prompt, or available through the browser's app menu
- A deliberately unprivileged application boundary: no native command bridge, local database, duplicated credentials, authenticated-page cache, or silent notification permission request
- A dedicated Accounts workspace for owner-reported email, social, developer, finance, gaming, shopping, work, and other profiles
- Manual status tracking for two-step verification, factor types, password uniqueness/passwordless use, recovery methods, backup-code readiness, review dates, structured review facts, and exceptional context notes
- Fresh passkey confirmation before account records are returned to a browser, followed by a session-bound grant held only in browser memory with a 15-minute inactivity timeout and an eight-hour absolute limit
- Explicit account-workspace locking that immediately removes decrypted profiles from browser state without signing out of the rest of HAVEN
- Locally bundled, recognizable platform marks with a clear monogram fallback for custom providers; no remote logo request or provider tracking is introduced
- Fact-derived suggestions for disabled two-step verification, reused passwords, missing recovery methods or backup codes, SMS/email-only factors, unknown checklist fields, and reviews older than six months
- Clear separation between account-notebook suggestions and threat alerts: notebook gaps never create push notifications or claim that an account was compromised
- AES-256-GCM encryption of every account profile using a dedicated random key outside SQLite, with ciphertext bound to its opaque profile identity
- Strict account APIs with no password, cookie, authenticator seed, recovery-code, OAuth-token, or provider-credential fields; recognizable secret formats are rejected and free-form notes carry an explicit warning
- Privacy-bounded account audit events that retain only an opaque profile identity and operation, never provider names, identifiers, posture choices, or notes
- Read-only Windows collection for Microsoft Defender, Windows Firewall, device posture, and up to 250 established or listening TCP endpoints
- SQLite posture history with migrations, consistent online backups, a 90-day default retention window, and no historical storage of connection or workload details
- A native Go agent with one-time enrollment, a unique ECDSA certificate, and TLS 1.3 mutual authentication
- Authenticated, privacy-bounded agent build evidence containing the public release, immutable revision, platform, installation kind, observed capability manifest, and collection-notice count
- A fleet lifecycle view that keeps report freshness, build maintenance, collection limitations, and endpoint security posture as separate facts
- Backward-compatible acceptance of pre-0.14 enrolled reporters, which remain visible as legacy until deliberately updated
- Exact-version and exact-revision comparison performed by the hub, without creating security alerts or remotely executing endpoint updates
- Checksummed Windows amd64, Linux amd64, and Linux arm64 agent artifacts produced from an explicit full source revision by CI
- Idempotent Windows and Linux install/repair workflows plus read-only status commands and identity-preserving uninstall procedures
- Reproducible Windows Task Scheduler packaging that runs a GUI-subsystem reporter and suppresses console allocation for child collectors, preventing periodic focus theft or window flashes
- Stable, browser-native routes for Overview, Devices, Network, Appliances, Accounts, Activity, Settings, and per-device posture, services, and history views
- A concise network-wide landing page instead of forcing every control and observation into one scrolling dashboard
- Bounded transient report retries that reuse a single observation identity, with idempotent hub acceptance when a successful response is lost
- A 35-minute server-owned freshness allowance so one missed 15-minute agent run does not create a noisy false alarm
- Database-backed readiness checks and a shared release version plus immutable build revision in health, runtime, Settings, and the footer
- Expanded rendered-component, routing, API-contract, accessibility, security-projection, and cross-platform Go tests with honest whole-frontend coverage gates
- Commit-pinned GitHub Actions, digest-pinned container build inputs, and CodeQL analysis for Go and TypeScript
- Native Ubuntu posture collection for updates, restart state, UFW policy, SSH, AppArmor, time synchronization, bounded failed-unit names, root-filesystem capacity, and live TCP/UDP endpoints
- Live Linux systemd service/socket attribution from bounded socket, process-cgroup, and unprivileged user-socket metadata, without retaining command lines or full cgroup paths
- A logical listener inventory that groups duplicate IPv4/IPv6 sockets and separates non-local services needing review, expected services, host-only services, and active connections
- A short-lived, isolated Docker inventory exporter that supplies only running workload names, image references, Compose identity, health, and published/container-only port mappings to the normal socket-blocked Linux agent
- Live Docker-to-listener attribution without collecting environment variables, commands, mounts, arbitrary labels, logs, container IDs, or container network addresses
- A one-time suggested-baseline review that derives high-confidence candidates from platform roles, live process ownership, sanitized Docker workload mappings, and owner-constrained Linux dynamic-service ranges without silently trusting the first observation
- Per-device expected-service labels for exact ports or bounded ranges, bind scope, and optional approved process/workload/systemd owners, with atomic bulk approval, an auditable owner decision, and no firewall or service side effects
- Optional server-enforced temporary service expectations from one hour to 30 days; they survive hub restarts, expire with the browser closed, and create a distinct review and notification lifecycle when a still-active listener needs approval again
- Process-constrained grouping for Windows dynamic RPC listeners so ordinary port rotation does not create dozens of permanent exceptions or conceal unrelated high-port services
- Privacy-bounded listener appearance history containing only protocol, port, bind scope, and timestamps—never payloads or historical remote connections
- Strictly increasing report sequences, timestamp checks, payload limits, rate limits, device revocation, and versioned messages
- A device inventory and detail view with explicitly synthetic demo fixtures for portfolio work
- A network-wide coverage view that summarizes report freshness, verified host firewalls, current findings, and unreviewed service exposure across enrolled devices
- Credential-free TCP/TLS reachability for explicitly configured private network appliances, plus optional SNMP and forced-command SSH health collection from file-backed credentials
- NAS disk inventory and SMART status without serial numbers, Linux storage-set member/state monitoring (including multi-disk RAID), volume capacity, non-waking disk temperature checks, system thermal sensors, uptime, kernel, and firmware metadata when safely exposed
- Explicit verified, partial, unsupported, and unavailable coverage so missing NAS telemetry is never presented as healthy
- Live relationship grouping that distinguishes explicitly enrolled peers, observed-only private endpoints, and Internet destinations grouped by source owner and destination service
- Cross-device finding lifecycle context without retaining raw remote endpoints, connection history, packet contents, or inferred device trust
- A hub-owned current-alert view derived only from server-classified report freshness, evaluated posture findings, and owner-reviewed service expectations
- Service-drift alerts when a known protocol/port/scope is still present but its live process, systemd-unit, or Docker-workload attribution no longer matches the approved baseline
- Opt-in Web Push delivery evaluated by the Ubuntu hub every minute, including when the dashboard is closed
- Encrypted-at-rest push capability endpoints, encrypted Web Push payloads, public-destination validation, redirect refusal, bounded retries, automatic expiry handling, and durable per-destination recurrence receipts
- Generic lock-screen messages containing only device name and severity; finding details remain inside the authenticated HAVEN dashboard
- Silent baselining when a destination is first enabled, recurrence-aware deduplication for medium/high alerts, and no interruption for low-severity review items
- A server-published freshness allowance so browser wording and stale timestamps cannot silently drift from the server's policy
- Frontend and Go invariant tests for address scope, listener grouping, expectation matching, relationship direction, mirrored-flow deduplication, external-address privacy, server-owned alert derivation, subscription validation, delivery baselining, retry timing, recurrence, and generic payload privacy
- Enforced coverage thresholds for security projection modules plus Go race detection in CI
- Clear language that observed-only assets are neither enrolled nor trusted and that the overview does not actively scan the LAN
- Explainable Windows baseline checks for servicing, BitLocker, Secure Boot, TPM, remote access, local administrator count, and Defender threat counts
- Consistent remote-access policy across Windows and Linux: a running SSH service is inventory, while unsafe authentication or network boundaries—not service presence alone—are actionable
- Non-elevated TPM verification through Windows TPM Tool when the administrative PowerShell provider is unavailable
- RDP context that distinguishes NLA-protected, firewall-restricted access from unrestricted or unverifiable exposure
- Separate healthy, intentionally configured, review, and unverified states with per-check observation timestamps
- Prioritized findings with evidence and conservative next steps instead of an opaque security score
- Continuous local collection every 15 minutes by default, with serialized manual refreshes
- A privacy-bounded activity ledger that records only when a finding opens or resolves
- An activity-first dashboard with status for every enrolled background-alert destination
- Passwordless owner authentication using the cross-platform WebAuthn passkey standard (Windows Hello is one supported provider)
- Multiple labeled owner passkeys for trusted computers, phones, and hardware security keys, with local terminal recovery
- Expiring server-side sessions, strict same-origin checks, anti-forgery tokens, and rate-limited authentication ceremonies
- Finding acknowledgement, 24-hour snooze, accepted-risk notes, immediate alert refresh, and a privacy-bounded audit trail; accepted risks and active snoozes leave alert, reminder, and review-count surfaces without erasing collected facts
- Provider-advertised action capabilities with fresh passkey confirmation; the first Windows provider offers a Defender quick scan and security-intelligence update
- No browser endpoint for arbitrary commands, scripts, paths, process launches, firewall changes, or Defender exclusions
- Privacy-bounded collection: administrator names, update titles, threat names, and detected resource paths are not collected
- A private HomeOps deployment boundary for a resource-bounded Ubuntu hub with private HTTPS, local DNS, and consistent backups
- Visible collector failures instead of silently treating unavailable information as healthy

The dashboard and agent endpoint both bind to loopback during development. No Docker runtime or deployment is needed for local iteration. A native development hub can collect from its own host; every containerized hub runs in hub-only mode and accepts observations only from explicitly enrolled native agents. Production uses separate, explicitly private listeners. Background alerts require explicit browser permission and a one-time destination enrollment. They use the browser vendor's push service, so delivery metadata leaves the home network; message content is encrypted and intentionally generic. HAVEN installs no privileged tray process or browser extension.

Managed appliances are configured separately from endpoint enrollment. Set `HAVEN_MANAGED_APPLIANCES_FILE` to a private JSON file owned by the deployment system. HAVEN accepts only literal private unicast addresses and explicit TCP ports; hostnames, address ranges, UDP probes, unknown fields, and discovery directives are rejected. A definition resembles the following, with the placeholder replaced only in private deployment configuration:

```json
{
  "appliances": [{
    "id": "home-nas",
    "displayName": "Home NAS",
    "kind": "nas",
    "address": "<private IPv4 address>",
    "health": {
      "provider": "terramaster-tos5",
      "snmpPort": 161,
      "communityFile": "/run/secrets/nas-snmp-community",
      "sshPort": 9222,
      "sshUsername": "<dedicated or administrator account>",
      "sshPrivateKeyFile": "/run/secrets/nas-monitor-key",
      "sshHostKeySHA256": "SHA256:<pinned ED25519 fingerprint>"
    },
    "services": [
      { "id": "smb", "name": "SMB file service", "protocol": "TCP", "port": 445, "tls": false, "required": true },
      { "id": "management", "name": "Management HTTPS", "protocol": "TCP", "port": 5443, "tls": true, "required": true }
    ]
  }]
}
```

The health block is optional. Its community and private-key values must live in owner-readable files mounted by private deployment configuration; inline credentials and relative secret paths are rejected. The SSH key must be pinned to the appliance's ED25519 host fingerprint and constrained appliance-side to the fixed `haven-nas-probe` command, with forwarding and PTY allocation disabled. SNMP v2c is not encrypted, so it belongs only on a trusted private segment with a unique random community—not the default `public` value.

The helper emits a bounded JSON schema containing only current health facts. It excludes accounts, shares, filenames, disk serial numbers, network configuration, commands, and arbitrary vendor responses. SMART is invoked with `-n standby,3`, which leaves a sleeping disk asleep and reports that limitation instead of waking it for a check. Capacity warnings begin at 85% used and become critical at 95%; disk temperature warnings begin at 50°C and become critical at 60°C; system temperature boundaries are 75°C and 90°C. Degraded, failed, and rebuilding multi-member storage sets remain visible and actionable. A one-member Linux `md` set is presented as single-disk storage with no drive redundancy rather than as configured RAID. Vendor firmware may remain partially verified when the installed TOS release is not available through these bounded sources. Future owner-confirmed device metadata will distinguish a manually recorded TOS version from automatic verification without turning missing firmware telemetry into an alert.

The hub records only current reachability, normalized health evidence, bounded error classes, check timestamps, and the public metadata of a presented TLS certificate. It never stores appliance credentials, raw responses, packet payloads, or newly discovered services. A required endpoint or complete health source must fail two consecutive checks before HAVEN creates an availability alert; visibility-only endpoints and incomplete-but-non-actionable health coverage remain quiet.

Because HAVEN is pre-release and observation schema 2 is still evolving, hubs and agents should run the same repository revision.

## Run locally on Windows

Requirements:

- Go 1.26.6 or later
- Node.js 24 or another version supported by the pinned frontend toolchain
- Windows PowerShell with the built-in Defender and NetSecurity modules

Build the web application and run the hub:

```powershell
Set-Location .\web
npm ci
npm run build
Set-Location ..
go run .\cmd\haven-hub
```

Open <http://localhost:5080>. The hub binds to loopback by default and writes its development database to the operating system's per-user application-data directory, outside the repository. The `localhost` name is required because browsers grant WebAuthn's local-development secure-context exception to localhost, not arbitrary loopback IP literals.

## Install the desktop experience

Open the production HTTPS address in a compatible desktop browser, sign in, and visit **Settings → Install HAVEN**. When the browser reports that installation is ready, HAVEN presents an **Install HAVEN** button; the browser's app or site menu remains the fallback. The installed application launches in its own window from the operating system's app launcher while continuing to use the same hub origin and security controls. It is a client shortcut, not another hub or endpoint agent. Hub monitoring continues regardless of whether the installed window starts at boot; background alert delivery remains subject to browser and operating-system policy.

On first use, keep the hub running and create a one-time bootstrap code in another terminal:

```powershell
go run .\cmd\haven-hub auth bootstrap
```

Paste the code into HAVEN and follow the passkey prompt offered by the browser and operating system. On Windows this may be Windows Hello; other systems may offer Touch ID, a phone, a synchronized passkey provider, or a hardware security key. The code expires after 10 minutes and is consumed only by a successful passkey registration. The same command provides local recovery if every registered passkey is later unavailable.

HAVEN supports multiple labeled owner passkeys. A signed-in owner can add or remove them from the dashboard; the final passkey cannot be removed without first adding a replacement. Direct enrollment from another computer requires HAVEN's eventual stable private HTTPS hostname because a `localhost` passkey belongs to the local development origin. Trusted-browser sessions last up to 30 days, while each sensitive control requires a fresh, single-use passkey confirmation. The Accounts workspace also consumes a fresh confirmation before issuing a separate session-bound grant that locks after 15 minutes of inactivity and expires absolutely after eight hours; the browser holds that grant only in memory. Passkey credential data, account-notebook profiles, and Web Push subscriptions are encrypted with separate random keys stored beside the database outside the repository; the VAPID identity also lives there. Back up the complete state directory as one unit. Losing an encryption key makes the corresponding stored data unreadable.

The hub takes an observation immediately at startup and every 15 minutes thereafter. Set `HAVEN_COLLECTION_INTERVAL` to a duration from `1m` through `24h` to change it during development.

Run a single read-only agent collection without enrollment:

```powershell
go run .\cmd\haven-agent
```

To exercise the local trust flow, keep the hub running, then create a short-lived token in another terminal:

```powershell
go run .\cmd\haven-hub enrollment create --name "Development PC"
go run .\cmd\haven-agent enroll --hub https://localhost:5443 --ca "$env:LOCALAPPDATA\HAVEN\pki\ca.crt" --name "Development PC"
go run .\cmd\haven-agent report
```

The enrollment command prompts for the token so it is not placed in shell history. Private keys, certificates, state, and observations are written under the operating system's per-user application-data directory, never the repository.

After enrollment, install or update the per-user Windows reporting task from an **elevated PowerShell session** in the HAVEN source directory:

```powershell
pwsh -NoProfile -File .\scripts\Install-WindowsAgentTask.ps1
```

The installer builds a separate GUI-subsystem reporter under the current user's application-data directory and points Task Scheduler directly at it. The interactive `haven-agent.exe` remains available for enrollment and diagnostics, while the scheduled reporter and its fixed PowerShell collector run without allocating a visible console. It preserves an existing task's triggers; a new task reports at logon and every 15 minutes. The task runs at Windows' highest available level so read-only collection can inspect protected Windows posture signals; the installer refuses to create a misleading limited task when it is not elevated. An always-running Service Control Manager process remains deliberately deferred until event-driven Defender or Event Log monitoring provides a concrete need for its larger resident attack surface.

The installer stamps the exact source revision into the background reporter. Inspect scheduling and binary-hash evidence without modifying the task, or uninstall the reporter while preserving its enrolled identity, with:

```powershell
pwsh -NoProfile -File .\scripts\Get-WindowsAgentStatus.ps1
pwsh -NoProfile -File .\scripts\Uninstall-WindowsAgentTask.ps1
```

On Linux, the source-based installer provides the same install/repair/status/uninstall lifecycle around the hardened user systemd timer. Uninstall preserves the enrolled identity by default:

```bash
./scripts/Install-LinuxAgent.sh install
./scripts/Install-LinuxAgent.sh status
```

`haven-agent status` reports local enrollment plus public build identity, while `haven-agent version` reports only the build identity. CI publishes checksummed agent binaries as a 30-day workflow artifact for each verified commit. HAVEN does not automatically replace endpoint binaries; an owner or private deployment workflow chooses and verifies the revision being installed.

Both installers also accept a prebuilt CI artifact only when its SHA-256 manifest value is supplied. Windows uses `-AgentBinary` with `-ExpectedSHA256`; Linux uses the `HAVEN_AGENT_BINARY` and `HAVEN_AGENT_SHA256` environment variables. A failed checksum leaves the installed reporter untouched.

Upgrade the hub before installing reporters from 0.14 or later. The newer hub deliberately accepts older metadata-free reports and labels them as legacy; a 0.13 hub's strict decoder does not recognize the optional agent-metadata field.

Create portfolio-safe inventory fixtures or a consistent SQLite backup with:

```powershell
go run .\cmd\haven-hub demo seed --count 5
go run .\cmd\haven-hub backup --to D:\Backups\haven-example.db
```

Use only a path outside the repository for backups. Revoke an enrolled identity with `go run .\cmd\haven-hub device revoke --id <device-id>`.

For screenshots, start the hub in explicit synthetic-only mode after seeding:

```powershell
$env:HAVEN_DEMO_MODE = "true"
go run .\cmd\haven-hub
Remove-Item Env:HAVEN_DEMO_MODE
```

Demo mode neither runs the local collector nor exposes non-synthetic devices through the dashboard API. Its clearly labeled cross-platform machines are invented examples, not network discovery results. Conversely, normal mode hides all demo fixtures. Keep demo mode enabled for the entire screenshot session.

For frontend development, set `$env:HAVEN_PUBLIC_ORIGIN = "http://localhost:5173"` before starting the hub, then run `npm run dev` from `web`. Vite binds to localhost and proxies `/api` to the hub. Remove the environment variable when returning to the embedded UI on port 5080.

## Checks

```powershell
go test .\...
go vet .\...
go mod verify
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 .\...

Set-Location .\web
npm ci
npm run build
npm run test:coverage
npm audit
Set-Location ..

pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

## Ubuntu deployment

GitHub-hosted CI builds and publishes an immutable `ghcr.io/adamwentworth/haven-hub:sha-<commit>` image only after all verification passes. A separate private HomeOps repository owns the production runner and fixed deployment controls. It validates the requested `main` revision and image label, recreates only HAVEN's constrained containers, health-checks private HTTPS, and rolls back on failure.

The production profile uses `haven.home.arpa` as a private DNS name, a private certificate authority for the browser endpoint, a LAN/VPN resolver, and a distinct mutually authenticated agent endpoint. The production container sets `HAVEN_LOCAL_COLLECTION_ENABLED=false`; its ephemeral container hostname is never a trusted device. Real addresses, deployment authority, trust roots, private keys, databases, and server configuration do not belong in this public repository. See [the deployment guide](docs/DEPLOYMENT.md) for the trust boundary. Endpoint agents run natively, not as privileged containers.

## Repository layout

```text
Haven/
├── cmd/
│   ├── haven-hub/       # API, embedded dashboard, and SQLite owner
│   ├── haven-agent/     # Native read-only collection entry point
│   └── haven-nas-probe/ # Fixed-schema, appliance-side health helper
├── internal/
│   ├── collector/       # Fixed, platform-specific collectors
│   ├── account/         # Encrypted manual account posture and suggestions
│   ├── agent/           # Enrollment, identity persistence, and reporting client
│   ├── alert/           # Server-owned current-alert projection
│   ├── hub/             # Local dashboard and mutually authenticated agent APIs
│   ├── healthpolicy/    # Explicit capacity and temperature thresholds
│   ├── model/           # Versionable observation model
│   ├── nasprobe/        # Bounded disk, RAID, volume, and thermal collection
│   ├── notification/    # Encrypted, durable Web Push delivery
│   ├── storage/         # SQLite persistence and retention
│   ├── workload/        # Sanitized, fixed-purpose runtime inventory
│   └── webui/           # Embedded production assets
├── web/                 # React, TypeScript, and Vite source
├── packaging/           # Generic native service and timer definitions
├── docs/                # Architecture, threat model, and publishing policy
├── Dockerfile
└── compose.yaml
```

## Design principles

1. **Observe first.** Read-only visibility comes before controls.
2. **Use native protections.** HAVEN coordinates trusted OS security controls instead of replacing them.
3. **Centralize understanding, not secrets.** Passwords, recovery codes, MFA seeds, cookies, and unrestricted device credentials do not belong in HAVEN.
4. **Treat unavailable as unknown.** A failed collector is never shown as a healthy signal.
5. **Keep actions narrow and reversible.** Platform providers advertise named, allowlisted operations with fresh confirmation and audit history—never a remote shell.
6. **Collect proportionately.** Connection and workload details are live-only by default; packet payloads and browsing content are outside HAVEN's scope.
7. **Respect every household member.** Monitoring another person's device requires visible opt-in and transparent collection.

## Current and next security milestone

Milestone 0.16 adds a same-origin installable desktop window, local application icons, browser-owned install flow, and explicit tests that prevent a privileged native bridge or authenticated offline cache from slipping into that convenience layer. Milestone 0.15.3 keeps reviewed account cards compact by removing redundant healthy-state copy, date time-of-day noise, and equal-height stretching between neighboring profiles.

Milestone 0.7 adds native Linux monitoring and boot-persistent endpoint-agent scheduling. Milestone 0.7.1 makes its network results explainable, 0.7.2 makes report freshness and finding lifecycles explicit, and 0.7.3 correlates host listeners with sanitized Docker port mappings. Milestone 0.7.4 adds deliberate suggested-baseline review; 0.7.5 adds live systemd ownership and service-constrained expectations for Linux listeners. Milestone 0.8 combines the latest authenticated reports into a network-wide coverage, change, and live-relationship view while keeping merely observed private endpoints separate from explicitly enrolled devices. Milestone 0.9 turns current findings, server-classified stale agents, incomplete enrollments, new non-local listeners, and changed service attribution into explainable active alerts. Milestone 0.10 moves that derivation to the hub and adds opt-in, encrypted, durable Web Push delivery with bounded retries and per-destination receipts; its expectation model also supports owner-constrained dynamic ranges and expiring development approvals. Milestone 0.11 adds reproducible console-free Windows scheduled-task packaging and credential-free monitoring of explicitly configured private network appliances. Milestone 0.12 adds optional read-only NAS health through bounded SNMP plus a host-key-pinned, forced-command SSH helper. Milestone 0.13 reorganizes the console around stable routes and strengthens report delivery, freshness semantics, readiness, version evidence, rendered UI tests, and the public release pipeline. Milestone 0.14 adds authenticated reporter provenance, capability evidence, fleet lifecycle presentation, checksummed cross-platform artifacts, and safe install/repair/status/uninstall workflows while preserving older enrolled reporters. Milestone 0.15 adds an encrypted owner-reported account-security notebook with calm, evidence-derived authentication and recovery suggestions while explicitly excluding provider access and secret storage; 0.15.2 adds a separately reauthenticated private workspace, structured review facts, and local platform branding. A later event-driven Windows sensor may move under Service Control Manager only when real-time Defender and Windows Event Log monitoring justify an always-running process; it must remain outbound-only and use the least privilege its collectors require. HAVEN does not scan the LAN, retain remote endpoints, or claim that an alert proves compromise. See [verification](docs/VERIFICATION.md) for the claim-to-test map. The Ubuntu hub does not execute Windows actions on another machine. GitHub Actions verifies the Go, frontend, dependency, concurrency, vulnerability, Windows process isolation, agent artifacts, image, static analysis, and public-repository safety checks on each proposed change.

Read the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [public repository policy](docs/PUBLIC_REPOSITORY.md) before expanding the trust boundary.
