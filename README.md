# HAVEN

**Home Asset Visibility, Events & Network Security**

HAVEN is a personal security observatory for home devices and networks. It presents native operating-system protections in one understandable console without trying to replace Microsoft Defender, host firewalls, or other trusted security controls.

HAVEN is pre-release software. The current milestone adds a read-only network overview that combines authenticated endpoint reports without turning the hub into a network scanner or silently trusting observed assets; it is not a replacement for native protection.

## Milestone 0.8 — Network Overview

The current implementation provides:

- A Go hub with a responsive React and TypeScript dashboard embedded in its executable
- Read-only Windows collection for Microsoft Defender, Windows Firewall, device posture, and up to 250 established or listening TCP endpoints
- SQLite posture history with migrations, consistent online backups, a 90-day default retention window, and no historical storage of connection or workload details
- A native Go agent with one-time enrollment, a unique ECDSA certificate, and TLS 1.3 mutual authentication
- Native Ubuntu posture collection for updates, restart state, UFW policy, SSH, AppArmor, time synchronization, bounded failed-unit names, root-filesystem capacity, and live TCP/UDP endpoints
- Live Linux systemd service/socket attribution from bounded socket, process-cgroup, and unprivileged user-socket metadata, without retaining command lines or full cgroup paths
- A logical listener inventory that groups duplicate IPv4/IPv6 sockets and separates non-local services needing review, expected services, host-only services, and active connections
- A short-lived, isolated Docker inventory exporter that supplies only running workload names, image references, Compose identity, health, and published/container-only port mappings to the normal socket-blocked Linux agent
- Live Docker-to-listener attribution without collecting environment variables, commands, mounts, arbitrary labels, logs, container IDs, or container network addresses
- A one-time suggested-baseline review that derives high-confidence candidates from platform roles, live process ownership, and sanitized Docker workload mappings without silently trusting the first observation
- Per-device expected-service labels for exact ports or bounded ranges, bind scope, and optional approved process/workload/systemd owners, with atomic bulk approval, an auditable owner decision, and no firewall or service side effects
- Process-constrained grouping for Windows dynamic RPC listeners so ordinary port rotation does not create dozens of permanent exceptions or conceal unrelated high-port services
- Privacy-bounded listener appearance history containing only protocol, port, bind scope, and timestamps—never payloads or historical remote connections
- Strictly increasing report sequences, timestamp checks, payload limits, rate limits, device revocation, and versioned messages
- A device inventory and detail view with explicitly synthetic demo fixtures for portfolio work
- A network-wide coverage view that summarizes report freshness, verified host firewalls, current findings, and unreviewed service exposure across enrolled devices
- Live relationship grouping that distinguishes explicitly enrolled peers, observed-only private endpoints, and Internet destinations grouped by source owner and destination service
- Cross-device finding lifecycle context without retaining raw remote endpoints, connection history, packet contents, or inferred device trust
- Clear language that observed-only assets are neither enrolled nor trusted and that the overview does not actively scan the LAN
- Explainable Windows baseline checks for servicing, BitLocker, Secure Boot, TPM, remote access, local administrator count, and Defender threat counts
- Non-elevated TPM verification through Windows TPM Tool when the administrative PowerShell provider is unavailable
- RDP context that distinguishes NLA-protected, firewall-restricted access from unrestricted or unverifiable exposure
- Separate healthy, intentionally configured, review, and unverified states with per-check observation timestamps
- Prioritized findings with evidence and conservative next steps instead of an opaque security score
- Continuous local collection every 15 minutes by default, with serialized manual refreshes
- A privacy-bounded activity ledger that records only when a finding opens or resolves
- An activity-first dashboard with opt-in browser desktop alerts for new high- and medium-severity findings while HAVEN is open
- Passwordless owner authentication using the cross-platform WebAuthn passkey standard (Windows Hello is one supported provider)
- Multiple labeled owner passkeys for trusted computers, phones, and hardware security keys, with local terminal recovery
- Expiring server-side sessions, strict same-origin checks, anti-forgery tokens, and rate-limited authentication ceremonies
- Finding acknowledgement, 24-hour snooze, accepted-risk notes, and a privacy-bounded audit trail
- Provider-advertised action capabilities with fresh passkey confirmation; the first Windows provider offers a Defender quick scan and security-intelligence update
- No browser endpoint for arbitrary commands, scripts, paths, process launches, firewall changes, or Defender exclusions
- Privacy-bounded collection: administrator names, update titles, threat names, and detected resource paths are not collected
- A private HomeOps deployment boundary for a resource-bounded Ubuntu hub with private HTTPS, local DNS, and consistent backups
- Visible collector failures instead of silently treating unavailable information as healthy

The dashboard and agent endpoint both bind to loopback during development. No Docker runtime or deployment is needed for local iteration. A native development hub can collect from its own host; every containerized hub runs in hub-only mode and accepts observations only from explicitly enrolled native agents. Production uses separate, explicitly private listeners. Desktop alerts require explicit browser permission and currently operate while the HAVEN page is open; they do not install a tray process or background browser extension.

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

On first use, keep the hub running and create a one-time bootstrap code in another terminal:

```powershell
go run .\cmd\haven-hub auth bootstrap
```

Paste the code into HAVEN and follow the passkey prompt offered by the browser and operating system. On Windows this may be Windows Hello; other systems may offer Touch ID, a phone, a synchronized passkey provider, or a hardware security key. The code expires after 10 minutes and is consumed only by a successful passkey registration. The same command provides local recovery if every registered passkey is later unavailable.

HAVEN supports multiple labeled owner passkeys. A signed-in owner can add or remove them from the dashboard; the final passkey cannot be removed without first adding a replacement. Direct enrollment from another computer requires HAVEN's eventual stable private HTTPS hostname because a `localhost` passkey belongs to the local development origin. Trusted-browser sessions last up to 30 days, while each sensitive control requires a fresh, single-use passkey confirmation. Passkey credential data is encrypted with a random key stored beside the database outside the repository. Back up both the state directory and that key together; losing the key makes the stored passkeys unusable.

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

Set-Location .\web
npm ci
npm run build
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
│   └── haven-agent/     # Native read-only collection entry point
├── internal/
│   ├── collector/       # Fixed, platform-specific collectors
│   ├── agent/           # Enrollment, identity persistence, and reporting client
│   ├── hub/             # Local dashboard and mutually authenticated agent APIs
│   ├── model/           # Versionable observation model
│   ├── storage/         # SQLite persistence and retention
│   ├── workload/        # Sanitized, fixed-purpose runtime inventory
│   └── webui/           # Embedded production assets
├── web/                 # React, TypeScript, and Vite source
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

Milestone 0.7 adds native Linux monitoring and boot-persistent endpoint-agent scheduling. Milestone 0.7.1 makes its network results explainable, 0.7.2 makes report freshness and finding lifecycles explicit, and 0.7.3 correlates host listeners with sanitized Docker port mappings. Milestone 0.7.4 adds deliberate suggested-baseline review; 0.7.5 adds live systemd ownership and service-constrained expectations for Linux listeners. Milestone 0.8 combines the latest authenticated reports into a network-wide coverage, change, and live-relationship view while keeping merely observed private endpoints separate from explicitly enrolled devices. It does not scan the LAN or retain remote endpoints. A later 0.8.x milestone can add owner-managed names and expectations for observed assets, then compare endpoint-reported exposure with separately reviewed router data. The Ubuntu hub does not execute Windows actions on another machine. GitHub Actions verifies the Go, frontend, dependency, image, and public-repository safety checks on each proposed change.

Read the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [public repository policy](docs/PUBLIC_REPOSITORY.md) before expanding the trust boundary.
