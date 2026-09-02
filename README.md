# HAVEN

**Home Asset Visibility, Events & Network Security**

HAVEN is a personal security observatory for home devices and networks. It presents native operating-system protections in one understandable console without trying to replace Microsoft Defender, host firewalls, or other trusted security controls.

HAVEN is pre-release software. The current milestone combines local device trust with an explainable Windows security baseline; it is not yet an authenticated household deployment or a replacement for native protection.

## Milestone 0.5 — Monitor & Respond

The current implementation provides:

- A Go hub with a responsive React and TypeScript dashboard embedded in its executable
- Read-only Windows collection for Microsoft Defender, Windows Firewall, device posture, and up to 250 established or listening TCP endpoints
- SQLite posture history with migrations, consistent online backups, a 90-day default retention window, and no historical storage of connection details
- A native Go agent with one-time enrollment, a unique ECDSA certificate, and TLS 1.3 mutual authentication
- Strictly increasing report sequences, timestamp checks, payload limits, rate limits, device revocation, and versioned messages
- A device inventory and detail view with explicitly synthetic demo fixtures for portfolio work
- Explainable Windows baseline checks for servicing, BitLocker, Secure Boot, TPM, remote access, local administrator count, and Defender threat counts
- Non-elevated TPM verification through Windows TPM Tool when the administrative PowerShell provider is unavailable
- RDP context that distinguishes NLA-protected, firewall-restricted access from unrestricted or unverifiable exposure
- Separate healthy, intentionally configured, review, and unverified states with per-check observation timestamps
- Prioritized findings with evidence and conservative next steps instead of an opaque security score
- Continuous local collection every 15 minutes by default, with serialized manual refreshes
- A privacy-bounded activity ledger that records only when a finding opens or resolves
- An activity-first dashboard with opt-in browser desktop alerts for new high- and medium-severity findings while HAVEN is open
- Privacy-bounded collection: administrator names, update titles, threat names, and detected resource paths are not collected
- A hardened, single-service Docker Compose definition for the future Ubuntu hub
- Visible collector failures instead of silently treating unavailable information as healthy

The dashboard and agent endpoint both bind to loopback during development. No Docker runtime or deployment is needed for local iteration, and the Compose baseline does not publish the agent listener yet. Desktop alerts require explicit browser permission and currently operate while the HAVEN page is open; they do not install a tray process or background browser extension.

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

Open <http://127.0.0.1:5080>. The hub binds to loopback by default and writes its development database to the operating system's per-user application-data directory, outside the repository.

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

For frontend development, run the hub and then start `npm run dev` from `web`. Vite binds to loopback and proxies `/api` to the hub.

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

The hub image and Compose definition are intended to be built and run on the always-on Ubuntu application server—not on development workstations. After cloning the public repository on that server:

```powershell
docker compose up --build -d
```

Compose publishes the dashboard on the host loopback interface only and persists SQLite in the `haven-data` volume. A private reverse proxy or VPN can be connected in a deployment-specific override after application authentication is implemented.

The Compose file intentionally does not publish the agent listener. Deployment comes after the server resource check, browser authentication, private routing decision, and CI/CD design. Endpoint agents must run natively, not as privileged containers.

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
5. **Keep actions narrow and reversible.** Future controls use named, allowlisted operations with confirmation and audit history—never a remote shell.
6. **Collect proportionately.** Connection details are live-only by default; packet payloads and browsing content are outside HAVEN's scope.
7. **Respect every household member.** Monitoring another person's device requires visible opt-in and transparent collection.

## Next security milestone

The next milestone is the authenticated action boundary: browser authentication, origin and anti-forgery protections, finding acknowledgement and accepted-risk notes, an audit ledger, and the first narrowly allowlisted actions such as opening the relevant native settings page or requesting a Defender quick scan. Private HTTPS access, native agent service packaging, deployment resource measurements, and scheduled backups remain gates for the household pilot. GitHub Actions verifies the current Go, frontend, dependency, and public-repository safety checks on each proposed change.

Read the [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [public repository policy](docs/PUBLIC_REPOSITORY.md) before expanding the trust boundary.
