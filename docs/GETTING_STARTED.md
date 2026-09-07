# Getting started

HAVEN is portable, but it is not zero-configuration infrastructure. A public clone contains the hub, agents, console, database migrations, local Compose profile, native installers, and tests. It intentionally does not contain the private DNS, TLS, firewall rules, device identities, or credentials needed to reproduce somebody else's network.

## Supported surfaces

| Surface | Current status | Important boundary |
| --- | --- | --- |
| Hub from source | Supported on Windows and Ubuntu | Native local collection reflects the host OS; production normally disables it and uses an enrolled native agent |
| Containerized hub | Supported on a Linux Docker host | The checked-in Compose profile is loopback-only evaluation, not a production network publication |
| Windows endpoint | Supported | Native collector plus an elevated, console-free per-user Task Scheduler reporter |
| Ubuntu endpoint | Supported | Native collector plus a hardened systemd user timer; other Linux distributions may provide only partial evidence |
| Web console | Supported in a modern browser | Production passkeys require one stable private HTTPS origin |
| Electron client | Windows installer supported | Linux and macOS packages are not currently produced |
| macOS endpoint | Not supported | The fallback collector reports the platform as unsupported; no native evidence or launchd installer exists yet |

“Supported” means the repository contains the implementation and verification described in [Verification](VERIFICATION.md). It does not mean every OS release, Linux distribution, browser, router, or appliance has been certified.

## How the pieces fit

```text
Windows / Ubuntu endpoints
          │
          │ outbound TLS 1.3 with one certificate per device
          ▼
      HAVEN hub ─── SQLite and encryption keys in one private state directory
          │
          ├── private HTTPS ── browser or Electron owner console
          └── bounded probes ─ managed appliances explicitly configured by the owner
```

The hub never discovers or silently enrolls devices. Each endpoint is named, enrolled, and scheduled deliberately. Agents report outward to the hub; the hub does not open a management listener on an endpoint.

## Evaluate from source

Install Go and Node.js versions compatible with `go.mod` and the committed npm lockfiles. Build the embedded console, then start the hub.

PowerShell:

```powershell
Set-Location .\web
npm ci
npm run build
Set-Location ..
go run .\cmd\haven-hub
```

Bash:

```bash
cd web
npm ci
npm run build
cd ..
go run ./cmd/haven-hub
```

Open `http://localhost:5080`. In a second terminal, create the first short-lived owner bootstrap code:

```text
go run ./cmd/haven-hub auth bootstrap
```

The development hub stores state in the current user's operating-system application-data directory, not in the checkout. `localhost` is a deliberate WebAuthn development exception; a production owner origin must use HTTPS.

The checked-in Compose profile offers a second loopback-only evaluation path:

```text
docker compose up --build
```

It maps the console and agent endpoint only to host loopback. Do not treat that profile as a production LAN deployment merely by changing a port binding.

## Prepare a production hub

A production owner supplies a private operations layer with:

1. An always-on Linux host and persistent state storage.
2. One stable private HTTPS origin for the console and passkeys.
3. A separate private address and TLS identity for the mutually authenticated agent endpoint.
4. Private DNS or another dependable name-resolution path for LAN and VPN clients.
5. Explicit firewall policy; neither endpoint should be forwarded from the public Internet.
6. Protected backups of the complete hub state and private HTTPS authority.
7. Optional appliance definitions and credentials stored outside Git.

The exact reverse proxy, DNS service, addresses, interfaces, secret mounts, runner authority, and rollback policy are deployment choices. HAVEN's public CI builds a verified image, while the reference deployment keeps those choices in a separate private operations repository. See [Deployment](DEPLOYMENT.md) before publishing either listener.

## Enroll an endpoint

After the production hub is healthy, create a short-lived token on the hub:

```text
haven-hub enrollment create --name "Desk Workstation"
```

Transfer the hub's public agent CA certificate to the endpoint through a trusted channel. Then run the endpoint's matching `haven-agent` binary and paste the token only when prompted:

```text
haven-agent enroll --hub <private-agent-https-url> --ca <trusted-ca-file> --name "Desk Workstation"
haven-agent report
```

Enrollment creates a unique, revocable client identity in that user's application-data directory. It does not install background scheduling. After the first report succeeds:

- Windows: run `scripts/Install-WindowsAgentTask.ps1` from an elevated PowerShell session.
- Ubuntu: run `./scripts/Install-LinuxAgent.sh install` as the user who owns the enrolled identity.

Both installers can build from a reviewed checkout or accept a prebuilt agent only with its expected SHA-256. They preserve the enrolled identity during ordinary repair and uninstall workflows. Repeat enrollment separately on every trusted endpoint; installing the Electron client is optional and does not enroll that computer as an agent.

## What does not “just work”

- A clone cannot know which machine should be the hub or which devices its owner trusts.
- Production TLS, DNS, firewall rules, backups, and public/private routing are not generated automatically.
- Windows and Ubuntu expose different evidence; unsupported signals remain unknown rather than being invented.
- macOS security collection and launchd packaging have not been implemented.
- Moving only the SQLite file is not a restore. Continuity requires the complete protected state directory; otherwise initialize a clean hub and re-enroll.

That friction is intentional where an automatic guess could expose the hub, trust the wrong device, overwrite identity, or copy one household's assumptions into another. The [Portability guide](PORTABILITY.md) covers a clean move or OS reinstall.
