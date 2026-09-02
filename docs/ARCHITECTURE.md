# HAVEN architecture

## Direction

HAVEN is a browser-first, agent-based personal security observatory.

```text
Windows agent ─┐
Linux agent ───┼── outbound mutually authenticated observations ──> HAVEN Hub
macOS agent ───┘                                                        │
                                                                        ├── SQLite
Private browser clients ─────────── private HTTPS ──────────────────────┘
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
| Desktop shell | Optional Tauri wrapper | Reuse the web interface only if tray or native notifications justify it |

PostgreSQL becomes appropriate if HAVEN needs multiple hub writers, multiple hub replicas, sustained high-volume flow telemetry, multi-tenant hosting, or concurrency that batching cannot handle. Storage-specific behavior remains inside `internal/storage`, but supporting two engines simultaneously is not a current goal.

## Current milestone boundary

Milestone 0.5 turns the explainable Windows baseline into a continuous local monitor while remaining local-only by default:

- `haven-hub` serves a loopback dashboard, performs local collection, owns SQLite, and exposes a separate loopback TLS 1.3 agent listener.
- Enrollment uses a short-lived, one-time 256-bit token plus an ECDSA P-256 certificate request. The trusted CA certificate is transferred out of band.
- Every agent receives a unique 90-day client certificate whose URI identity must match its observation envelope and database record.
- Reports have a version, random identity, strictly increasing per-device sequence, and bounded timestamp. Replays, revoked devices, oversized bodies, unsupported versions, and excessive request rates are rejected.
- The hub stores posture but removes connection metadata before persistence. There is no remote-control endpoint.
- The Compose dashboard remains loopback-only and its agent listener is not published.
- Observation schema version 2 adds privacy-bounded Windows posture. The hub derives checks and findings from raw signals so severity logic stays reviewable and consistent.
- Findings use explicit evidence and recommendations rather than a combined score. Unavailable data remains unknown, never healthy.
- The local hub collects immediately at startup and on a bounded interval. Manual and scheduled collections are serialized so the fixed native collector cannot run concurrently with itself.
- SQLite stores an append-only transition event only when an evaluated finding opens or resolves. Unchanged observations do not create activity noise.
- The browser can request desktop-notification permission and alerts only on newly opened high- or medium-severity findings while the page is open. Notification state stays in browser-local storage.
- A configured state distinguishes intentionally enabled services with verified compensating controls from both healthy defaults and actionable findings. The Windows collector can verify TPM readiness without elevation and summarizes RDP firewall scope without retaining rule names or network addresses.

The trusted inventory contains only the local collector and explicitly enrolled agents. HAVEN does not infer trust from sharing a network. Any future network-discovery view will keep merely observed assets separate from enrolled devices, and another household member's device requires informed opt-in before an agent is installed.

Windows baseline collection stores configuration state and aggregate counts only. It excludes local administrator names, update titles, Defender threat names, detection resource paths, and BitLocker recovery material.

Browser authentication, private network publication, automated certificate renewal, native service packaging, and CI/CD deployment are gates for the household pilot rather than assumptions hidden in local development.

## Storage and retention

Agents will send high-level observations to the hub, never SQL. The SQLite file remains on local storage beside its WAL files in a persistent container volume.

- Posture observations expire after 90 days by default; deployment configuration can shorten that period.
- Live TCP connection details are returned to the dashboard but removed before a snapshot is stored.
- Finding-transition events retain the privacy-bounded category, title, severity, and summary already present in posture history; they never copy connection details or excluded identifiers.
- Packet payloads, browser content, keystrokes, screenshots, and document contents are never collected.
- Future high-volume network summaries receive shorter retention than posture changes.
- Account-security records contain status metadata, never passwords, recovery codes, authenticator seeds, cookies, or refresh tokens unless a separately reviewed integration makes a token unavoidable.
- Portfolio and demo modes use synthetic fixtures only.

## Hub container boundary

The production container contains the Go hub and compiled web assets. It runs as a non-root user with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a bounded temporary filesystem, and one writable data volume.

The Compose file publishes to host loopback. Deployment-specific private access belongs behind a TLS reverse proxy or VPN and must not be committed with real hostnames, addresses, certificate identities, or credentials.

## Planned deployment stages

1. **Local foundation:** validate Windows collection, UI, persistence, privacy behavior, and container build.
2. **Trust foundation:** define versioned messages, enrollment, device certificates, mutual TLS, revocation, and replay resistance.
3. **Household pilot:** deploy the Dockerized hub and one native Windows service through private authenticated access.
4. **Multi-platform:** add least-privileged Linux and macOS agents, preserving platform-specific security meaning.
5. **Narrow controls:** add separately privileged allowlisted actions only after the read-only system is trustworthy.
