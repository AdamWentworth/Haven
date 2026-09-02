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

Milestone 0.6 performs continuous collection, explainable baseline evaluation, privacy-bounded finding-transition logging, authenticated device reporting, and an authenticated local action boundary. On Windows, the collector launches one fixed, internally defined PowerShell script with no user-controlled commands or parameters. The two available controls also select fixed internal PowerShell commands for a Defender quick scan or security-intelligence update; browser text is never interpolated into them.

The owner registers one or more discoverable passkeys through the cross-platform WebAuthn standard. Windows Hello, platform biometric providers, synchronized phone passkeys, and hardware security keys are authenticator choices rather than HAVEN dependencies. The first passkey requires a one-time local CLI code; the same short-lived mechanism provides local recovery. A signed-in owner can add or remove passkeys, but cannot remove the final credential without a replacement.

Passkey credential data is encrypted at rest with a random key outside the repository. Session and anti-forgery tokens are random; only hashes are stored in SQLite. Trusted-browser sessions expire after 30 days. Mutating routes require an authenticated session, an exact configured Origin, and a matching anti-forgery cookie/header pair. Sensitive actions additionally require a fresh passkey assertion that issues a two-minute, single-use authorization bound to the current session and exact capability. Authentication attempts are rate limited.

The agent endpoint uses TLS 1.3. Enrollment tokens are random, short-lived, one-time values; each accepted certificate has a distinct key and device identity. Observation identity, device identity, sequence, timestamp, schema, media type, body size, and request rate are validated. Revoked devices cannot submit reports.

SQLite and private keys are stored outside the source tree. Historical records exclude live connection details and expire after a bounded period. Development Compose publishes only the dashboard to host loopback. The production profile binds exact private addresses for its dashboard, DNS, and agent listeners and does not expose them through public ingress.

Baseline history contains only bounded posture and counts. HAVEN does not retain administrator names, Windows update titles, Defender threat names, detected file or resource paths, BitLocker recovery keys, or other recovery material. A finding is a local rule evaluation, not proof of compromise or a substitute for native security guidance.

The activity ledger records only finding-opened and finding-resolved transitions using the already bounded finding text. Browser desktop alerts are opt-in, contain no secrets, and operate only while the page is open. HAVEN does not register a privileged tray process or notification service in this milestone.

## Principal threats

### A malicious website accesses the local API

Current mitigations:

- Bind the development hub to loopback.
- Do not enable CORS.
- Require a WebAuthn owner session for observation and control APIs while keeping only health and authentication ceremonies public.
- Require exact-origin and anti-forgery validation for every state-changing dashboard request.
- Return no authentication secrets.
- Send a restrictive Content Security Policy and related browser headers.

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

### A compromised endpoint lies to HAVEN

An agent running on a compromised endpoint cannot be assumed to report trustworthy state. HAVEN will distinguish endpoint-reported observations, hub-observed reachability and certificate state, and independent network-sensor observations. Conflicts remain visible instead of being silently reconciled.

The native Ubuntu agent runs as the existing unprivileged deployment account because production automation cannot create a dedicated system identity without separate host authorization. Its user unit denies access to the Docker socket, exposes its home directory read-only except for the agent identity directory, enables `no-new-privileges`, and applies the filesystem, namespace, syscall, and kernel-tunable restrictions supported by an unprivileged systemd user manager. It never joins a privileged container and receives no command-execution channel from the hub. Root-only posture remains unknown until it can be supplied through a separately reviewed, fixed-output local probe.

### Collection invades household privacy

Mitigations and requirements:

- Obtain explicit consent before installing an agent on another person's device.
- Show exactly which fields each collector gathers.
- Keep live connection details out of historical storage.
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

## Security gates

Remote ingestion, remote access, privileged actions, agent auto-update, account-provider OAuth, and central deployment each require a design review and tests before release. No feature may bypass Defender tamper protection or disable a native firewall service.
