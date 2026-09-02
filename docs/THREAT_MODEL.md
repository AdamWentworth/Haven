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

Milestone 0.4 performs read-only collection, explainable baseline evaluation, and authenticated device reporting. On Windows, the Go collector launches one fixed, internally defined PowerShell script with no user-controlled commands or parameters. The dashboard and agent listener bind to loopback by default, there is no CORS policy or remote-control route, and the dashboard sends restrictive browser security headers.

The agent endpoint uses TLS 1.3. Enrollment tokens are random, short-lived, one-time values; each accepted certificate has a distinct key and device identity. Observation identity, device identity, sequence, timestamp, schema, media type, body size, and request rate are validated. Revoked devices cannot submit reports.

SQLite and private keys are stored outside the source tree. Historical records exclude live connection details and expire after a bounded period. The Docker Compose definition publishes only the dashboard to host loopback; it does not publish the agent listener.

Baseline history contains only bounded posture and counts. HAVEN does not retain administrator names, Windows update titles, Defender threat names, detected file or resource paths, BitLocker recovery keys, or other recovery material. A finding is a local rule evaluation, not proof of compromise or a substitute for native security guidance.

## Principal threats

### A malicious website accesses the local API

Current mitigations:

- Bind the development hub to loopback.
- Do not enable CORS.
- Keep the dashboard API read-only and separate from the agent listener.
- Return no authentication secrets.
- Send a restrictive Content Security Policy and related browser headers.

Before adding state-changing routes, HAVEN requires authenticated sessions, origin validation, anti-forgery protection, and reauthorization for sensitive actions. Loopback and private networking are not authentication.

### A compromised dashboard becomes a remote-administration tool

Planned mitigations:

- Never expose arbitrary command, script, file-write, registry-write, or process-launch APIs.
- Model actions as named capabilities with strict schemas.
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
