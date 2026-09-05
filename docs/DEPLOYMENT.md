# Hub deployment

HAVEN's production hub runs in resource-bounded containers on the always-on Ubuntu application server. Development workstations continue to run the Go process directly; Docker is not required there.

## Delivery model

The public repository does not use a persistent self-hosted GitHub Actions runner. GitHub-hosted CI performs the tests and publishes one immutable GHCR image for each successful push to `main`. A separate private HomeOps repository owns the production runner, Compose model, DNS and TLS configuration, backup service, health checks, and rollback procedure. HAVEN sends only an allowlisted repository identity and full approved commit hash across that boundary.

The private workflow independently confirms that the hash is the current HAVEN `main` revision, pulls its commit-tagged image, and verifies the embedded revision label. Public repository workflow code never executes directly on the household server, and the hub container does not receive the Docker socket, host namespaces, devices, broad host mounts, or privileged mode.

## Private access

The reference production profile uses three small services:

- `hub`: the Go API, embedded dashboard, SQLite, mutually authenticated agent endpoint, and durable alert evaluator;
- `proxy`: private HTTPS for the dashboard through a dedicated Caddy internal authority;
- `dns`: a conventional private `haven.home.arpa` record with recursive forwarding for clients that select the server as their DNS resolver. The exact name is a private deployment choice.

The dashboard is published only on the configured LAN address and high HTTPS port. The agent endpoint is a separate TLS 1.3 listener with a certificate containing the configured private DNS name and address. Neither endpoint should be forwarded from the public internet. WireGuard clients can use the same hostname by selecting the private DNS resolver and routing the LAN subnet.

Web Push is disabled until an owner enrolls a browser. Once enabled, the hub needs outbound DNS and HTTPS access to that browser's vendor push service; it does not need another inbound port. The sender rejects redirects and any destination that resolves to a private, loopback, link-local, multicast, or non-global address. Browser push services observe delivery metadata even though payload contents are encrypted.

## Optional managed-NAS health

Basic appliance reachability needs no credentials. Full NAS health is an explicit private deployment choice. Store a unique random SNMP community and a dedicated unencrypted Ed25519 private key as owner-readable files outside Git, mount them read-only into the hub, and reference only their container paths from the private managed-appliance configuration. SNMP v2c must remain restricted to the trusted LAN because it does not encrypt its community or response.

Install the matching architecture's `haven-nas-probe` binary on the appliance as a root-owned mode-0755 file. The corresponding `authorized_keys` entry must be limited to the hub host and use `command="/usr/local/sbin/haven-nas-probe",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty`. Verify that requesting an unrelated SSH command still returns only the health JSON before enabling the provider. Password-based administrator access is separate from this key and is not used or stored by HAVEN.

The helper does not accept arguments and must not be generalized into a remote shell. It excludes disk serials, accounts, shares, filenames, and network configuration; SMART checks use standby-safe behavior. Appliance firmware upgrades may remove a manually installed helper, so revalidate the forced command, file ownership, and health coverage after each vendor OS upgrade.

The container must set `HAVEN_LOCAL_COLLECTION_ENABLED=false`. A container cannot truthfully observe its Linux host without weakening isolation, and its generated container hostname is not a household device identity. Only native agents appear in the production trusted inventory. If an earlier pre-release deployment created container-host records, back up the hub and run `haven-hub device prune-local --confirm`; the command removes only `local` collector devices and their observation history, preserving enrolled devices, authentication, audit history, and PKI.

Passkeys are bound to the exact private HTTPS origin. Choose the permanent hostname and port before enrolling production passkeys.

## First installation

Production templates and the runner workflow belong to private HomeOps. Real addresses and filesystem paths belong only in the server's untracked `.env` file.

1. Allow GitHub-hosted HAVEN CI to verify and publish the commit-tagged hub image.
2. Register the production runner only with the private HomeOps repository.
3. Install HomeOps' untracked HAVEN environment on the server and create its data, TLS, and protected backup directories.
4. Manually dispatch the first exact HAVEN `main` revision from HomeOps and verify the dashboard, DNS record, container limits, and backup timer.
5. After the manual path is proven, enable the public CI workflow's narrowly scoped cross-repository dispatch credential.

After the proxy generates its internal authority, install only its public root certificate in each owner's trust store. Never copy the authority private key to a client. Configure LAN clients—or the router's DHCP service—to use the private resolver. WireGuard client profiles can use the same resolver explicitly.

## Persistent data and recovery

SQLite, the WebAuthn credential-encryption key, the account-notebook encryption key, the browser-site-review encryption key, the Web Push subscription-encryption key, the VAPID identity, and the agent PKI live together in the configured data directory. Caddy's private authority lives in its separate data directory. All are outside the repository.

The daily backup service uses HAVEN's SQLite backup command and then archives:

- the consistent SQLite backup;
- the WebAuthn credential-encryption key;
- the account-notebook encryption key;
- the browser-site-review encryption key;
- the Web Push subscription-encryption key and VAPID identity;
- the hub/agent private authority;
- the dashboard private authority required to preserve existing client trust.

Backup archives contain security-sensitive private keys and are created with owner-only permissions. A second encrypted or physically protected copy and a tested restoration procedure are still required before the deployment can be treated as durable.

## Native agents

Endpoint agents run natively with the smallest privileges their collectors require. The current Windows collector is a one-shot GUI-subsystem executable launched directly by a per-user Task Scheduler task; every PowerShell child is created with Windows' no-console flag. The separate interactive executable remains available for enrollment and diagnostics. Linux uses systemd, and future macOS packaging will use launchd. A future event-driven Windows sensor may use Service Control Manager only when continuous Defender or Windows Event Log monitoring justifies a persistent process. The current remote protocol accepts read-only observations through per-device mutual TLS. Remote action execution is not implemented and must not be simulated with a shell or Docker access.

Every current report carries the reporter's public release, immutable source revision, platform, bounded installation kind, observed capabilities, and current collection-notice count. The hub first validates the observation schema. An accepted report from a different release is displayed as protocol compatible rather than as an update requirement; an exact build match remains stronger provenance. Milestone 0.18 reporters add an optional privacy-bounded browser-security object under observation schema 2; milestone 0.19 extends that object with fixed Chrome session-protection evidence and optional meaningful extension changes; milestone 0.20 adds bounded live-only Chrome profile and domain-level cookie metadata. Deploy the 0.20 hub before updating agents because older strict decoders do not recognize the profile field. The console-free Windows artifact embeds `windows-task` so an older scheduled task that still invokes plain `report` remains truthful after an in-place binary update; systemd invocations are recognized from systemd's own execution environment. Older reporters remain visible without newer optional evidence until deliberately updated; no hub process pushes or installs binaries on an endpoint.

GitHub-hosted CI attaches a checksummed agent bundle to each verified commit for 30 days. The public Windows installer builds and stamps the current checkout, repairs an existing task in place, and preserves enrollment. Its status companion is read-only; its high-confirmation uninstaller preserves identity unless identity removal is separately requested. The Linux lifecycle script provides the corresponding source-based user-systemd workflow. Private HomeOps may instead extract the revision-matched Linux binary from the approved hub image, but it must retain the same systemd sandbox and verify the embedded revision before activation.

Deploy the 0.20 hub before updating an endpoint binary. The newer hub accepts older reports without Chrome profile metadata, while an older strict decoder rejects the new profile field. No database migration is required because Chrome profile metadata exists only in the latest in-memory observation and is removed before historical persistence. After the hub readiness check succeeds, update reporters one endpoint at a time and require a current report before proceeding to the next device.

Milestone 0.21 does not change the agent observation schema. The hub applies one additive SQLite migration for encrypted browser-site classifications and creates a dedicated `browser-site-reviews.key` in its private state directory. Back up that key with the database: losing it makes the classifications unreadable. Existing agents remain protocol-compatible, although updating them keeps fleet release/revision evidence aligned.

Milestone 0.22 changes only the web projection and documentation. It adds no observation fields, database migration, secret, collector permission, endpoint command, or notification policy. Existing 0.21 agents remain fully protocol-compatible; updating their displayed build version is optional and only keeps fleet release evidence aligned.

Milestone 0.23 adds no observation field, database migration, endpoint permission, or remote action. It records the public/private/state portability boundary, removes household-specific service guesses from reusable code, makes the Electron origin a validated build-time choice, and presents every accepted current-schema agent as protocol compatible even when release numbers differ. See [Portability and reinitialization](PORTABILITY.md) before moving the hub or rebuilding a network.

Each updated agent creates `browser-extension-baseline.json` inside its existing private state directory after the hub accepts its first 0.19 report. That first baseline is intentionally quiet. Preserve this file with the agent identity when repairing or moving an installation; deleting it safely causes another silent baseline rather than a flood of historical extension alerts. The file contains friendly extension names and coarse capability state, so protect and back it up with the same owner-only permissions as the rest of the endpoint identity directory.

The public `packaging/systemd` definitions provide a generic, unprivileged Linux timer and a hardened one-shot reporting service. They contain no endpoint address, enrollment token, certificate, device identity, username, or private deployment path. Installers must create the per-user state directory before activation and enable lingering deliberately when reporting must continue without an interactive login.

The Ubuntu application server runs a separate native agent even though it also hosts the hub container. Its stable host identity is independent from both the Linux login name and Docker's ephemeral container hostname. The private deployment extracts the CI-built agent from the same revision-pinned image, enrolls it once as `Ubuntu Application Server`, and schedules reports with the lingering user systemd manager. The reporting service starts without an interactive login, blocks both conventional Docker-socket paths, makes the home and system trees read-only, and writes only its dedicated identity directory.

Before each report, systemd starts a distinct one-shot Docker inventory exporter. Docker socket access is root-equivalent; this helper is intentionally short-lived, has only the Unix address family, and can write only the agent state directory. It queries the fixed running-container list endpoint and writes a sanitized mode-0600 inventory. The normal reporting service starts after it exits, validates the file, and correlates host listeners with published mappings. Environment variables, commands, mounts, arbitrary labels, logs, IDs, container network addresses, and Docker control operations are excluded. The hub removes this inventory before historical persistence.
