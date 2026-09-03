# Hub deployment

HAVEN's production hub runs in resource-bounded containers on the always-on Ubuntu application server. Development workstations continue to run the Go process directly; Docker is not required there.

## Delivery model

The public repository does not use a persistent self-hosted GitHub Actions runner. GitHub-hosted CI performs the tests and publishes one immutable GHCR image for each successful push to `main`. A separate private HomeOps repository owns the production runner, Compose model, DNS and TLS configuration, backup service, health checks, and rollback procedure. HAVEN sends only an allowlisted repository identity and full approved commit hash across that boundary.

The private workflow independently confirms that the hash is the current HAVEN `main` revision, pulls its commit-tagged image, and verifies the embedded revision label. Public repository workflow code never executes directly on the household server, and the hub container does not receive the Docker socket, host namespaces, devices, broad host mounts, or privileged mode.

## Private access

The production profile uses three small services:

- `hub`: the Go API, embedded dashboard, SQLite, mutually authenticated agent endpoint, and durable alert evaluator;
- `proxy`: private HTTPS for the dashboard through a dedicated Caddy internal authority;
- `dns`: a private `haven.home.arpa` record with recursive forwarding for clients that select the server as their DNS resolver.

The dashboard is published only on the configured LAN address and high HTTPS port. The agent endpoint is a separate TLS 1.3 listener with a certificate containing the configured private DNS name and address. Neither endpoint should be forwarded from the public internet. WireGuard clients can use the same hostname by selecting the private DNS resolver and routing the LAN subnet.

Web Push is disabled until an owner enrolls a browser. Once enabled, the hub needs outbound DNS and HTTPS access to that browser's vendor push service; it does not need another inbound port. The sender rejects redirects and any destination that resolves to a private, loopback, link-local, multicast, or non-global address. Browser push services observe delivery metadata even though payload contents are encrypted.

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

SQLite, the WebAuthn credential-encryption key, the Web Push subscription-encryption key, the VAPID identity, and the agent PKI live together in the configured data directory. Caddy's private authority lives in its separate data directory. All are outside the repository.

The daily backup service uses HAVEN's SQLite backup command and then archives:

- the consistent SQLite backup;
- the WebAuthn credential-encryption key;
- the Web Push subscription-encryption key and VAPID identity;
- the hub/agent private authority;
- the dashboard private authority required to preserve existing client trust.

Backup archives contain security-sensitive private keys and are created with owner-only permissions. A second encrypted or physically protected copy and a tested restoration procedure are still required before the deployment can be treated as durable.

## Native agents

Endpoint agents run directly under Windows Service Control Manager, systemd, or launchd with the smallest privileges their collectors require. The current remote protocol accepts read-only observations through per-device mutual TLS. Remote action execution is not implemented and must not be simulated with a shell or Docker access.

The Ubuntu application server runs a separate native agent even though it also hosts the hub container. Its stable host identity is independent from both the Linux login name and Docker's ephemeral container hostname. The private deployment extracts the CI-built agent from the same revision-pinned image, enrolls it once as `Ubuntu Application Server`, and schedules reports with the lingering user systemd manager. The reporting service starts without an interactive login, blocks both conventional Docker-socket paths, makes the home and system trees read-only, and writes only its dedicated identity directory.

Before each report, systemd starts a distinct one-shot Docker inventory exporter. Docker socket access is root-equivalent; this helper is intentionally short-lived, has only the Unix address family, and can write only the agent state directory. It queries the fixed running-container list endpoint and writes a sanitized mode-0600 inventory. The normal reporting service starts after it exits, validates the file, and correlates host listeners with published mappings. Environment variables, commands, mounts, arbitrary labels, logs, IDs, container network addresses, and Docker control operations are excluded. The hub removes this inventory before historical persistence.
