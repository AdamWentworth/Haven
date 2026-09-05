# Portability and reinitialization

HAVEN separates reusable product code from one household's deployment. Cloning this repository should give a new owner the application, schemas, container definition, native-agent packaging, and tests. It must not reproduce a private network, credentials, enrolled device identities, account notes, or reviewed service decisions.

This is a recovery model, not a promise that a second live copy of a home-security hub can be restored beside the first one without coordination.

## Three layers

| Layer | Examples | Where it belongs | Recovery approach |
| --- | --- | --- | --- |
| Portable product | Go hub and agent, React console, Electron source, migrations, generic packaging | This public repository | Clone and build from a reviewed revision |
| Private deployment | Addresses, DNS records, TLS configuration, runner/deployment policy, appliance definitions, secret-file mounts | A private operations repository or host configuration | Reapply after reviewing the new network |
| Private state | SQLite data, encryption keys, passkey credentials, device certificates, account notes, service expectations, push subscriptions | The hub or endpoint state directory | Preserve as one protected unit for continuity, or deliberately reinitialize |

No private layer is required to evaluate HAVEN in local development. A production deployment supplies it explicitly.

## Assumptions ledger

| Concern | Product default or invariant | Deployment-specific choice | If the environment changes |
| --- | --- | --- | --- |
| Development hub | Loopback HTTP on port `5080` | None | Run locally and create fresh development state |
| Production console | Exact private HTTPS origin; the desktop example uses `haven.home.arpa:8443` | Private DNS, reverse proxy, certificate, and listening port | Recreate DNS/TLS, or build the desktop client for the replacement origin |
| Agent API | Separate mutually authenticated endpoint; local default is loopback `5443` | Reachable private address, TLS trust root, and firewall policy | Re-enroll agents against the new endpoint if identity state is not preserved |
| Device identity | Random enrollment identity plus a friendly owner-selected label | Device names and installation schedule | Re-enroll and reuse meaningful labels; hostnames are evidence, not identity |
| Collection schedule | Fifteen-minute reporting by default | Windows Task Scheduler or a systemd user timer | Re-run the idempotent native installer on each endpoint |
| Network services | Ports are observed and unreviewed by default | Expected labels, process owners, workloads, bind scope, and optional ranges | Review the new network instead of copying obsolete expectations blindly |
| Host firewall | Read-only verification | Interface names, subnets, VPN routing, and permitted ports | Rebuild firewall policy outside HAVEN, then let HAVEN verify the result |
| Managed appliances | Explicit private-unicast targets only; no discovery | Addresses, required services, SNMP/SSH secret files, and host-key pins | Recreate the private appliance file and re-pin changed identities |
| Browser/account review | Bounded local evidence and encrypted owner notes | Profile labels and owner classifications | Re-review after a browser profile or OS is rebuilt |
| Notifications | Owner opt-in, destination-specific Web Push | Browser permission and subscription | Enroll the replacement browser again |
| Electron client | One exact HTTPS origin embedded at build time | Which trusted workstation receives the installer | Rebuild only for workstations where a dedicated client is useful |

Port numbers such as a custom WireGuard listener are deliberately not universal product knowledge. HAVEN may show the observed port and its attributed process; the owner decides whether it belongs in that deployment's expected-service baseline.

## Fresh start on a replacement network

1. Clone a reviewed HAVEN revision. Restore the private operations repository separately, if one exists.
2. Choose a stable private DNS name for the hub. A `.home.arpa` name is appropriate for home networks, but the exact name and port are deployment choices.
3. Provision the hub host, persistent state directory, private TLS, and separate agent endpoint. Keep both listeners private; do not publish them directly to the Internet.
4. Start the hub and verify its database-backed readiness endpoint.
5. Either restore the complete protected state directory before accepting traffic, or start clean. Never mix a database from one backup with encryption keys from another.
6. For a clean start, generate the local bootstrap code and register the first owner passkey.
7. Re-enroll each native endpoint using the new private agent URL and CA, then install its background schedule. Use stable, human-readable labels rather than IP addresses.
8. Recreate managed-appliance definitions from the private deployment layer. Reconfirm every address, SSH host-key fingerprint, and required service.
9. Let one full observation arrive from every endpoint. Review findings and create a new expected-service baseline from current process/workload attribution.
10. Enroll push notifications in the browsers that should receive them. Build and install the Electron client only on an administrative workstation where it improves access.

This process favors re-verification over silently carrying old network assumptions into a different environment.

## Continuity versus clean reinitialization

A continuity recovery preserves history and owner decisions. Stop the hub, copy its complete state directory as one unit, protect that copy like a credential backup, restore it before startup, and validate permissions and readiness. The directory includes the database and multiple encryption identities; partial copies can be internally consistent at the filesystem level while still making encrypted records unrecoverable.

A clean reinitialization requires no private backup. It intentionally loses historical observations, expected-service approvals, account-notebook records, passkeys, agent identities, and notification subscriptions. The hub remains recoverable because each of those relationships can be established again from the owner-controlled machines and providers.

For a personal pre-release deployment, the clean-start drill above is the more useful portability test. A destructive restore rehearsal should wait until HAVEN has a dedicated, versioned export manifest and an isolated test environment; it should never be improvised against the live household hub.

## Read-only diagnostics

Milestone 0.24 makes the recovery model inspectable without adding an automated repair surface:

```powershell
haven-hub doctor
haven-hub doctor --json
haven-agent doctor
haven-agent doctor --json
```

The hub command verifies that the configured state directory and SQLite header are readable, the protected owner-material manifest is complete, the hub authority and server certificate chain are valid, the owner origin is HTTPS, and both listeners are structurally configured. When the hub is already running, the System & Recovery page uses its existing database connection for a stronger readiness probe. The offline CLI deliberately does not open the application store because doing so could create a database or apply migrations.

The agent command verifies its existing configuration, client certificate chain, locally recorded accepted-report sequence, and packaged installation identity. It does not contact the hub, submit a report, create a directory, enroll, repair a scheduler, or rotate a certificate. A failed check produces a non-zero exit after all results are printed; an advisory identifies a bounded follow-up such as an identity nearing expiry.

Both formats include the same fixed redacted recovery checklist. Output never includes actual paths, hostnames, addresses, device IDs, account details, certificate contents, or secret values. The dashboard report is authenticated and sent with `Cache-Control: no-store`.

## Desktop origin configuration

The Electron application remains pinned to one exact HTTPS origin. The origin is selected when the installer is built, not from an environment variable when the installed app launches:

```powershell
Set-Location .\desktop
$env:HAVEN_DESKTOP_ORIGIN = "https://security.home.arpa:9443"
npm ci
npm run dist:windows
```

The build rejects HTTP, credentials, paths, queries, and fragments. If the variable is omitted, the conventional development/deployment example `https://haven.home.arpa:8443/` is used. Changing networks does not require installing the client on every endpoint; rebuild it only if the hub's exact origin changes.

## Public-clone boundary

A public clone must be safe before it is useful. The repository therefore contains placeholders and conventional defaults, not:

- private IP addresses or interface names;
- TLS, enrollment, SNMP, SSH, notification, or encryption secrets;
- real device or browser-profile inventories;
- account identifiers or security-review notes;
- owner-approved service baselines; or
- deployment credentials and runner authority.

Use synthetic demo data for portfolio images and keep the household-specific layer private. See [Public repository policy](PUBLIC_REPOSITORY.md), [Deployment](DEPLOYMENT.md), and [Threat model](THREAT_MODEL.md).
