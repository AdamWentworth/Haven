# Public repository and portfolio policy

HAVEN is intended to be safe to publish and feature in a public portfolio. Source control contains code, documentation, and synthetic fixtures—not observations from a real household.

## Never commit

- Passwords, API keys, OAuth tokens, cookies, authenticator seeds, or recovery codes
- Private keys, client certificates, VPN profiles, certificate-export bundles, or VAPID signing keys
- Web Push subscription endpoints, subscription key material, or exported notification-delivery records
- Account-notebook exports, provider/profile identifiers, private notes, or the account-notebook encryption key
- Real hostnames, usernames, email addresses, device IDs, MAC addresses, or household IP addresses
- Packet captures, event-log exports, crash dumps, databases, snapshots, or application logs
- Screenshots made while HAVEN displays live device, network, or account information
- Local deployment files containing DNS names, mount paths, proxy configuration, or credentials

Use `example.com`, generic device names, and the documentation-only address ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` in examples and tests.

## Repository safeguards

- `.gitignore` excludes dependency trees, generated web assets, credentials, captures, databases, certificates, dumps, and local configuration.
- `scripts/Test-PublicRepository.ps1` checks proposed repository content for common credentials and personal infrastructure identifiers.
- `.githooks/pre-commit` runs the staged-content check before each commit.
- Go modules and npm dependencies have committed checksums or lock files.
- Tests and demo mode use synthetic fixtures. `HAVEN_DEMO_MODE=true` filters every non-synthetic device and never invokes the live collector.
- Once hosted publicly, enable GitHub secret scanning, push protection, dependency alerts, and CodeQL default setup.

Run the check manually with:

```powershell
pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

## Secret and deployment configuration

Development and production secrets belong outside the project tree. Compose secrets or another host-protected secret mechanism should mount sensitive values as files. Environment variables are acceptable for non-secret settings such as ports and retention periods, but a compromised process can read them.

The checked-in Compose file is deliberately generic and loopback-only. Real reverse-proxy names, VPN addresses, certificate locations, enrollment state, and deployment overrides remain private on the server.

Runtime databases and logs belong in operating-system application-data directories or explicit container volumes outside the Git checkout.

HAVEN generates its Web Push VAPID private key and subscription-encryption key inside the private runtime state directory. Browser subscription capabilities are encrypted before database storage. Treat the database, its backups, and any decrypted subscription endpoint as secrets even though notification payloads contain only generic alert metadata.

## Portfolio material

Portfolio screenshots must use `HAVEN_DEMO_MODE=true` after seeding fixtures with `haven-hub demo seed`. Blur is not an adequate substitute because image metadata, missed fields, or later design changes can still disclose information. Verify that every visible device is synthetic before recording.

## If something leaks

Do not merely delete a leaked value in a later commit. Revoke or rotate it first, remove the sensitive artifact from Git history where appropriate, and review access logs and dependent credentials.
