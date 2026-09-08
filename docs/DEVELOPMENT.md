# HAVEN development workflow

HAVEN is Adam Wentworth’s owner-maintained project. The repository is public for transparency, portfolio presentation, and source availability; it is not operated as a collaborative project, and public visibility does not grant or imply repository write access.

This workflow protects a single owner’s project while preserving the separation between reusable product code, private deployment configuration, and private runtime state.

## Decide before building

Start with a concrete observed need. State what should improve, which evidence supports it, what data and privileges it requires, how failure remains visible, and how it will be tested. Changes that expand collection, persistence, remote actions, authentication, deployment authority, or provider access require corresponding architecture and threat-model review.

The [product direction](ROADMAP.md) records ideas already considered and the trigger required before pursuing them. It is acceptable—and often preferable—to leave a plausible feature deferred.

## Git workflow

`main` is protected and represents the latest reviewed, CI-verified source. Required checks are enforced for the owner, so normal work uses a short-lived branch and pull request.

The pull request is an automated verification boundary for the owner’s own changes. It is not a request for outside participation or approval.

Use purpose-based branch names:

- `feature/<outcome>` for user-visible capability;
- `fix/<problem>` for a bounded correction;
- `docs/<topic>` for documentation-only work;
- `refactor/<boundary>` for behavior-preserving restructuring;
- `test/<claim>` for regression evidence.

Do not add an agent, tool, editor, or vendor prefix to branch names unless the owner explicitly asks for one. Keep each pull request focused, wait for every required Linux and Windows check, squash-merge into `main`, and delete the temporary branch. Direct pushes, protection bypasses, force pushes, and moving published tags are not part of the normal workflow.

Branching is a verification boundary, not a second product line: accepted changes end on `main`, and abandoned experiments do not.

## Local development

Local iteration does not require Docker. Build the web client, then run the Go hub against loopback as described in the README and [Getting started](GETTING_STARTED.md). Development state belongs in the operating system’s application-data location, never inside the checkout.

Docker is a deployment artifact for the Linux hub. Endpoint agents remain native because a container cannot truthfully inspect its host without weakening isolation.

## Public and private boundaries

- The public HAVEN repository owns product code, generic packaging, synthetic fixtures, tests, and household-neutral documentation.
- GitHub-hosted workflows verify source and publish immutable images and checksummed artifacts. They do not administer the home server.
- The private operations repository owns real DNS, addresses, interfaces, reverse-proxy and firewall policy, secret mounts, appliance definitions, deployment approval, health checks, and rollback.
- Runtime databases, keys, certificates, enrolled identities, account notes, browser-site decisions, notification subscriptions, and observations remain outside both repositories.

Never change or deploy the private operations repository merely because a HAVEN source change is complete. Production deployment is a separate owner-authorized action using the exact verified commit image. See [Deployment](DEPLOYMENT.md) and [Portability](PORTABILITY.md).

## Privacy guard

Enable the repository-owned pre-commit hook once per clone:

```powershell
pwsh -NoProfile -File .\scripts\Enable-GitHooks.ps1
```

Before publication, run both the guard’s regression test and the full-tree scan:

```powershell
pwsh -NoProfile -File .\scripts\Test-PublicRepository.Tests.ps1
pwsh -NoProfile -File .\scripts\Test-PublicRepository.ps1
```

The local hook provides early feedback; CI is the authoritative backstop. The complete denylist and incident procedure are in [Public repository and portfolio policy](PUBLIC_REPOSITORY.md).

## Verification

Run tests in proportion to the change, then run the complete gates before merge. The authoritative command list and claim-to-test map live in [Verification](VERIFICATION.md).

Tests should prove externally meaningful behavior, privacy limits, failure handling, migration compatibility, and security claims. Do not increase coverage by executing incidental lines without assertions. Use synthetic identifiers and temporary state; automated tests must never contact or modify the live hub, enrolled endpoints, managed appliances, or private operations repository.

## Documentation and releases

- The README explains the product as it exists now.
- Architecture and threat-model documents define maintained boundaries.
- Setup, deployment, portability, and verification documents describe repeatable operations.
- The roadmap records current direction, considered ideas, and decision triggers.
- The changelog contains concise release-level outcomes, not a commit or milestone diary.

Use one semantic version across Go, web, and Electron; the consistency script and CI enforce agreement. Follow [Releasing](RELEASING.md) for versioning, artifacts, tags, deployment identity, and rollback.
