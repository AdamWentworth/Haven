# Release process

HAVEN uses one semantic release number across the Go hub and agents, web package, and Electron client. `scripts/Test-VersionConsistency.ps1` enforces agreement; Electron reads its user-agent version directly from its package manifest.

## Prepare a release

1. Work on a short-lived, purpose-named branch following the [owner’s development workflow](DEVELOPMENT.md); do not add an agent or tool prefix unless the owner requests one. Keep product behavior, migrations, privacy boundaries, and deployment implications explicit.
2. Update the release version in `internal/buildinfo/buildinfo.go`, `web/package.json`, both npm lockfiles, and `desktop/package.json`.
3. Add one concise entry to `CHANGELOG.md`. Record user-visible behavior and operational compatibility, not a commit diary.
4. Run the required local gates in `VERIFICATION.md`, including the version and public-repository checks.
5. Merge only after the Linux and Windows CI jobs pass. The exact merged commit is the release candidate.

## Identify and distribute it

1. Create an annotated `vX.Y.Z` tag on the already-verified main-branch commit; never move a published tag.
2. Use the checksummed endpoint-agent artifact and Windows installer produced by CI for that exact commit. Artifacts from different revisions are not interchangeable even when their release number matches.
3. Deploy the immutable hub image tagged `sha-<full commit>` through the private operations repository. The floating `main` image is convenient for inspection, not deployment identity.
4. Keep Windows installers clearly described as unsigned until code signing is deliberately introduced. Verify the source revision, checksum, and expected private HAVEN origin before installing.
5. Upgrade the hub before reporters whenever the release notes describe an additive observation field that an older strict decoder would reject. Otherwise, update endpoints individually and confirm a fresh authenticated report after each one.

GitHub-hosted workflow artifacts currently expire after 30 days. A durable public release attachment can be added when HAVEN is ready for broader distribution; until then, source tags plus immutable commit and image identities are authoritative.

## Rollback

Application rollback means redeploying a previously verified immutable hub image. State rollback is separate: restore the complete protected state set described in `PORTABILITY.md`, never a database without its matching keys and trust material. Endpoint binaries are replaced only through an explicit owner or private-operations action.
