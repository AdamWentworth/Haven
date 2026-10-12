# Changelog

HAVEN's notable user-facing and operational changes are recorded here. The README describes the product as it exists today; it does not duplicate this history.

## 0.27.1 - 2026-10-11

### Changed

- Added owner-selectable reporting expectations: always-on devices retain overdue alerts; intermittently used devices show neutral absence and a quiet weekly check-in reminder.
- Label older endpoint evidence as last observed, and keep expected absence separate from security findings and current coverage.
- Preserve the observation protocol and collection permissions. An additive database migration defaults existing devices to their previous always-on behavior.

## 0.27.0 - 2026-09-07

### Changed

- Split the largest web application and SQLite storage modules into focused, domain-oriented files without changing routes, schemas, or owner state.
- Replaced the README's implementation diary with a concise current-scope summary and outcome-based roadmap.
- Raised frontend and Go coverage floors to reflect the current regression suite.
- Made the Electron user-agent version derive from its package manifest and added a repository-wide version consistency gate.

### Added

- Added targeted device-panel tests for unknown evidence, inactive firewall policy, listener grouping, expected-service ownership, finding lifecycle, and clear posture.
- Added an isolated synthetic continuity test covering bootstrap, agent enrollment, authenticated reporting, protected-state backup, restoration, and clean reinitialization.
- Added maintained roadmap and release-process documentation.

No observation schema, database schema, collection permission, remote action, deployment secret, or private-network setting changes in this release.
