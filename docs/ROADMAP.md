# Project roadmap

HAVEN is pre-release personal security infrastructure. This roadmap describes the next engineering outcomes, not a promise of dates or an archive of every implementation step.

## Current focus: stabilization and distribution

The next milestone is complete when these outcomes are in place:

1. **Smaller web boundaries**
   - Route-level pages and focused hooks replace the oversized application component.
   - Existing URLs, authentication behavior, privacy boundaries, and rendered output remain compatible.
2. **Smaller persistence boundaries**
   - SQLite behavior is organized by storage domain instead of one oversized source file.
   - Existing databases and migrations remain compatible; no owner state is rewritten merely for refactoring.
3. **Stronger regression evidence**
   - Authentication, hub APIs, storage, and route-level UI receive targeted tests where coverage is currently weakest.
   - Coverage floors rise gradually and protect meaningful security behavior rather than rewarding incidental line execution.
4. **Clean-start and recovery exercise**
   - An isolated test uses temporary, synthetic state to exercise bootstrap, enrollment, reporting, backup, and clean reinitialization.
   - It never operates on a live hub, private deployment, real identity, or household data.
5. **Repeatable releases**
   - Version policy, concise release notes, tags, checksummed artifacts, and installation guidance form one documented release path.
   - Windows packages remain clearly identified as unsigned until a deliberate code-signing decision is made.

## After stabilization

- Improve the Windows desktop experience only where it remains a thin, least-privilege client of the hub.
- Expand evidence or controls only when the platform can provide a bounded, testable source of truth.
- Continue reducing private deployment assumptions and document every assumption that cannot be removed.

## Deliberately deferred

- **macOS collection and packaging:** outside the current supported scope until there is a real deployment need and a native collector can be tested responsibly.
- **Always-running Windows service:** deferred until event-driven evidence justifies a resident process and its additional privilege and attack surface.
- **Automatic endpoint updates:** deferred; installation remains an explicit owner or private-operations decision.
- **Public Internet exposure:** not planned. The owner console and agent endpoint remain private-network or VPN services.
- **Paid code signing:** valuable before broad Windows distribution, but not required for source development or the owner's current installation.

## Roadmap rules

- Product source stays public and household-neutral; addresses, credentials, certificates, device identities, firewall policy, and deployment authority stay private.
- A refactor must preserve observable behavior unless its change is separately designed, documented, and tested.
- HAVEN coordinates native protections; it does not become an antivirus, password manager, packet recorder, provider-session authority, or arbitrary remote shell.
- Completed behavior belongs in maintained architecture, threat-model, setup, and verification documentation—not in a chronological README diary.
