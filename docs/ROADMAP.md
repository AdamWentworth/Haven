# Product direction and considered work

HAVEN is pre-release personal security infrastructure. This document records the current direction, ideas already considered, and the evidence that would justify resuming implementation. It is intentionally not a calendar, commitment, or milestone diary.

## Current phase: operate, observe, and learn

Version 0.27 completed the immediate stabilization work: the largest web and storage modules have clearer boundaries, regression gates are stronger, synthetic continuity and clean-start paths are exercised, and the public release process is documented.

There is no active 0.28 feature milestone. The useful work now is to:

1. Deliberately deploy a verified 0.27 revision through the private operations repository when the owner is ready.
2. Confirm that enrolled agents, the managed NAS, notifications, account notes, and reviewed service baselines remain healthy after deployment.
3. Use HAVEN normally rather than manufacturing test activity or new alerts.
4. Record actual friction, false positives, unclear evidence, missed security questions, or recurring manual work.
5. Resume engineering only when those observations support one coherent outcome.

Source readiness and production deployment are separate facts. The version displayed by the live HAVEN System & Recovery page is the authority for the running hub; the public repository does not claim that a particular household has deployed its newest commit.

## How an idea becomes planned work

A candidate should become an implementation milestone only when it has:

- a concrete owner need or repeatedly observed product problem;
- a security, reliability, privacy, or usability improvement that can be stated precisely;
- a bounded source of truth on every supported platform it affects;
- an explicit data-retention and privilege model;
- testable success and failure behavior;
- a migration and rollback story when persisted state or deployment behavior changes.

Novelty, a convenient version number, or the existence of a possible feature is not enough. Small related fixes can ship without inventing a milestone; substantial work should have one theme and written exit criteria.

## Considered next steps

| Idea | Potential value | Evidence or trigger required | Current decision |
| --- | --- | --- | --- |
| HAVEN-state backup bundle | Preserve the hub database, HAVEN keys, certificates, enrollment continuity, and owner decisions after hub loss | Rebuilding that state becomes materially costly, or a real recovery requirement is chosen | Deferred. It would cover HAVEN state only, never monitored-device files, cookies, passwords, or unrelated secrets. The owner must choose the private destination and recovery-key model first. |
| Verified restore command | Make continuity recovery repeatable without improvising against a live hub | A versioned backup format exists and can restore only into an empty destination | Deferred with the backup bundle. Synthetic continuity and clean reinitialization are already tested. |
| Durable GitHub releases | Keep installers and agent artifacts beyond the current workflow-artifact retention window | HAVEN is distributed beyond its owner, or durable rollback artifacts become necessary | Deferred. Immutable commit images and short-lived checksummed CI artifacts are sufficient for current use. |
| Additional UI or Electron polish | Reduce friction in the owner’s primary console | A repeatable layout, navigation, accessibility, notification, or authentication problem appears during normal use | Improve from observed issues only. Do not redesign for activity’s sake. |
| Higher-risk code coverage | Increase confidence in authentication, hub handlers, storage, Network, and System & Recovery behavior | A behavior change touches those areas or a concrete untested failure mode is identified | Continue incrementally. Coverage floors should protect claims, not reward incidental execution. |
| Native Windows service | Support genuinely event-driven collection without scheduled process startup | A required signal cannot be collected by the quiet one-shot scheduled reporter | Deferred. A resident privileged process would add attack surface and operational complexity. |
| Automatic endpoint updates | Reduce manual agent replacement | Manual updates become error-prone across a meaningfully larger fleet and a signed rollback design exists | Deferred. Endpoint installation remains an explicit owner or private-operations action. |
| macOS agent and packaging | Extend native posture collection to Macs | A consenting Mac owner wants enrollment and the collector can be built and tested on real supported hardware | Outside current scope. A generic Go binary is not meaningful macOS security monitoring. |
| Phone agent | Add mobile-device posture | Mobile platforms expose useful, permission-bounded evidence that materially improves this household’s view | Deferred. The responsive dashboard and push notifications already support phone access without another privileged agent. |
| Provider-connected account checks | Verify sessions, MFA, and recovery settings automatically | Providers offer stable least-privilege APIs without turning HAVEN into a high-value OAuth-token vault | Keep the account notebook manual for now. Never infer provider state from cookies. |
| More cookie/session intelligence | Make browser evidence easier to review | A browser exposes additional privacy-bounded metadata with a defensible interpretation | Continue conservatively. HAVEN must not read cookie names or values, claim authentication from cookie presence, or become a session-token repository. |
| Email alert delivery | Reach the owner when browser push is missed | Web Push proves unreliable during normal use and a privacy-bounded email transport is deliberately configured | Deferred. Avoid creating another credential and delivery-metadata surface without demonstrated need. |
| Broader network discovery | Find unmanaged devices automatically | A clear asset-discovery need outweighs consent, noise, retention, and false-attribution risks | Not planned. Appliances remain explicit and observed peers remain untrusted. |
| Packet capture or inspection | Provide deeper network diagnostics | A separate tightly scoped diagnostic use case is defined with retention and consent controls | Not planned for the core product. HAVEN is not Wireshark or a payload recorder. |
| Dynamic DNS, VPN, or router automation | Improve remote access reliability | A bounded health signal belongs in HAVEN rather than the private network’s operations layer | Keep configuration and automation in private operations. HAVEN may later observe a fact without owning router or VPN policy. |
| NAS firmware recommendations | Provide clearer update guidance | A reliable vendor source and model/version compatibility policy can be checked without forcing an update | Continue reporting installed evidence; do not invent, force, or automatically apply firmware decisions. |
| Paid Windows code signing | Improve installer trust presentation | The installer is distributed broadly enough to justify certificate cost and lifecycle management | Deferred for the owner’s current private installation. |

## Explicit non-goals

HAVEN should not become:

- an antivirus engine or replacement for native security products;
- a password manager, authenticator, or recovery-code vault;
- a store for cookie values, session tokens, packet payloads, browsing history, or monitored-device files;
- an arbitrary remote shell, script runner, firewall editor, or tamper-protection bypass;
- a public Internet administration console;
- a trust label automatically assigned to anything merely observed on the network.

## Resume checklist

When development resumes:

1. Read the [README](../README.md), this document, the [changelog](../CHANGELOG.md), [architecture](ARCHITECTURE.md), [threat model](THREAT_MODEL.md), and [verification map](VERIFICATION.md).
2. Check the live hub version and diagnostics instead of assuming production matches `main`.
3. Review recent real alerts and owner friction; do not create scope from an unused version number.
4. Select one coherent outcome, record its boundaries and exit criteria, and identify affected private deployment assumptions.
5. Use the [contributor workflow](../CONTRIBUTING.md), including a purpose-named temporary branch and required CI.
6. Update maintained behavior and compatibility documentation when the implementation changes.

Completed behavior belongs in architecture, threat-model, setup, and verification documentation. Concise user-visible changes belong in the changelog. Neither the README nor this roadmap should accumulate a chronological implementation ledger.
