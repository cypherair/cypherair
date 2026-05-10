# AppData Phase 7 Implementation Reference

> **Status:** Archived historical Phase 7 closure reference.
> **Archived on:** 2026-05-02.
> **Archival reason:** Phase 7 is complete and its current-state facts now live in long-lived architecture, security, technical, testing, and review docs. Contacts Phase 8 sequencing now lives in Contacts-specific docs.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md) · [PERSISTED_STATE_INVENTORY](../PERSISTED_STATE_INVENTORY.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**
>
> Original snapshot metadata follows.
>
> **Original pre-archive status:** Completed Phase 7 architecture and closure reference.
> **Purpose:** Document the completed Phase 7 protection requirements and auditable PR tracks for non-Contacts app-owned data surfaces after AppData Phase 1-6.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Relationship:** This document is not a symbol-level implementation plan and must not freeze future schema, type, method, or file names. It complements the inventory in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) and the progress record in [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md).
> **Last reviewed:** 2026-05-02.
> **Update triggers:** Any Phase 7 scope change, protected-setting migration, self-test persistence decision, temporary/export/tutorial cleanup or file-protection behavior change, or Contacts gate change.

## 1. Scope And Document Roles

Phase 7 covered the non-Contacts protected-after-unlock surfaces:

- ordinary app settings now protected by `protected-settings` schema v2, with legacy `UserDefaults` keys retained only as cleanup/migration sources
- self-test report or diagnostics persistence
- decrypted, streaming, export, and guided-tutorial temporary files
- tutorial-only defaults and sandbox cleanup guarantees

This document records architecture requirements and review boundaries for those surfaces. It is a closure reference, not a new source of code, schema, or API work.

Document ownership:

- [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) remains the row-level inventory and cross-domain migration rule document.
- [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) remains the code-backed progress record.
- [SECURITY](../SECURITY.md), [ARCHITECTURE](../ARCHITECTURE.md), [TDD](../TDD.md), and [TESTING](../TESTING.md) remain the durable technical contract for implemented behavior.
- [APP_DATA_PHASE7_TEMPORARY_RECORD](APP_DATA_PHASE7_TEMPORARY_RECORD.md) is superseded by this document and should be retained only as a recovery/audit note for pre-reference material.

Contacts are unblocked Phase 8 work after Phase 7 closure. This document may point to the Contacts follow-on plan, but it must not define Contacts-internal schema or rollout details.

## 2. Current Baseline

Implemented AppData Phase 1-7 behavior:

- `ProtectedDataRegistry`, shared root-secret authorization, wrapped-DMK lifecycle, relock, recovery dispatch, and post-unlock domain opening are present.
- `protected-settings` exists as the first real ProtectedData domain. Schema v2 preserves `clipboardNotice` and stores the ordinary-settings snapshot for `gracePeriod`, `hasCompletedOnboarding`, `colorTheme`, `encryptToSelf`, and `guidedTutorialCompletedVersion`.
- `private-key-control` owns `authMode` plus private-key rewrap / modify-expiry recovery journal state after app unlock.
- `key-metadata` owns `PGPKeyIdentity` payloads after app unlock.
- ProtectedData storage under `Application Support/ProtectedData/` applies and verifies explicit file protection where supported.
- `ProtectedOrdinarySettingsCoordinator` owns the Phase 7 ordinary-settings lock state and loads/saves through `protected-settings` schema v2 only after app privacy authentication and an unlocked protected-settings handoff.

Completed Phase 7 status:

- Phase 7 PR 3 selected the short-lived/export-only self-test model: current self-test reports are in-memory only until explicit user export, and legacy `Documents/self-test/` content is cleanup-only on startup and local-data reset.
- Phase 7 PR 4 selected the `ephemeral-with-cleanup` model for decrypted, streaming, export handoff, guided tutorial artifacts, and tutorial-only `UserDefaults` suites. It does not add a ProtectedData domain.
- `tmp/decrypted/op-<UUID>/...` and `tmp/streaming/op-<UUID>/...` provide per-operation ownership for streaming outputs; owner cleanup deletes the operation directory.
- `tmp/export-<UUID>-<filename>` remains a fileExporter handoff path owned by `FileExportController`, with owner cleanup through `finish()`.
- `tmp/CypherAirGuidedTutorial-<UUID>/` remains tutorial-local storage. Tutorial defaults use the fixed `com.cypherair.tutorial.sandbox` suite, while orphaned legacy `com.cypherair.tutorial.<UUID>` defaults suites are removed by startup and Reset All Local Data fallback sweeps.

Apple platform references that motivate Phase 7:

- [UserDefaults](https://developer.apple.com/documentation/foundation/userdefaults) is documented as a persistent settings store for app-specific settings; Apple warns not to store personal or sensitive information there because defaults are stored on disk in an unencrypted format.
- [Encrypting Your App's Files](https://developer.apple.com/documentation/uikit/encrypting-your-app-s-files) requires apps to choose data-protection levels deliberately and recommends the strongest workable protection for user data files.
- [FileProtectionType.complete](https://developer.apple.com/documentation/foundation/fileprotectiontype/complete) is the level where the file is encrypted on disk and unavailable while the device is locked or booting.
- [NSData.WritingOptions.completeFileProtection](https://developer.apple.com/documentation/foundation/nsdata/writingoptions/completefileprotection) applies complete file protection when data writes create app-owned temporary handoff files.
- [Data Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.default-data-protection) provides a default protection class, but Phase 7 must not rely on a default entitlement as a substitute for explicit protection and verification where CypherAir owns the file.

## 3. Protection Requirements

Ordinary protected settings:

- Phase 7 must use the existing ProtectedData / session-unlocked model. It must not introduce a second vault, second root-secret model, or parallel registry authority.
- Settings may move into ordinary protected settings only after synchronous or pre-unlock read paths are removed or replaced.
- No pre-unlock shadow copy may be introduced to preserve old behavior.
- If a protected setting is unavailable during launch, resume, recovery, or relock, the app must fail closed to the safest available behavior. It must not weaken app-session authentication, skip a privacy gate, or infer protected values from stale storage.
- Settings migration must preserve readable legacy source state until the protected destination is verified readable, then retire or quarantine source state according to the implementation plan for that PR.
- Corrupted committed protected settings must become a recovery surface, not an automatic reset to defaults.

Settings targeted for ordinary protected settings:

| Setting | Phase 7 target requirement |
|---------|----------------------------|
| `gracePeriod` | Protect after unlock once resume/grace behavior can use an opened session value or fail closed to immediate authentication. |
| `hasCompletedOnboarding` | Protect after startup routing no longer requires this value before app-session authentication. |
| `colorTheme` | Protect after pre-unlock UI can render with system/default styling and apply the user's theme only after protected settings open. |
| `encryptToSelf` | Protect after Encrypt and related flows stop depending on a synchronous default before protected settings are available. |
| `guidedTutorialCompletedVersion` | Protect after tutorial entry, replay, onboarding, and Settings flows can handle locked/unavailable completion state safely. |

Settings and state not targeted for ordinary protected settings:

- `appSessionAuthenticationPolicy` remains an early-readable boot-authentication exception unless a later design proves an equivalent protected value plus boot cache without weakening launch authentication strength.
- `authMode` remains owned by `private-key-control`; it must not move into ordinary protected settings or back into a pre-auth source of truth.
- `clipboardNotice` is already protected in the narrow Phase 3 domain and should remain compatible with the expanded protected-settings domain.
- UI-test bypass keys, legacy cleanup-only keys, private-key material rows, framework bootstrap metadata, and out-of-app-custody exported files remain explicit exceptions according to the inventory.

Self-test persistence:

- Phase 7 PR 3 chose short-lived/export-only reports for self-test persistence; no protected diagnostics domain was added.
- A protected diagnostics design must reuse the shared ProtectedData framework and must define unlock, relock, recovery, reset, migration, and cleanup behavior.
- A short-lived/export-only design must define report lifetime, owner cleanup, reset cleanup, startup cleanup if needed, and file-protection expectations for any intermediate file.
- Self-test reports must not become a silent long-lived plaintext diagnostics cache.

Temporary, export, and tutorial files:

- `AppTemporaryArtifactStore` is the central owner for Phase 7 PR 4 temporary file paths, `.complete` protection application, protection verification, startup cleanup, reset cleanup, fixed tutorial defaults cleanup, and legacy tutorial defaults UUID cleanup.
- `tmp/decrypted/` and `tmp/streaming/` outputs must live under one operation directory per service call: `tmp/decrypted/op-<UUID>/...` and `tmp/streaming/op-<UUID>/...`. Final filenames remain recognizable sanitized source names, but cleanup ownership is the operation directory, not the shared filename.
- `tmp/export-*` handoff files must be written atomically with `.completeFileProtection`, verified with `.complete`, and owned only by the export controller that created them. `prepareFileExport` for an existing file does not take custody of that file.
- `tmp/CypherAirGuidedTutorial-*` directories must be created with verified `.complete` protection and removed on current tutorial cleanup plus startup and local-data reset cleanup.
- Tutorial-only `UserDefaults` use the fixed `com.cypherair.tutorial.sandbox` suite for the single active tutorial sandbox. `TutorialSandboxContainer` clears that suite before each creation and on current-container cleanup. Startup and Reset All Local Data clear the fixed suite directly, then enumerate the app Preferences directory for legacy `com.cypherair.tutorial.<UUID>.plist` orphans, call `removePersistentDomain(forName:)`, and remove residual plists. No tutorial suite registry is used because the fixed suite plus legacy sweep is deterministic.
- User-selected export destinations become out-of-app-custody only after the user-controlled transfer succeeds. Startup/reset cleanup only removes app-owned temporary handoff paths, not user-selected destinations.

## 4. Auditable PR Tracks

Phase 7 was delivered as multiple reviewable PRs. Future documentation should preserve these audit boundaries when describing the completed work.

1. Startup and synchronous read-path removal
   - Status: implemented for ordinary settings by Phase 7 PR 1.
   - `ProtectedOrdinarySettingsCoordinator` is the app-wide ordinary-settings source of truth for `locked`, `loaded(snapshot)`, and `recoveryRequired`.
   - `appSessionAuthenticationPolicy` remains the only ordinary settings boot-authentication exception unless a later reviewed design changes that.
   - Pre-auth startup must not fetch the root secret, unwrap a DMK, open protected payloads, read legacy ordinary-setting sources, or weaken the selected app-session authentication policy.

2. Protected settings expansion
   - Status: implemented by Phase 7 PR 2.
   - Extend the existing protected-settings capability to cover the targeted ordinary settings.
   - Preserve `clipboardNotice` compatibility and legacy cleanup guarantees.
   - Include migration survivability, unreadable-state recovery, relock cleanup, and no-shadow-copy coverage.

3. Self-test persistence decision
   - Status: implemented by Phase 7 PR 3 as short-lived/export-only reports.
   - Keep generated self-test reports in memory until explicit user export, reset, or app exit.
   - Treat legacy `Documents/self-test/` as cleanup-only on startup and local-data reset.
   - Update inventory and testing docs with the selected classification.
   - Prove self-test reports do not remain as unreviewed plaintext durable state.

4. Temporary, export, and tutorial file hardening
   - Status: implemented by Phase 7 PR 4 as `ephemeral-with-cleanup`.
   - Finalize cleanup and file-protection policy for decrypted, streaming, export handoff, and tutorial sandbox artifacts.
   - Cover owner cleanup, startup cleanup, reset cleanup, and relock/content-clear behavior where each surface applies.
   - Keep user-selected exported files classified as out-of-app-custody after transfer.

5. Documentation and gate closure
   - Status: implemented by Phase 7 PR 5 as docs-only closure.
   - Update [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md), [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md), [SECURITY](../SECURITY.md), [ARCHITECTURE](../ARCHITECTURE.md), [TDD](../TDD.md), and [TESTING](../TESTING.md) to match implemented Phase 7 behavior.
   - Mark Phase 8 Contacts as unblocked follow-on work without implementing Contacts or redefining its schema.
   - Do not introduce, remove, or rename Swift/Rust public APIs, ProtectedData schemas, UniFFI surfaces, entitlements, permission strings, or build settings.

## 5. Validation Requirements

Every Phase 7 implementation PR included tests appropriate to its surface. At minimum, the complete Phase 7 closure must prove:

- pre-auth startup does not read protected settings payloads, fetch the root secret, or unwrap any domain master key
- app-session authentication strength and `LAContext` handoff behavior are preserved
- protected settings migrate only after destination readability is verified
- legacy sources are not deleted before verified migration
- corrupted protected state enters recovery instead of silently resetting
- relock clears unlocked settings and any decrypted in-memory protected payloads
- self-test reports follow the selected protected-diagnostics or short-lived/export-only model
- temporary decrypted, streaming, export, and tutorial artifacts are covered by owner cleanup, startup cleanup, reset cleanup, and file-protection checks where applicable
- orphaned tutorial `UserDefaults` suites are discoverable and removable by prefix without touching real app defaults

Expected validation levels:

- Swift unit tests for state classification, migration, recovery, relock, reset, and cleanup behavior.
- Targeted macOS UI smoke coverage when startup routing, onboarding, tutorial entry, Settings, or user-visible recovery flow changes.
- Platform-targeted or manual verification for lock-state file-protection semantics that repository automation cannot prove.
- Rust tests only when Phase 7 implementation touches Rust or Swift-visible Rust behavior.

Docs-only PRs that create or revise this reference do not require Rust or Xcode test runs, but they should verify active-document links and avoid conflicting Phase 7 authority.
