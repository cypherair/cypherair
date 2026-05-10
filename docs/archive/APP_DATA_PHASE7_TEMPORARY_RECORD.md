# AppData Phase 7 Temporary Recovery Record

> **Status:** Archived temporary Phase 7 recovery record.
> **Archived on:** 2026-05-02.
> **Archival reason:** The temporary recovery note was already superseded by the Phase 7 implementation reference; both are now archived because current Phase 7 facts live in long-lived docs and Phase 8 work lives in Contacts docs.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md) · [CONTACTS_PRD](../CONTACTS_PRD.md) · [CONTACTS_TDD](../CONTACTS_TDD.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](../CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](../CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**
>
> Original snapshot metadata follows.
>
> **Status:** Superseded temporary recovery record.
> **Purpose:** Restore and index Phase 7 information that became less visible during the AppData documentation consolidation in `f9bc4dc`.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Last reviewed:** 2026-05-02.
> **Original current authority:** This document was superseded by [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md). Current code, [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md), [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md), [ARCHITECTURE](../ARCHITECTURE.md), [SECURITY](../SECURITY.md), [TDD](../TDD.md), and [TESTING](../TESTING.md) outranked this temporary record if they disagreed. Phase 7 closure status belonged in the implementation reference and roadmap status documents, not this historical record.

## 1. Scope And Use

This file records Phase 7 details recovered from the documentation state before and during `f9bc4dc docs: consolidate AppData phase status docs`.

Use it only as a historical recovery/audit index. Do not treat any row here as reviewed implementation direction; use [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md) for active Phase 7 architecture requirements and PR-track guidance.

Primary source material:

- `f9bc4dc` diff for [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)
- [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md)
- [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)
- [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)
- the current [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)

## 2. Diff Recovery Summary

The `f9bc4dc` consolidation changed the active migration guide from the detailed proposal-era guide into a smaller remaining-roadmap document. In that commit, `docs/APP_DATA_MIGRATION_GUIDE.md` went from 422 lines to 160 lines.

The detailed proposal-era migration guide content was preserved in [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md). The active guide now keeps only a brief Phase 7 summary, the row-level inventory without detailed notes, and cross-domain migration rules.

This record restores the Phase 7-specific details that were compressed out of the active guide. It does not revert the consolidation and does not change roadmap order.

## 3. Restored Phase 7 Scope

Recovered Phase 7 statement:

- Migrate remaining non-Contacts protected-after-unlock app state once its synchronous read paths are removed or replaced.

Recovered candidate areas:

- additional ordinary settings not yet moved in Phase 3
- self-test policy or diagnostics storage
- temporary decrypted, streaming, export, and tutorial files that need explicit file-protection or cleanup coverage

Current active-guide summary:

- targeted ordinary settings moved into `protected-settings` schema v2; legacy ordinary `UserDefaults` keys are cleanup-only after verified migration
- self-test reports are in-memory export-only data; legacy `Documents/self-test/` is cleanup-only on startup and Reset All Local Data
- temporary decrypted, streaming, export, and tutorial files are implemented as Phase 7 PR 4 `ephemeral-with-cleanup` with verified `.complete` file protection where CypherAir creates the file or directory
- tutorial-only defaults use fixed-suite cleanup for `com.cypherair.tutorial.sandbox` plus startup/reset fallback cleanup for orphaned legacy `com.cypherair.tutorial.<UUID>` suites

## 4. Restored Surface Notes

These rows are recovered notes, not revalidated implementation decisions.

| Surface | Recovered classification | Recovered note |
|---------|--------------------------|----------------|
| `gracePeriod` | `protected-after-unlock`, Phase 7, pending, not ready | Cold launch still authenticates without this value; future resume behavior can use the already-unlocked in-memory value and fail closed to immediate auth if unavailable. |
| `hasCompletedOnboarding` | `protected-after-unlock`, Phase 7, pending, not ready | Requires startup/routing refactor: show the locked shell first, then decide onboarding vs home after unlock. |
| `colorTheme` | `protected-after-unlock`, Phase 7, pending, not ready | Requires UI refactor: use system/default tint before unlock, then apply the user's theme after protected settings open. |
| `encryptToSelf` | `protected-after-unlock`, Phase 7, pending, not ready | Current sync read path still exists in Encrypt flow. |
| `guidedTutorialCompletedVersion` | `protected-after-unlock`, Phase 7, pending, not ready | Current sync read path still exists in tutorial and Settings entry flows. |
| `Documents/self-test/` | `ephemeral-with-cleanup`, Phase 7 PR 3, implemented as legacy cleanup-only | PR 3 selected the short-lived/export-only model. New self-test reports are held in memory until explicit export, reset, or app exit; no ProtectedData diagnostics domain was added. |
| `tmp/decrypted/` | `ephemeral-with-cleanup`, Phase 7 PR 4, implemented | Decrypted file previews now live under `tmp/decrypted/op-<UUID>/<sanitized output filename>`. The service creates a unique owner directory for each decrypt operation, applies and verifies `.complete` file protection, and cleans the owner directory on failure, cancellation-after-return, view cleanup, startup, or Reset All Local Data. |
| `tmp/streaming/` | `ephemeral-with-cleanup`, Phase 7 PR 4, implemented | Streaming encryption outputs now live under `tmp/streaming/op-<UUID>/<sanitized input filename>.gpg`. Ownership is per operation, so repeated same-name operations do not share a path. |
| `tmp/export-*` | `ephemeral-with-cleanup`, Phase 7 PR 4, implemented | Temporary fileExporter handoff files are written as `tmp/export-<UUID>-<sanitized filename>` with atomic complete file protection, verified after write, owned by `FileExportController`, and deleted by `finish()`, next export, startup, or Reset All Local Data. |
| `tmp/CypherAirGuidedTutorial-*` | `ephemeral-with-cleanup`, Phase 7 PR 4, implemented | Tutorial contacts sandbox directories are created with verified `.complete` protection and remain isolated from real app data. Current tutorial cleanup, startup cleanup, and Reset All Local Data remove matching directories. |
| Tutorial `UserDefaults` suite | `ephemeral-with-cleanup`, Phase 7 PR 4, implemented | Current tutorial cleanup removes the fixed `com.cypherair.tutorial.sandbox` suite used by the single active tutorial sandbox. Startup cleanup and Reset All Local Data clear that fixed suite directly, then enumerate the app Preferences directory for legacy `com.cypherair.tutorial.<UUID>.plist` orphans, remove those persistent domains, and delete residual plists without a registry. |

## 5. Restored Constraints

Recovered constraints for future review:

- Phase 7 must not move a setting merely because it is user-visible.
- A setting may enter protected settings only if it is target-classified as `protected-after-unlock` and is no longer required by synchronous or pre-unlock read paths.
- Shadow copies are not allowed to preserve early-boot behavior.
- Future migration of a startup-influencing setting requires a documented two-phase startup design and tests proving startup authentication strength is unchanged.
- Any domain migration must preserve readable source state until the protected destination is confirmed valid, verify destination readability before retiring old state, and treat unreadable converted state as a recovery surface rather than a silent wipe.

## 6. Restored Validation Clues

Recovered validation clues for later Phase 7 planning:

- Protected-after-unlock setting migration must prove that pre-auth startup does not read protected payloads, does not fetch the root-secret Keychain item, and does not weaken or change the selected app-session authentication policy.
- The `appSessionAuthenticationPolicy` boot authentication profile must stay early-readable unless a future testable design provides a protected value plus boot cache without changing launch authentication strength.
- PR 3 self-test coverage proves short-lived/export-only report generation plus cleanup semantics for legacy `Documents/self-test/`.
- PR 4 temporary-file coverage proves `tmp/decrypted`, `tmp/streaming`, `tmp/export-*`, `tmp/CypherAirGuidedTutorial-*`, and tutorial defaults cleanup, including owner, reset, startup, protection, same-name, and orphan-suite cases where each surface applies.
- Migration survivability, startup adoption, and no-silent-reset guarantees belong to Swift unit coverage, plus targeted macOS-local integration validation when startup routing or user-visible recovery flows are part of the scenario.
