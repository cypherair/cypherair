# AppData Phase 7 Temporary Recovery Record

> **Status:** Superseded temporary recovery record.
> **Purpose:** Restore and index Phase 7 information that became less visible during the AppData documentation consolidation in `f9bc4dc`.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Last reviewed:** 2026-05-02.
> **Current authority:** This document is superseded by [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md). Current code, [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md), [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md), [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), [TDD](TDD.md), and [TESTING](TESTING.md) outrank this temporary record if they disagree.

## 1. Scope And Use

This file records Phase 7 details recovered from the documentation state before and during `f9bc4dc docs: consolidate AppData phase status docs`.

Use it only as a historical recovery/audit index. Do not treat any row here as reviewed implementation direction; use [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md) for active Phase 7 architecture requirements and PR-track guidance.

Primary source material:

- `f9bc4dc` diff for [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)
- [archive/APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](archive/APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md)
- [archive/APP_DATA_PROTECTION_TDD](archive/APP_DATA_PROTECTION_TDD.md)
- [archive/APP_DATA_VALIDATION](archive/APP_DATA_VALIDATION.md)
- the current [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)

## 2. Diff Recovery Summary

The `f9bc4dc` consolidation changed the active migration guide from the detailed proposal-era guide into a smaller remaining-roadmap document. In that commit, `docs/APP_DATA_MIGRATION_GUIDE.md` went from 422 lines to 160 lines.

The detailed proposal-era migration guide content was preserved in [archive/APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](archive/APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md). The active guide now keeps only a brief Phase 7 summary, the row-level inventory without detailed notes, and cross-domain migration rules.

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
- temporary decrypted, streaming, export, and tutorial files that need final cleanup and file-protection review
- tutorial-only defaults and sandbox cleanup guarantees

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
| `tmp/decrypted/` | `ephemeral-with-cleanup`, Phase 7, partial | Decrypted file previews; cleanup exists in some flows, but file-protection review remains Phase 7 work. |
| `tmp/streaming/` | `ephemeral-with-cleanup`, Phase 7, partial | Streaming encrypt/decrypt outputs; startup cleanup exists, but file-protection review remains Phase 7 work. |
| `tmp/export-*` | `ephemeral-with-cleanup`, Phase 7, partial | Temporary fileExporter handoff files; deleted by owner/reset cleanup where possible, with remaining cleanup/file-protection review in Phase 7. |
| `tmp/CypherAirGuidedTutorial-*` | `ephemeral-with-cleanup`, Phase 7, partial | Tutorial contacts sandbox; isolated from real app data and deleted on tutorial cleanup/reset, with remaining cleanup/file-protection review in Phase 7. |
| Tutorial `UserDefaults` suite | `ephemeral-with-cleanup`, Phase 7, partial | Tutorial-only settings sandbox; removed on tutorial cleanup, with remaining cleanup review in Phase 7. |

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
- Temporary-file tests must cover `tmp/decrypted`, `tmp/streaming`, `tmp/export-*`, and tutorial sandbox cleanup, including relock, reset, and startup cleanup where each surface applies.
- Migration survivability, startup adoption, and no-silent-reset guarantees belong to Swift unit coverage, plus targeted macOS-local integration validation when startup routing or user-visible recovery flows are part of the scenario.
