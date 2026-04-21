# App Data Migration Guide

> **Version:** Draft v1.0
> **Status:** Draft future migration guide. This document does not describe current shipped behavior.
> **Purpose:** Define the phased rollout, adoption sequencing, and migration inventory for the protected app-data proposal.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Primary authority:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) for roadmap intent and [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) for architecture and security constraints.
> **Companion documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)
> **Related documents:** [CONTACTS_PRD](CONTACTS_PRD.md) · [CONTACTS_TDD](CONTACTS_TDD.md)

## 1. Scope And Relationship

This guide collects the migration and rollout details that support the main app-data protection roadmap.

It specifies:

- phased adoption order
- startup and session sequencing for real-domain rollout
- the reviewed persisted-state inventory
- first-domain rules for `ProtectedSettingsStore`
- cross-domain adoption constraints for later Contacts migration

If this guide conflicts with the core architecture or security rules in [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md), the TDD wins. If it conflicts with the high-level rollout intent in [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md), the Plan wins on sequencing and scope.

## 2. Migration Order

### 2.1 Phase 1: Protected App-Data Framework

Build the reusable protected app-data substrate first.

Goals:

- establish shared terminology and lifecycle
- define common envelope and recovery rules
- define the shared-gate / per-domain-DMK topology
- define the `ProtectedDataRegistry` contract before any real domain lands
- define separated shared-resource lifecycle state and mutation execution phase semantics
- define registry consistency invariants and a deterministic recovery matrix
- define registry-first evidence ordering rules
- define unified session orchestration before any real domain lands
- define a system-gated app-data authorization model that is separate from the private-key access-control source of truth
- define a strict startup authentication boundary
- define common relock, deauthorize, and session-unlock semantics
- define fail-closed relock behavior including `restartRequired`
- define the v1 DMK persistence and wrapped-DMK model
- define the initial persistent-state classification inventory

This phase should land before Contacts migration so Contacts can depend on the shared framework instead of creating its own parallel architecture.

### 2.2 Phase 2: File-Protection Baseline

Establish the file/static-protection baseline required by protected-domain storage before any real protected domain lands in code.

Goals:

- define the minimum platform-specific local static protection contract for registry files, protected-domain files, bootstrap metadata, and temporary scratch files
- ensure no real protected domain ships without its file/static-protection baseline

### 2.3 Phase 3: First Low-Risk Real Domain

Use a low-risk domain such as protected-after-unlock settings or recovery/control state as the first adopter.

Goals:

- exercise the new framework without touching the private-key domain
- validate shared authorize / lazy unlock / relock / deauthorize behavior on real app-owned data
- reduce plaintext or lightly protected security-sensitive preferences over time

Phase 3 uses a split-settings model.

#### 2.3.1 Bootstrap-Critical Settings

The following settings remain in the early-readable layer in v1 because they are read before protected domains unlock:

- `authMode`
- `gracePeriod`
- `requireAuthOnLaunch`
- `hasCompletedOnboarding`
- `colorTheme`

These settings are not eligible for `ProtectedSettingsStore` in Phase 3.

#### 2.3.2 Protected-After-Unlock Settings / Control State

Phase 3 may migrate only settings or control state that:

- are target-classified as `protected-after-unlock`
- are no longer required by synchronous or pre-unlock read paths

Phase 3 must not rely on a shadow copy of protected settings to recreate early boot behavior.

This first real domain must also declare its recovery contract up front:

- `ProtectedSettingsStore`-style non-bootstrap settings/control state are `resettable-with-confirmation`
- they are not import-recoverable in v1
- they must never silently reset on unreadable local state

### 2.4 Phase 4: Contacts Vault On Shared Framework

Migrate Contacts to the shared protected app-data framework rather than letting Contacts become a one-off vault system.

Goals:

- preserve the Contacts product and TDD direction
- ensure Contacts remains a domain-specific consumer of the shared substrate
- avoid duplicating domain key lifecycle, envelope handling, recovery logic, registry authority, and relock rules
- keep Contacts explicitly `import-recoverable`

### 2.5 Phase 5: Remaining Persistent Domains

Migrate remaining app-owned persistent domains in order of security value and implementation risk.

Candidate areas include:

- additional settings or recovery state not yet moved in Phase 3
- future local drafts or protected caches
- future user-managed local data that should not remain plaintext at rest

## 3. Startup Boundary And Adoption Sequencing

### 3.1 Startup Authentication Boundary

All future implementations derived from this proposal must follow a two-phase startup model.

#### 3.1.1 Pre-Auth Bootstrap Phase

Before app-data authorization succeeds, the app may:

- read bootstrap-critical settings
- read the `ProtectedDataRegistry`
- read file-side per-domain bootstrap metadata
- route cold start and determine whether protected domains exist

Before app-data authorization succeeds, the app must not:

- fetch `LASecret`
- authorize the shared app-data right implicitly in an initializer or getter
- unwrap any domain DMK
- attempt to open protected-domain generations
- finalize framework or domain recovery state from protected-domain contents alone

#### 3.1.2 Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- authorize the shared right through the protected-data session layer
- fetch the shared app-data secret
- lazy-unlock a requested domain DMK
- open `current / previous / pending`
- determine final framework and domain state

This startup boundary is a required implementation constraint, not a best-effort guideline.

Startup recovery derived from this guide must also:

- validate registry schema and consistency rules before inspecting evidence
- use the registry row to decide which evidence is allowed to be consulted
- emit exactly one documented recovery disposition instead of implementation-defined branching

### 3.2 App-Data Session Lifetime

The shared app-data session follows the current grace-window model, but the grace window has only one owner: `AppSessionOrchestrator`.

In v1:

- launch/resume first enters `AppSessionOrchestrator`
- if app session is not active, the orchestrator completes app-level privacy unlock first
- `first real protected-domain access` means the first route in the current app session that actually needs protected-domain content, not process launch by itself
- if cold start or resume immediately enters such a route, that same orchestrated flow may authorize the shared right and activate the shared app-data session there
- shared right authorization does not occur merely because process launch or service initialization happened
- shared right authorization does not eagerly unwrap every domain DMK
- launch/resume authentication alone does not imply that the shared app-data session is already active
- a second or third protected domain in the same active app-data session must not prompt again
- `ProtectedDataSessionCoordinator` does not own an independent grace timer or second launch/resume UX surface
- app-data relock and deauthorize occur only on:
  - explicit app lock
  - grace-period expiration
  - session loss
  - app termination or exit
- if relock cannot complete safely, the current process enters `restartRequired` and may not unlock protected domains again until restart
- entering background alone does not deauthorize app-data while the grace window is still valid
- `gracePeriod = 0` is the supported posture for "every resume requires fresh authorization before protected-domain access"

### 3.3 Startup Architecture Impact

The protected app-data proposal is no longer just a narrow service-layer addition.

For any future real protected domain, the implementation plan must treat the following as explicit architecture migration areas:

- startup ordering
- service initialization timing
- locked-state UI routing
- `AppSessionOrchestrator` wiring
- `ProtectedDataSessionCoordinator` wiring
- final framework and domain state classification timing

This is especially important for future Contacts adoption, where cold-start loading and locked-state presentation already exist in the app surface.

### 3.4 Current-State Owner Map

This migration guide documents the handoff points that the future single-owner session model must absorb. It does not redesign the current app.

| Concern | Current shipping owner(s) | Current behavior | Future handoff |
|------|------------------|--------------|---------------------|
| Launch authentication on cold start | `PrivacyScreenModifier` + `AuthenticationManager.evaluate(...)` | `onAppear` checks `requireAuthOnLaunch`, presents the privacy unlock prompt, and records success in `AppConfiguration` | Absorb launch sequencing into `AppSessionOrchestrator`, with protected-domain handoff through `ProtectedDataSessionCoordinator` when the initial route requires protected content |
| Resume authentication after grace expiry | `PrivacyScreenModifier` + `AuthenticationManager.evaluate(...)` | scene-activation and resume routing blur the UI, re-authenticate after expiry, and unblock the app shell on success | Move resume sequencing and re-entry decisions under `AppSessionOrchestrator` |
| Grace-window timing | `AppConfiguration` | `gracePeriod`, `lastAuthenticationDate`, and `isGracePeriodExpired` currently determine whether re-auth is required | Make `AppSessionOrchestrator` the only grace-window owner |
| Content clearing on auth boundary | `AppConfiguration` + view observers | grace-expiry re-auth increments `contentClearGeneration` before authentication so decrypted UI state clears | Move relock-driven clearing into framework relock plus `ProtectedDataRelockParticipant` fan-out |
| Cold-start loading and temp cleanup | `AppStartupCoordinator` | cold start loads keys and Contacts, runs recovery checks, and cleans temporary files before any future protected app-data layer exists | Split startup into pre-auth bootstrap plus post-auth protected-domain unlock; future protected-domain loading must not happen merely from startup initialization |

## 4. Persisted-State Classification Inventory

Before any real protected domain lands, implementation planning must maintain a complete inventory of currently persisted app-owned state.

Each persisted item must have:

- a `target class`
- a `migration readiness`

Allowed target classes:

- `early-readable`
- `protected-after-unlock`
- `remain plaintext with rationale`

At minimum this inventory must include:

- current `AppConfiguration` keys
- auth and recovery flags currently stored in `UserDefaults`
- any future app-owned bootstrap metadata
- documented cross-launch temporary disk surfaces

The inventory must prevent four failure modes:

- omitted state that never gets reviewed for migration
- state that is moved into a protected domain even though startup still needs it before authorization
- state that remains plaintext indefinitely without an explicit documented reason
- state that is target-classified correctly but migrated before its read paths are actually ready

Initial classification baseline:

| Item | Current location | Target class | Migration readiness | Notes |
|------|------------------|--------------|---------------------|-------|
| `authMode` | `UserDefaults` | `early-readable` | n/a in v1 | Read before app-data authorization |
| `gracePeriod` | `UserDefaults` | `early-readable` | n/a in v1 | Read before app-data authorization |
| `requireAuthOnLaunch` | `UserDefaults` | `early-readable` | n/a in v1 | Read before app-data authorization |
| `hasCompletedOnboarding` | `UserDefaults` | `early-readable` | n/a in v1 | Affects startup routing |
| `colorTheme` | `UserDefaults` | `early-readable` | n/a in v1 | Affects early scene presentation |
| `encryptToSelf` | `UserDefaults` | `protected-after-unlock` | no | Current sync read path still exists in Encrypt flow |
| `clipboardNotice` | `UserDefaults` | `protected-after-unlock` | no | Current sync read path still exists in clipboard UX flow |
| `guidedTutorialCompletedVersion` | `UserDefaults` | `protected-after-unlock` | no | Current sync read path still exists in tutorial and Settings entry flows |
| `rewrapInProgress` | `UserDefaults` | `remain plaintext with rationale` | n/a in v1 | Private-key recovery flag; stays outside app-data domain |
| `rewrapTargetMode` | `UserDefaults` | `remain plaintext with rationale` | n/a in v1 | Private-key recovery flag; stays outside app-data domain |
| `modifyExpiryInProgress` | `UserDefaults` | `remain plaintext with rationale` | n/a in v1 | Private-key recovery flag; stays outside app-data domain |
| `modifyExpiryFingerprint` | `UserDefaults` | `remain plaintext with rationale` | n/a in v1 | Private-key recovery flag; stays outside app-data domain |
| `Documents/contacts/*.gpg` | App sandbox documents | `remain plaintext with rationale` | n/a in this round | Existing Contacts storage remains plaintext until App Data Phase 4 Contacts adoption begins |
| `Documents/contacts/contact-metadata.json` | App sandbox documents | `remain plaintext with rationale` | n/a in this round | Existing Contacts metadata remains plaintext until App Data Phase 4 Contacts adoption begins |
| `Documents/self-test/` | App sandbox documents | `remain plaintext with rationale` | n/a in v1 | Diagnostic output remains outside protected-domain scope |
| `tmp/decrypted/` | App temporary directory | `remain plaintext with rationale` | n/a in v1 | Ephemeral decrypted previews; explicit cleanup path, not a protected-domain candidate |
| `tmp/streaming/` | App temporary directory | `remain plaintext with rationale` | n/a in v1 | Ephemeral streaming outputs; explicit cleanup path, not a protected-domain candidate |
| `ProtectedDataRegistry` | App-owned bootstrap manifest | `early-readable` | framework prerequisite | Bootstrap authority for membership and shared-resource lifecycle |
| future per-domain bootstrap metadata | App-owned bootstrap files | `early-readable` | domain-specific | Read before app-data authorization by design |

## 5. Domain Migration Rules

Migration from current plaintext or non-uniform state into protected domains must follow these rules:

- preserve readable source state until protected destination is confirmed valid
- never silently reset to empty state on conversion failure
- define explicit post-cutover cleanup rules
- make unreadable converted state a recovery surface, not a silent wipe

For any domain migration:

1. read current source state
2. validate and normalize
3. write protected destination using the new domain model
4. verify readability of the destination
5. only then retire or quarantine the old source state

First-domain rule for `ProtectedSettingsStore`:

- a setting may enter the first protected settings domain only if it is target-classified as `protected-after-unlock`
- and it is no longer required by synchronous or pre-unlock read paths
- shadow copies are not allowed to preserve early-boot behavior
