# App Data Migration Guide

> **Version:** Draft v1.0
> **Status:** Draft future migration guide. This document does not describe current shipped behavior.
> **Purpose:** Define the phased rollout, adoption sequencing, and migration inventory for the protected app-data proposal.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Primary authority:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) for roadmap intent and [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) for architecture and security constraints.
> **Companion documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) · [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md)
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
- define common relock, session teardown, and session-unlock semantics
- define fail-closed relock behavior including `restartRequired`
- define the v1 DMK persistence and wrapped-DMK model
- define the initial persistent-state classification inventory

This phase should land before any later protected-domain migration so future domains can depend on the shared framework instead of creating parallel architectures.

### 2.2 Phase 2: File-Protection Baseline

Establish the file/static-protection baseline required by protected-domain storage before any real protected domain lands in code.

Goals:

- define the minimum platform-specific local static protection contract for registry files, protected-domain files, bootstrap metadata, and temporary scratch files
- ensure no real protected domain ships without its file/static-protection baseline

### 2.3 Phase 3: First Low-Risk Real Domain

Use a low-risk domain such as protected-after-unlock settings or recovery/control state as the first adopter.

Goals:

- exercise the new framework without touching the private-key domain
- validate shared root-secret activation / lazy domain unlock / relock behavior on real app-owned data
- prove that launch/resume authentication can activate the shared app-data session with the same authenticated `LAContext` when the first route needs protected settings
- reduce plaintext or lightly protected security-sensitive preferences over time

Phase 3 uses a split-settings model.

Current implementation status is intentionally narrow: Phase 3 has landed `ProtectedSettingsStore` as the first real domain and migrated `clipboardNotice` into it. Other ordinary settings and control state are not Phase 3 completion criteria; they remain Phase 7 targets until their synchronous or pre-unlock read paths are removed.

#### 2.3.1 Bootstrap-Critical Settings

The following settings remain in the early-readable layer in v1 because they are read before protected domains unlock:

- `authMode`
- `gracePeriod`
- `hasCompletedOnboarding`
- `colorTheme`

`requireAuthOnLaunch` is retired and must not be treated as an active
bootstrap-critical setting. Production launch authentication is always required;
test bypasses are controlled by non-persistent launch configuration, and Reset
removes the legacy UserDefaults key if it exists.

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

### 2.4 Phase 4: Post-Unlock Multi-Domain Orchestration And Framework Hardening

Extend post-unlock orchestration and harden the framework before additional source-of-truth domains depend on it.

Goals:

- allow app privacy authentication to open additional required protected domains through the current authenticated context without extra Face ID prompts
- harden second-domain create/delete/recovery behavior
- cover pending-mutation continuation and last-domain cleanup before later product domains depend on them
- keep this phase focused on framework behavior rather than Contacts, private-key-control, or key-metadata source-of-truth migration

### 2.5 Phase 5: Private-Key Control Domain

Create the `private-key-control` ProtectedData domain.

Goals:

- migrate `authMode` into `private-key-control.settings.authMode`
- migrate private-key rewrap / modify-expiry recovery state into `private-key-control.recoveryJournal`
- move recovery detection out of pre-auth startup
- preserve the existing private-key material domain without copying SE-wrapped private-key bundle rows into ProtectedData payloads

### 2.6 Phase 6: Key Metadata Domain

Create the `key metadata` ProtectedData domain.

Goals:

- migrate `PGPKeyIdentity` metadata out of the transitional Keychain metadata account
- open key metadata after app privacy authentication through post-unlock orchestration
- avoid double authentication and empty-key-list flashes while preserving the private-key material boundary

### 2.7 Phase 7: Non-Contacts Protected-After-Unlock Domains

Migrate remaining non-Contacts protected-after-unlock app state once its synchronous read paths are removed or replaced.

Candidate areas include:

- additional ordinary settings not yet moved in Phase 3
- self-test policy or diagnostics storage
- temporary decrypted, streaming, export, and tutorial files that need explicit file-protection or cleanup coverage

### 2.8 Phase 8: Contacts Protected Domain

Migrate Contacts to the shared protected app-data framework after the earlier private-key-control, key-metadata, and non-Contacts protected-after-unlock phases.

Goals:

- preserve the Contacts product and TDD direction
- ensure Contacts remains a domain-specific consumer of the shared substrate
- avoid duplicating domain key lifecycle, envelope handling, recovery logic, registry authority, and relock rules
- keep Contacts explicitly `import-recoverable`

Contacts internal implementation sequencing lives in [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md). AppData Phase 4 framework hardening is a prerequisite, but Contacts PR1-PR8 are still Phase 8 work and remain behind the Phase 5-7 roadmap gates. No Contacts schema-only prep starts earlier unless this roadmap is explicitly revised.

### 2.9 Phase 9: Future Persistent Domains

Migrate future app-owned persistent domains not covered by the current inventory in order of security value and implementation risk.

## 3. Startup Boundary And Adoption Sequencing

### 3.1 Startup Authentication Boundary

All future implementations derived from this proposal must follow a two-phase startup model.

#### 3.1.1 Pre-Auth Bootstrap Phase

Before app-session authentication succeeds, the app may:

- read bootstrap-critical settings
- read the `ProtectedDataRegistry`
- read file-side per-domain bootstrap metadata
- route cold start and determine whether protected domains exist
- synchronously bootstrap an empty steady-state registry when no protected-data artifacts exist

Before app-session authentication succeeds, the app must not:

- fetch the shared app-data root secret
- read the root-secret Keychain item implicitly in an initializer or getter
- unwrap any domain DMK
- attempt to open protected-domain generations
- finalize framework or domain recovery state from protected-domain contents alone

#### 3.1.2 Post-Auth Unlock Phase

After app-session authentication succeeds and protected-domain access is requested, the app may:

- pass the authenticated `LAContext` from app-session authentication into the protected-data session layer
- fetch the shared app-data root secret through Keychain / `SecAccessControl` / `kSecUseAuthenticationContext`
- lazy-unlock a requested domain DMK
- open `current / previous / pending`
- determine final framework and domain state

This startup boundary is a required implementation constraint, not a best-effort guideline.

Phase 1 implementation note:

- `CypherAirApp.init()` remains the synchronous startup entry point
- `AppStartupCoordinator.performPreAuthBootstrap(...)` is the only startup hook allowed to touch `ProtectedDataRegistry` before authorization
- that bootstrap path may create the empty steady-state registry but may not retrieve the shared root secret
- cold-start bootstrap output is an initial handoff only; later protected-domain access must consult current framework state instead of treating the startup snapshot as perpetual truth

Startup recovery derived from this guide must also:

- validate registry schema and consistency rules before inspecting evidence
- use the registry row to decide which evidence is allowed to be consulted
- keep registry classification single-valued, using orphan shared-resource evidence only to authorize post-classification `cleanupOnly` under the empty steady-state row
- emit exactly one documented recovery disposition instead of implementation-defined branching

### 3.2 App-Data Session Lifetime

The shared app-data session follows the current grace-window model, but the grace window has only one owner: `AppSessionOrchestrator`.

In v1:

- launch/resume first enters `AppSessionOrchestrator`
- if app session is not active, the orchestrator completes app-level privacy unlock first
- `first real protected-domain access` means the first route in the current app session that actually needs protected-domain content, not process launch by itself
- if cold start or resume immediately enters such a route, that same orchestrated flow may pass the authenticated `LAContext` into root-secret Keychain retrieval and activate the shared app-data session there
- root-secret retrieval does not occur merely because process launch or service initialization happened
- root-secret retrieval does not eagerly unwrap every domain DMK
- launch/resume authentication alone does not imply that the shared app-data session is already active unless root-secret retrieval and wrapping-root-key derivation also completed successfully
- a second or third protected domain in the same active app-data session must not prompt again
- `ProtectedDataSessionCoordinator` does not own an independent grace timer or second launch/resume UX surface
- app-data relock and session teardown occur only on:
  - explicit app lock
  - grace-period expiration
  - session loss
  - app termination or exit
- if relock cannot complete safely, the current process enters `restartRequired` and may not unlock protected domains again until restart
- entering background alone does not tear down app-data access while the grace window is still valid
- `gracePeriod = 0` is the supported posture for "every resume requires fresh authorization before protected-domain access"

### 3.3 Legacy Gate Migration Requirement

Any implementation that has already provisioned `LAPersistedRight` / `LASecret` app-data state must treat that state as a legacy migration source.

Required migration rules:

- never hand-edit or silently delete legacy `LAPersistedRight` state before the replacement root-secret Keychain record is written and verified
- authorize the legacy right only inside an explicit migration flow
- copy the legacy raw secret into the new root-secret Keychain record protected by `SecAccessControl`
- validate that the new record can be read through an authenticated `LAContext`
- update registry/shared-resource metadata only after the new record is usable
- zeroize all raw secret buffers used during migration
- if migration fails, preserve the legacy state and keep protected domains fail-closed
- after migration succeeds, ordinary app-data unlock must use the Keychain root-secret gate, not the legacy right

### 3.4 Startup Architecture Impact

The protected app-data proposal is no longer just a narrow service-layer addition.

For any future real protected domain, the implementation plan must treat the following as explicit architecture migration areas:

- startup ordering
- service initialization timing
- locked-state UI routing
- `AppSessionOrchestrator` wiring
- `ProtectedDataSessionCoordinator` wiring
- final framework and domain state classification timing

This is especially important for future Contacts adoption, where cold-start loading and locked-state presentation already exist in the app surface.

### 3.5 Current-State Owner Map

This migration guide documents the remaining handoff points around future protected-domain adoption. The app-wide session owner has already moved to `AppSessionOrchestrator`; future work should build on that owner instead of reintroducing view-local authentication state.

| Concern | Current shipping owner(s) | Current behavior | Future handoff |
|------|------------------|--------------|---------------------|
| Launch authentication on cold start | `AppSessionOrchestrator` through `PrivacyScreenModifier` | The view modifier is a UI adapter; the orchestrator evaluates privacy unlock, records the reusable `LAContext`, and can hand it to ProtectedData authorization when a route needs protected content |
| Resume authentication after grace expiry | `AppSessionOrchestrator` through scene-phase observation | Scene activation routes through the orchestrator, which owns suppression around system auth UI, content clearing, and reusable context storage |
| Grace-window timing | `AppSessionOrchestrator` | The orchestrator owns last-authentication timing and grace-period expiry decisions |
| Content clearing on auth boundary | `AppSessionOrchestrator` + relock participants | Grace-expiry re-auth increments `contentClearGeneration`; ProtectedData participants use relock hooks for domain-local cleanup |
| Cold-start loading and temp cleanup | `AppStartupCoordinator` | cold start loads keys and Contacts, runs recovery checks, and cleans temporary files before any future protected app-data layer exists | Split startup into pre-auth bootstrap plus post-auth protected-domain unlock; future protected-domain loading must not happen merely from startup initialization |

Current implementation progress for these owners lives in [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md). Keep that file as the current progress record rather than mixing Phase 1, Phase 3, and Phase 4 status into this migration guide.

## 4. Persisted-State Classification Inventory

The long-term app-data goal is to protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain. The inventory therefore covers settings, Keychain records, ProtectedData framework files, app documents, temporary files, tutorial sandbox state, and export handoff surfaces.

This inventory does not authorize migration of the existing private-key material domain. Secure Enclave wrapping and permanent/pending private-key Keychain bundle rows remain governed by the existing private-key design. Other private-key-adjacent state such as `authMode`, recovery journals, and key metadata is tracked here because the long-term goal is to move it behind post-unlock protected domains without changing the private-key material protection model.

Each in-scope persisted item must have:

- a `target class`
- a `target phase` or explicit exception
- a `current status`
- a `migration readiness`

Allowed target classes:

- `protected-after-unlock`
- `early-readable boot exception`
- `private-key-control target`
- `key-metadata-domain target`
- `private-key-material exception`
- `framework-bootstrap`
- `ephemeral-with-cleanup`
- `out-of-app-custody`
- `legacy cleanup-only`
- `test-only exception`

At minimum this in-scope inventory must include:

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

| Item | Current location | Target class | Target phase / exception | Current status | Migration readiness | Notes |
|------|------------------|--------------|--------------------------|----------------|---------------------|-------|
| `appSessionAuthenticationPolicy` | `UserDefaults` | `early-readable boot exception` | Boot exception | Exception retained | n/a in v1 | Boot authentication profile; decides whether app launch/root-secret auth uses user-presence or biometrics-only policy |
| `authMode` | `UserDefaults` | `private-key-control target` | Phase 5 | Pending | no | Future `private-key-control.settings.authMode`; app unlock should automatically open this domain before private-key settings or recovery checks need it |
| `gracePeriod` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no | Cold launch still authenticates without this value; future resume behavior can use the already-unlocked in-memory value and fail closed to immediate auth if unavailable |
| `hasCompletedOnboarding` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no | Requires startup/routing refactor: show the locked shell first, then decide onboarding vs home after unlock |
| `colorTheme` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no | Requires UI refactor: use system/default tint before unlock, then apply the user's theme after protected settings open |
| `requireAuthOnLaunch` | Retired legacy `UserDefaults` key | `legacy cleanup-only` | Legacy cleanup | Cleanup-only | cleanup only | Production launch authentication is always required; Reset removes this legacy key |
| `encryptToSelf` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no | Current sync read path still exists in Encrypt flow |
| `clipboardNotice` | `ProtectedSettingsStore`; legacy `UserDefaults` key for migration cleanup | `protected-after-unlock` | Phase 3 | Implemented | yes | Only completed Phase 3 setting; legacy key is removed after migration |
| `guidedTutorialCompletedVersion` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no | Current sync read path still exists in tutorial and Settings entry flows |
| `uiTestBypassAuthentication` | Test-only `UserDefaults` key | `test-only exception` | Test-only exception | Exception retained | n/a | Non-production bypass state; production code must not depend on it; Reset may delete stale production-suite residue |
| `rewrapInProgress` | `UserDefaults` | `private-key-control target` | Phase 5 | Pending | no | Future `private-key-control.recoveryJournal`; no pre-auth marker, and recovery detection should run only after app unlock opens the domain |
| `rewrapTargetMode` | `UserDefaults` | `private-key-control target` | Phase 5 | Pending | no | Future `private-key-control.recoveryJournal`; stores target mode details only after protected domain unlock |
| `modifyExpiryInProgress` | `UserDefaults` | `private-key-control target` | Phase 5 | Pending | no | Future `private-key-control.recoveryJournal`; no pre-auth marker, and recovery detection should run only after app unlock opens the domain |
| `modifyExpiryFingerprint` | `UserDefaults` | `private-key-control target` | Phase 5 | Pending | no | Future `private-key-control.recoveryJournal`; keeps the affected key fingerprint out of pre-auth UserDefaults |
| Permanent SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a | `se-key`, `salt`, and `sealed-key` rows remain under existing Secure Enclave / Keychain protection |
| Pending SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a | `pending-se-key`, `pending-salt`, and `pending-sealed-key` stay in the private-key material domain; protected recovery journals may reference them but must not store them |
| `PGPKeyIdentity` metadata rows | Dedicated Keychain metadata account | `key-metadata-domain target` | Phase 6 | Pending | no | Transitional cold-launch Keychain account; long-term target is a ProtectedData `key metadata` domain opened automatically after app unlock |
| Shared app-data root secret | Keychain default account | `framework-bootstrap` | Phase 1 | Implemented with SE device binding | implemented | Keychain-protected root secret released only through authenticated `LAContext` handoff; v2 stores a Secure Enclave device-bound envelope rather than raw root-secret bytes |
| `ProtectedDataRegistry` | `Application Support/ProtectedData/ProtectedDataRegistry.plist` | `framework-bootstrap` | Phase 1 / Phase 2 | Implemented | framework prerequisite | Bootstrap authority for membership and shared-resource lifecycle; file-protection coverage belongs to Phase 2 |
| Per-domain bootstrap metadata | `Application Support/ProtectedData/<domain>/bootstrap.plist` | `framework-bootstrap` | Phase 2 / domain phase | Implemented for existing domain | domain-specific | Read before app-data authorization by design; contains framework metadata, not protected payload plaintext |
| Protected settings payload | `Application Support/ProtectedData/protected-settings/` | `protected-after-unlock` | Phase 3 | Implemented narrowly | implemented | Current `clipboardNotice` domain with encrypted generations and wrapped DMK metadata |
| `Documents/contacts/*.gpg` | App sandbox documents | `protected-after-unlock` | Phase 8 | Pending | no | Planned Contacts protected domain; includes imported public certificates used for encryption and verification enrichment |
| `Documents/contacts/contact-metadata.json` | App sandbox documents | `protected-after-unlock` | Phase 8 | Pending | no | Planned Contacts protected domain; stores verification-state manifest |
| `Documents/self-test/` | App sandbox documents | `protected-after-unlock` or `ephemeral-with-cleanup` | Phase 7 | Pending | no | Decide whether to move reports into a protected diagnostics domain or make reports short-lived/export-only |
| `tmp/decrypted/` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial | Decrypted file previews; cleanup exists in some flows, but file-protection review remains Phase 7 work |
| `tmp/streaming/` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial | Streaming encrypt/decrypt outputs; startup cleanup exists, but file-protection review remains Phase 7 work |
| `tmp/export-*` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial | Temporary fileExporter handoff files; deleted by owner/reset cleanup where possible, with remaining cleanup/file-protection review in Phase 7 |
| `tmp/CypherAirGuidedTutorial-*` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial | Tutorial contacts sandbox; isolated from real app data and deleted on tutorial cleanup/reset, with remaining cleanup/file-protection review in Phase 7 |
| Tutorial `UserDefaults` suite | Temporary tutorial suite name | `ephemeral-with-cleanup` | Phase 7 | Partial | partial | Tutorial-only settings sandbox; removed on tutorial cleanup, with remaining cleanup review in Phase 7 |
| Files exported to user-selected locations | Outside app-controlled sandbox after export | `out-of-app-custody` | Out-of-app-custody exception | Exception retained | n/a | Once the user saves/shares a file outside CypherAir's container, protection depends on the destination |

### 4.1 Private-Key Material Exceptions And Future Private-Key Control Domains

The following private-key material surfaces are reviewed explicitly for scope control, but they are not app-data migration targets in this guide because their existing Keychain and Secure Enclave model remains semantically unchanged:

- permanent SE-wrapped private-key bundles
- pending SE-wrapped private-key bundles used during mode-switch and modify-expiry recovery

Private-key-adjacent control state is not exempt forever. The long-term target is one physical ProtectedData `private-key-control` domain with logical sections:

- `settings.authMode` for the current private-key protection mode
- `recoveryJournal` for rewrap and modify-expiry recovery state

The `private-key-control` domain must be opened after app privacy authentication by reusing the current authenticated context. Pre-auth startup must not retain a recovery marker for this domain. Recovery detection and any warning about interrupted private-key operations should run after this post-unlock open step.

Key metadata is also not a permanent private-key-material exception. The dedicated Keychain metadata account is a transitional cold-launch index. The long-term target is a ProtectedData `key metadata` domain that opens after app unlock and loads `PGPKeyIdentity` state without touching private-key bundle rows.

### 4.2 Unified Protection Roadmap

The inventory follows the same numeric phase order as Section 2:

- Phase 4: extend post-unlock orchestration and harden second-domain framework behavior before additional product domains depend on it
- Phase 5: create the `private-key-control` domain, migrate `authMode` and the private-key `recoveryJournal`, and move rewrap / modify-expiry recovery detection out of pre-auth startup
- Phase 6: create the `key metadata` domain, migrate `PGPKeyIdentity` metadata out of the transitional Keychain metadata account, and avoid empty-key-list flashes during unlock
- Phase 7: migrate non-Contacts ordinary protected-after-unlock settings, self-test policy, and local file/static-protection cleanup once synchronous read paths have been removed or replaced
- Phase 8: migrate Contacts as a later independent protected domain on the shared framework
- Phase 9: migrate future app-owned persistent domains not yet covered by the current inventory

Protected-settings route requirement:

- When the user is already on Settings, backgrounds the app, and returns through app privacy unlock, `contentClearGeneration` invalidation should non-interactively auto-open protected settings if the session is already authorized or a handoff context is available.
- This requirement must not add a new Face ID prompt; it only aligns the existing Settings instance with the auto-open behavior already used when entering Settings from another page.

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
