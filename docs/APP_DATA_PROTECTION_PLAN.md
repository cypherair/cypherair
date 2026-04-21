# App Data Protection Migration Plan

> **Version:** Draft v1.0  
> **Status:** Draft active roadmap. This document does not describe current shipped behavior.  
> **Purpose:** Define the migration strategy for introducing a protected app-data layer beside the existing private-key security architecture.  
> **Audience:** Engineering, security review, QA, and AI coding tools.  
> **Companion document:** [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)  
> **Related documents:** [SECURITY](SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [TESTING](TESTING.md) · [CONTACTS_PRD](CONTACTS_PRD.md) · [CONTACTS_TDD](CONTACTS_TDD.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Intent

CypherAir already applies strong hardware-backed protection to private keys:

- Secure Enclave wrapping
- Keychain storage with `WhenUnlockedThisDeviceOnly`
- per-operation authentication for decrypt, sign, export, and other private-key actions
- explicit Standard / High Security semantics

That private-key path remains the authoritative security domain for key material.

This roadmap exists because the rest of the app's persistent state does not yet share a uniform protection model. Contacts, security-sensitive app state, recovery state, and future local caches should ultimately live inside a dedicated protected app-data architecture rather than relying on ad hoc file or preferences storage.

This initiative introduces a **new protected app-data layer**. It is not a rewrite of the private-key system.

## 2. Problem Statement

The current security posture is intentionally asymmetric:

- private keys receive strong device-bound protection
- app-owned persistent data outside the private-key path does not yet receive the same uniform treatment

This is acceptable as an intermediate state, but not as the long-term target.

The missing capability is not "stronger private-key protection." The missing capability is a reusable framework for:

- protecting app-owned persistent data at rest
- unlocking that data for the authenticated app session
- relocking and zeroizing that data when the session ends
- recovering deterministically from interrupted writes or unreadable state
- supporting later feature domains without forcing each one to invent a new vault architecture

The current proposal direction is also too dependent on app-managed authorization timing. For app-data domains, the revised v1 goal is to make the **first release of the shared app-data secret itself** a system-enforced boundary rather than a convention owned only by application code.

## 3. Hard Constraints

This roadmap is bounded by the following non-negotiable constraints:

- zero network access remains a hard requirement
- no notification, share-extension, or other extension-specific assumptions are allowed in the baseline design
- existing private-key protection must not be weakened to make the new layer easier to build
- the new layer must preserve a minimal bootstrap boundary for cold start and recovery
- protected app-data domains must not silently reset to empty state after corruption or unreadable local state
- future implementation should prefer new files and composition over invasive edits to current private-key code

### 3.1 Private-Key Stability Rule

Unless a concrete security defect is discovered, this initiative does **not** change:

- current Secure Enclave private-key wrapping semantics
- current Standard / High Security behavior
- current per-operation private-key authentication boundaries

Private-key protection is treated as already sound enough to remain the separate authority for secret key material.

## 4. Target Architecture Decisions

### 4.1 Separate Security Domains

CypherAir will explicitly separate two security domains:

- **Private Key Domain**
- **Protected App Data Domains**

The Private Key Domain retains the existing design for secret key material.

Protected App Data Domains cover persistent app-owned data that should be protected at rest and unlocked only for the authenticated app session, but that should not inherit private-key-specific loss semantics.

### 4.2 Shared Gate With Per-Domain Master Keys

Protected app data will use:

- one shared app-data `LAPersistedRight`
- one shared app-data secret protected by that right
- one `Domain Master Key` per protected domain

The shared app-data secret acts as the session-level KEK for per-domain DMKs.

Rationale:

- preserves per-domain isolation for envelope, recovery, deletion, and future rekey behavior
- avoids per-domain prompt repetition inside one active app-data session
- avoids a literal single global DMK for every protected byte
- keeps the first system-gated secret release at the shared app-data session boundary

Per-domain DMKs do **not** imply per-domain authorization prompts in v1. Domain isolation remains at the DMK, envelope, lifecycle, and recovery layers even when authorization is shared.

### 4.3 Recoverable App-Data Domains

Protected app-data domains are **recoverable domains**.

This means:

- they remain device-bound on the local installation
- they reuse authenticated app-session unlock semantics
- they do **not** inherit private-key-style biometric re-enrollment invalidation semantics from future `Special Security Mode`
- they do **not** require rewrapping merely because the private-key authentication mode changes

The design goal is to keep private-key risk surfaces and app-data risk surfaces deliberately separate.

### 4.4 System-Gated App-Data Authorization

Protected app-data domains use a **system-gated persisted right** as the primary authorization boundary in v1.

The canonical v1 model is:

- one shared app-data `LAPersistedRight` protects one shared app-data secret
- the shared right uses `LAAuthenticationRequirement.default`
- the shared app-data secret is the only system-gated secret released by the right
- per-domain DMKs remain distinct and are unwrapped only after shared authorization succeeds
- one successful shared-right authorization covers all protected domains in the current app-data session
- later domain access in that same app-data session must not require another authorization prompt

This means the first gate for app-data unlock is no longer "application code remembered to check session state first." The first gate is the system-managed authorization boundary for the shared persisted right.

For future protected domains, `LAPersistedRight.authorize(...)` remains the single normative app-data authorization boundary.

### 4.5 ProtectedDataRegistry As Lifecycle Authority

Protected app-data must use one global **`ProtectedDataRegistry`** as the sole authority for:

- committed protected-domain membership
- shared-resource lifecycle
- pending create/delete mutation state
- recovery reconciliation order

The registry is a single manifest stored under:

```text
Application Support/ProtectedData/
```

Normal lifecycle decisions must follow registry state, not filesystem inference.

In v1:

- domains in committed `active` or domain-scoped `recoveryNeeded` state count as members
- domains in transient `creating` or `deleting` state do not count as committed members
- orphaned directories, bootstrap metadata files, or wrapped-DMK artifacts never implicitly become members
- shared right and shared secret must exist whenever committed membership is non-empty
- shared right and shared secret may be deleted only after registry state has committed membership to empty

Directory enumeration and per-domain bootstrap metadata may be used during recovery as evidence to repair or quarantine state, but they are never the normal authority for deciding whether the last protected domain still exists.

### 4.6 Unified Session Orchestration

The target app-data architecture uses two layers:

- **`AppSessionOrchestrator`**
- **`ProtectedDataSessionCoordinator`**

`AppSessionOrchestrator` is the app-wide session owner.

In v1 planning, it is the only owner of:

- grace-window policy
- launch/resume privacy-auth sequencing
- app lock / relock initiation
- scene lifecycle intake
- the decision that protected-domain access may proceed

`ProtectedDataSessionCoordinator` sits under that orchestrator and is the app-data subsystem coordinator.

In v1 planning, it is the only owner of:

- the strong reference to the shared `LAPersistedRight`
- shared app-data secret lifetime in memory
- shared right authorize/deauthorize behavior
- app-data shared-session state
- zeroization of the shared secret and all unwrapped DMKs on relock

Existing launch/resume privacy auth is therefore not the long-term parallel authority for app-data unlock. It is absorbed into the top-level `AppSessionOrchestrator`, while `LAPersistedRight.authorize(...)` remains the normative app-data gate triggered through orchestrator-controlled sequencing.

### 4.7 Minimal Bootstrap Metadata

The system may keep a minimal layer of plaintext bootstrap metadata outside encrypted domain payloads when required for cold start, recovery, or migration routing.

In v1, this bootstrap layer consists of:

- the global `ProtectedDataRegistry`
- minimal per-domain bootstrap metadata stored beside encrypted generations

This bootstrap layer must be:

- minimal
- non-secret
- non-social-graph-bearing
- non-content-bearing
- insufficient to recreate meaningful business data

Typical acceptable bootstrap information includes:

- registry or envelope version markers
- committed domain membership
- shared-resource lifecycle state
- generation identifiers
- coarse recovery state markers
- wrapped-DMK record presence/version

This allowance exists to keep startup recovery deterministic. It is not permission to leave broad app state outside protected domains.

### 4.8 Private-Key And App-Data Secure Enclave Boundary

The current private-key design uses indirect Secure Enclave wrapping because the app's OpenPGP private keys are not directly managed by the Secure Enclave.

Protected app-data domains are different:

- their shared app-data secret is app-generated and persisted through `LAPersistedRight`
- Apple provides a higher-level LocalAuthentication right model for gating access to a key and a secret
- Apple documents `LAPersistedRight` as being backed by a unique key in the Secure Enclave

Choosing `LAPersistedRight` as the primary app-data gate in v1 therefore does **not** mean dropping Secure Enclave involvement. It means preferring the system's higher-level right/secret model over a custom app-managed unlock-secret gate.

### 4.9 Dedicated App-Data Authorization Policy

Protected app-data domains must use a dedicated app-data authorization policy.

This policy is separate from the private-key access-control source of truth.

In v1, this means:

- app-data authorization must not derive from `AuthenticationMode`
- app-data authorization must not call `AuthenticationMode.createAccessControl()`
- app-data authorization must not call `AuthenticationManager.createAccessControl(for:)`
- the shared app-data right uses `LAAuthenticationRequirement.default`
- app-data domains must not inherit current `Standard` / `High Security` semantics
- app-data domains must not inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- per-domain authorization-policy variation is out of scope in v1 unless a later domain-specific proposal explicitly reopens it
- per-domain right authorization is out of scope in v1

This rule exists to preserve the intended boundary: private-key security semantics remain private-key-specific.

## 5. Migration Order

Implementation should follow this sequence.

### Phase 1: Protected App-Data Framework

Build the reusable protected app-data substrate first.

Goals:

- establish shared terminology and lifecycle
- define common envelope and recovery rules
- define the shared-gate / per-domain-DMK topology
- define the `ProtectedDataRegistry` contract before any real domain lands
- define unified session orchestration before any real domain lands
- define a system-gated app-data authorization model that is separate from the private-key access-control source of truth
- define a strict startup authentication boundary
- define common relock, deauthorize, and session-unlock semantics
- define the v1 DMK persistence and wrapped-DMK model
- define the initial persistent-state classification inventory

This phase should land before Contacts migration so Contacts can depend on the shared framework instead of creating its own parallel architecture.

### Phase 2: File-Protection Baseline

Establish the file/static-protection baseline required by protected-domain storage before any real protected domain lands in code.

Goals:

- define the minimum platform-specific local static protection contract for registry files, protected-domain files, bootstrap metadata, and temporary scratch files
- ensure no real protected domain ships without its file/static-protection baseline

### Phase 3: First Low-Risk Real Domain

Use a low-risk domain such as protected-after-unlock settings or recovery/control state as the first adopter.

Goals:

- exercise the new framework without touching the private-key domain
- validate shared authorize / lazy unlock / relock / deauthorize behavior on real app-owned data
- reduce plaintext or lightly protected security-sensitive preferences over time

Phase 3 uses a split-settings model.

#### Bootstrap-Critical Settings

The following settings remain in the early-readable layer in v1 because they are read before protected domains unlock:

- `authMode`
- `gracePeriod`
- `requireAuthOnLaunch`
- `hasCompletedOnboarding`
- `colorTheme`

These settings are not eligible for `ProtectedSettingsStore` in Phase 3.

#### Protected-After-Unlock Settings / Control State

Phase 3 may migrate only settings or control state that:

- are target-classified as `protected-after-unlock`
- are no longer required by synchronous or pre-unlock read paths

Phase 3 must not rely on a shadow copy of protected settings to recreate early boot behavior.

This first real domain must also declare its recovery contract up front:

- `ProtectedSettingsStore`-style non-bootstrap settings/control state are **resettable with explicit destructive confirmation**
- they are not import-recoverable in v1
- they must never silently reset on unreadable local state

### Phase 4: Contacts Vault On Shared Framework

Migrate Contacts to the shared protected app-data framework rather than letting Contacts become a one-off vault system.

Goals:

- preserve the Contacts product and TDD direction
- ensure Contacts remains a domain-specific consumer of the shared substrate
- avoid duplicating domain key lifecycle, envelope handling, recovery logic, registry authority, and relock rules
- keep Contacts explicitly **import-recoverable**

### Phase 5: Remaining Persistent Domains

Migrate remaining app-owned persistent domains in order of security value and implementation risk.

Candidate areas include:

- additional settings or recovery state not yet moved in Phase 3
- future local drafts or protected caches
- future user-managed local data that should not remain plaintext at rest

### 5.1 Startup Authentication Boundary

All future implementations derived from this roadmap must follow a two-phase startup model.

#### Pre-Auth Bootstrap Phase

Before app-data authorization succeeds, the app may:

- read bootstrap-critical settings
- read the `ProtectedDataRegistry`
- read file-side per-domain bootstrap metadata
- route cold start and determine whether protected domains exist

Before app-data authorization succeeds, the app must **not**:

- fetch `LASecret`
- authorize the shared app-data right implicitly in an initializer or getter
- unwrap any domain DMK
- attempt to open protected-domain generations
- finalize framework or domain recovery state from protected-domain contents alone

#### Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- authorize the shared right through the protected-data session layer
- fetch the shared app-data secret
- lazy-unlock a requested domain DMK
- open `current / previous / pending`
- determine final framework and domain state

This startup boundary is a required implementation constraint, not a best-effort guideline.

### 5.2 App-Data Session Lifetime

The shared app-data session follows the current grace-window model, but the grace window has only one owner: `AppSessionOrchestrator`.

In v1:

- launch/resume first enters `AppSessionOrchestrator`
- if app session is not active, the orchestrator completes app-level privacy unlock first
- shared right authorization starts only on first real protected-domain access
- shared right authorization does not eagerly unwrap every domain DMK
- a second or third protected domain in the same active app-data session must not prompt again
- app-data relock and deauthorize occur only on:
  - explicit app lock
  - grace-period expiration
  - session loss
  - app termination or exit
- entering background alone does **not** deauthorize app-data while the grace window is still valid
- `gracePeriod = 0` is the supported posture for "every resume requires fresh authorization before protected-domain access"

### 5.3 Persistent-State Classification Inventory

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
| `Documents/contacts/*.gpg` | App sandbox documents | `remain plaintext with rationale` | n/a in this round | Existing Contacts storage stays outside this round until Contacts docs are revised |
| `Documents/contacts/contact-metadata.json` | App sandbox documents | `remain plaintext with rationale` | n/a in this round | Existing Contacts metadata stays outside this round until Contacts docs are revised |
| `Documents/self-test/` | App sandbox documents | `remain plaintext with rationale` | n/a in v1 | Diagnostic output remains outside protected-domain scope |
| `ProtectedDataRegistry` | App-owned bootstrap manifest | `early-readable` | framework prerequisite | Bootstrap authority for membership and shared-resource lifecycle |
| future per-domain bootstrap metadata | App-owned bootstrap files | `early-readable` | domain-specific | Read before app-data authorization by design |

### 5.4 Startup Architecture Impact

The protected app-data proposal is no longer just a narrow service-layer addition.

For any future real protected domain, the implementation plan must treat the following as explicit architecture migration areas:

- startup ordering
- service initialization timing
- locked-state UI routing
- `AppSessionOrchestrator` wiring
- `ProtectedDataSessionCoordinator` wiring
- final framework and domain state classification timing

This is especially important for future Contacts adoption, where cold-start loading and locked-state presentation already exist in the app surface.

## 6. Explicit Do-Not-Change List

This roadmap does **not** authorize broad edits to the current private-key security path.

Treat the following as out of scope unless a concrete defect requires targeted follow-up:

- `Sources/Security/SecureEnclaveManager.swift`
- `Sources/Security/AuthenticationManager.swift`
- `Sources/Services/DecryptionService.swift`
- existing private-key wrap / unwrap semantics
- existing Standard / High Security semantics
- existing per-operation private-key authentication boundaries

The preferred implementation posture is:

- new files for the new layer
- narrow dependency wiring
- use one shared `LAPersistedRight` as the primary app-data authorization gate in v1
- reuse existing lower-level primitives by composition only where they support, rather than replace, that system gate
- never attach the new layer to the private-key access-control source of truth
- no "cleanup refactor" of the private-key domain just to make the new layer look symmetrical

This proposal also does not require future protected domains to depend on the current `AuthenticationMode` gate in order to reach app-data authorization.

## 7. Code / Interface Direction

The new protected app-data layer should primarily appear as new code under a dedicated area such as:

```text
Sources/Security/ProtectedData/
```

Recommended initial files:

- `ProtectedDataDomain.swift`
- `ProtectedDomainEnvelope.swift`
- `ProtectedDataRegistry.swift`
- `ProtectedDomainBootstrapStore.swift`
- `ProtectedDomainKeyManager.swift`
- `ProtectedDataSessionCoordinator.swift`
- `ProtectedDomainRecoveryCoordinator.swift`
- `AppSessionOrchestrator.swift`

Recommended first concrete adopter:

- `ProtectedSettingsStore`

Expected narrow integration seams:

- `AppContainer` for dependency construction
- `AppStartupCoordinator` for protected-domain startup recovery
- app lock / resume flow through `AppSessionOrchestrator`
- future Contacts integration

The phrase "narrow integration seams" must not be interpreted as "no startup architecture impact." Future real protected domains are still expected to require explicit startup-flow changes.

## 8. Canonicalization Plan

These two new documents are planning and design inputs first. They are not yet canonical replacements for current-state docs.

After approval and implementation maturity:

- fold accepted app-data protection rules into [SECURITY](SECURITY.md)
- update [ARCHITECTURE](ARCHITECTURE.md) with the new domain boundaries and startup wiring
- update [TESTING](TESTING.md) with protected-domain validation requirements
- update [PRD](PRD.md) or future domain-specific PRDs when user-visible behavior changes
- update [TDD](TDD.md) only for durable cross-cutting technical rules that become current-state

Until then:

- current code and canonical docs outrank this roadmap for shipped behavior
- this roadmap exists to prevent inconsistent one-off implementations

## 9. Review Questions For Future Implementation

Any implementation derived from this roadmap should be reviewable against these questions:

- does it preserve the existing private-key domain without semantic drift?
- does it introduce a reusable protected app-data substrate rather than a one-off vault?
- does it treat one shared `LAPersistedRight` as the first gate for app-data unlock secret access?
- does it avoid making `AuthenticationMode` the normative gate for future app-data authorization?
- does it fully specify `ProtectedDataRegistry` as the only membership authority?
- does it fully specify the shared-resource create/delete lifecycle and last-domain rule?
- does it fully specify the DMK persistence and wrapped-DMK model?
- does it make `AppSessionOrchestrator` the only grace-window owner?
- does it keep app-data domains recoverable rather than private-key-style invalidating?
- does it keep framework-level and domain-level recovery separate?
- does it keep bootstrap metadata minimal and non-sensitive?
- does it harden file protection explicitly instead of relying on platform defaults?
- does it classify all existing persisted app-owned state into a reviewed target class and migration-readiness state?
- does it make Contacts a consumer of the framework rather than the owner of a separate architecture?
- does it keep anti-rollback explicitly out of scope in v1 rather than implying freshness guarantees?
