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

The current proposal direction is also too dependent on app-managed authorization timing. For app-data domains, the revised v1 goal is to make the **first release of the domain unlock secret itself** a system-enforced boundary rather than a convention owned only by application code.

## 3. Hard Constraints

This roadmap is bounded by the following non-negotiable constraints:

- zero network access remains a hard requirement
- no notification, share-extension, or other extension-specific assumptions are allowed in the baseline design
- existing private-key protection must not be weakened to make the new layer easier to build
- the new layer must preserve a minimal bootstrap boundary for cold start and recovery
- protected app-data domains must not silently reset to empty state after corruption or unreadable local wrapping state
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

### 4.2 Per-Domain Master Keys

Protected app data will use **per-domain master keys**, not one literal global root key.

Rationale:

- matches the existing future direction already established in Contacts planning
- allows different domains to migrate independently
- avoids turning every protected app-owned byte into a single blast-radius failure
- keeps future export, recovery, and lifecycle rules domain-scoped

This initiative therefore treats "AppKey" as a conceptual app-data protection layer, not as a mandate for one monolithic symmetric key.

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

- each domain persists encrypted payload generations on disk
- the domain unlock secret is protected by `LAPersistedRight`
- the right uses `LAAuthenticationRequirement.default`
- the system must not return the unlock secret before the right is authorized
- once authorized, the secret may be cached for the authenticated app session and must be cleared on relock

This means the first gate for app-data unlock is no longer "application code remembered to check session state first." The first gate is the system-managed authorization boundary for the persisted right.

For future protected domains, `LAPersistedRight.authorize(...)` is the single normative app-data authorization boundary.

Existing `AuthenticationManager` / `AuthenticationMode` launch-resume authentication may remain as separate privacy UX in shipped code, but it must not be described as the required gate for future app-data unlock semantics.

### 4.5 Minimal Bootstrap Metadata

The system may keep a minimal layer of plaintext bootstrap metadata outside encrypted domain payloads when required for cold start, recovery, or migration routing.

In v1, this bootstrap metadata is file-side metadata stored beside encrypted generations. It is not stored in Keychain.

This bootstrap layer must be:

- minimal
- non-secret
- non-social-graph-bearing
- non-content-bearing
- insufficient to recreate meaningful business data

Typical acceptable bootstrap information includes:

- schema or envelope version
- whether a domain exists locally
- generation identifiers
- coarse recovery state markers

This allowance exists to keep startup recovery deterministic. It is not permission to leave broad app state outside protected domains.

### 4.6 Private-Key And App-Data Secure Enclave Boundary

The current private-key design uses indirect Secure Enclave wrapping because the app's OpenPGP private keys are not directly managed by the Secure Enclave.

Protected app-data domains are different:

- their domain unlock secret is app-generated
- Apple provides a higher-level LocalAuthentication right model for gating access to a key and a secret
- Apple documents `LAPersistedRight` as being backed by a unique key in the Secure Enclave

Choosing `LAPersistedRight` as the primary app-data gate in v1 therefore does **not** mean dropping Secure Enclave involvement. It means preferring the system's higher-level right/secret model over a custom app-managed unlock-secret gate.

### 4.7 Dedicated App-Data Authorization Policy

Protected app-data domains must use a dedicated app-data authorization policy.

This policy is separate from the private-key access-control source of truth.

In v1, this means:

- app-data authorization must not derive from `AuthenticationMode`
- app-data authorization must not call `AuthenticationMode.createAccessControl()`
- app-data authorization must not call `AuthenticationManager.createAccessControl(for:)`
- all v1 app-data domains use `LAAuthenticationRequirement.default`
- app-data domains must not inherit current `Standard` / `High Security` semantics
- app-data domains must not inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- per-domain authorization-policy variation is out of scope in v1 unless a later domain-specific proposal explicitly reopens it

This rule exists to preserve the intended boundary: private-key security semantics remain private-key-specific.

## 5. Migration Order

Implementation should follow this sequence.

### Phase 1: Protected App-Data Framework

Build the reusable protected app-data substrate first.

Goals:

- establish shared terminology and lifecycle
- define common envelope and recovery rules
- define a system-gated app-data authorization model that is separate from the private-key access-control source of truth
- define a strict startup authentication boundary
- define common relock, deauthorize, and session-unlock semantics
- define the v1 `Domain Master Key` persistence and recovery model
- define the initial persistent-state classification inventory

This phase should land before Contacts migration so Contacts can depend on the shared framework instead of creating its own parallel architecture.

### Phase 2: File-Protection Baseline

Establish the file/static-protection baseline required by protected-domain storage before any real protected domain lands in code.

Goals:

- define the minimum platform-specific local static protection contract for protected-domain files
- define the required protection for bootstrap metadata and temporary scratch files
- ensure no real protected domain ships without its file/static-protection baseline

### Phase 3: First Low-Risk Real Domain

Use a low-risk domain such as protected-after-unlock settings or recovery/control state as the first adopter.

Goals:

- exercise the new framework without touching the private-key domain
- validate authorize / unlock / relock / deauthorize behavior on real app-owned data
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

Phase 3 may migrate only settings or control state that do not participate in early boot routing, launch-time authentication decisions, or pre-unlock presentation decisions.

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
- avoid duplicating domain key lifecycle, envelope handling, recovery logic, and relock rules
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
- read file-side bootstrap metadata
- route cold start and determine whether protected domains exist

Before app-data authorization succeeds, the app must **not**:

- fetch `LASecret`
- authorize a domain right implicitly in an initializer or getter
- attempt to open protected-domain generations
- finalize `locked / unlocked / recoveryNeeded` from protected-domain contents

#### Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- authorize the domain right through the protected-data session layer
- fetch the domain unlock secret
- open `current / previous / pending`
- determine final `locked / unlocked / recoveryNeeded` state

This startup boundary is a required implementation constraint, not a best-effort guideline.

### 5.2 Persistent-State Classification Inventory

Before any real protected domain lands, implementation planning must maintain a complete inventory of currently persisted app-owned state.

Each persisted item must be classified as exactly one of:

- `early-readable`
- `protected-after-unlock`
- `remain plaintext with rationale`

At minimum this inventory must include:

- current `AppConfiguration` keys
- auth and recovery flags currently stored in `UserDefaults`
- any future app-owned bootstrap metadata

The inventory must prevent three failure modes:

- omitted state that never gets reviewed for migration
- state that is moved into a protected domain even though startup still needs it before authorization
- state that remains plaintext indefinitely without an explicit documented reason

The reviewed inventory must include not only `UserDefaults`, but also currently persisted app-owned files and directories that remain outside the protected-domain migration in this round.

### 5.3 Startup Architecture Impact

The protected app-data proposal is no longer just a narrow service-layer addition.

For any future real protected domain, the implementation plan must treat the following as explicit architecture migration areas:

- startup ordering
- service initialization timing
- locked-state UI routing
- post-auth unlock orchestration
- final `locked / unlocked / recoveryNeeded` classification timing

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
- use `LAPersistedRight` as the primary app-data authorization gate in v1
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
- `ProtectedDomainBootstrapStore.swift`
- `ProtectedDomainKeyManager.swift`
- `ProtectedDataSessionCoordinator.swift`
- `ProtectedDomainRecoveryCoordinator.swift`

Recommended first concrete adopter:

- `ProtectedSettingsStore`

Expected narrow integration seams:

- `AppContainer` for dependency construction
- `AppStartupCoordinator` for protected-domain startup recovery
- app lock / resume flow for authorize, relock, deauthorize, and authenticated session reuse
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
- does it treat `LAPersistedRight` as the first gate for app-data unlock secret access?
- does it avoid making `AuthenticationMode` the normative gate for future app-data authorization?
- does it fully specify the `Domain Master Key` persistence and recovery model?
- does it keep app-data domains recoverable rather than private-key-style invalidating?
- does it keep bootstrap metadata minimal and non-sensitive?
- does it harden file protection explicitly instead of relying on platform defaults?
- does it classify all existing persisted app-owned state into a reviewed storage class?
- does it make Contacts a consumer of the framework rather than the owner of a separate architecture?
- does it keep anti-rollback explicitly out of scope in v1 rather than implying freshness guarantees?
