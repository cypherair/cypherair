# App Data Protection Technical Design Document

> **Version:** Draft v1.0  
> **Status:** Draft future technical spec. This document does not describe current shipped behavior.  
> **Purpose:** Define the reusable technical substrate for protected app-owned persistent data outside the existing private-key domain.  
> **Audience:** Engineering, security review, QA, and AI coding tools.  
> **Companion document:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md)  
> **Related documents:** [SECURITY](SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [TESTING](TESTING.md) · [CONTACTS_TDD](CONTACTS_TDD.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Technical Scope

This document defines the reusable framework for protecting app-owned persistent data at rest while keeping the existing private-key architecture separate.

This TDD covers:

- shared terminology for protected app-data domains
- domain master key lifecycle
- app-session unlock and relock behavior
- protected domain storage and recovery model
- explicit file-protection posture for protected domain files
- initial framework interfaces for future implementation
- migration rules for moving plaintext or non-uniform state into protected domains

This TDD does **not** redesign the current private-key system.

## 2. Non-Goals

This document does not authorize or require:

- rewrites of the current private-key wrapping path
- changes to Standard / High Security behavior
- changes to private-key auth-mode switching semantics
- merging app-data recovery and private-key recovery into one shared state machine
- a literal global single-key design that conflicts with current Contacts direction
- notification, extension, or network-driven assumptions
- anti-rollback or freshness guarantees in v1

## 3. Terminology

### 3.1 Private Key Domain

The existing security domain that protects secret OpenPGP key material.

Properties:

- per-operation authentication boundaries
- current Secure Enclave wrapping semantics
- current Standard / High Security behavior
- future `Special Security Mode` behavior for private-key loss semantics

This domain remains separate and authoritative for secret keys.

### 3.2 Protected App Data Domain

A reusable security domain for app-owned persistent data that should be:

- encrypted at rest
- unlocked for the authenticated app session
- relocked when the session ends
- recoverable through explicit domain recovery rules

Examples:

- protected settings or recovery/control state
- Contacts vault
- future protected local drafts or caches

### 3.3 Domain Master Key

A random 256-bit symmetric key that encrypts one protected app-data domain.

Properties:

- unique per domain
- never stored in plaintext
- used to encrypt domain payload generations on disk
- re-established independently on import or recovery flows when needed
- persisted in a v1 domain-specific protected form that is stable across startup, relock, and crash recovery

### 3.4 Bootstrap Metadata

Minimal non-secret metadata stored outside the encrypted domain payload so cold start and deterministic recovery remain possible.

Allowed examples:

- schema version
- domain presence marker
- generation identifiers
- coarse recovery state flags

Disallowed examples:

- decrypted domain content
- relationship graph information
- user text, notes, tags, recipient sets, or meaningful business data
- plaintext caches or search indexes

### 3.5 Locked / Unlocked / RecoveryNeeded

Protected domains expose explicit runtime state:

- `locked`: domain exists locally but its master key is not active in memory
- `unlocked`: master key is active for the authenticated app session and the domain may be opened
- `recoveryNeeded`: local state exists, but no readable authoritative generation can be opened with the local wrapping material

Protected domains must never silently substitute an empty state for `locked` or `recoveryNeeded`.

## 4. Design Principles

The framework must satisfy these principles:

- offline-only operation
- composition over invasive refactor of the private-key domain
- per-domain isolation with shared infrastructure
- deterministic crash recovery
- no silent reset to empty state
- explicit session unlock and relock behavior
- system-enforced authorization before the app receives the domain unlock secret
- explicit zeroization expectations for sensitive in-memory buffers
- explicit file-protection policy instead of relying on platform defaults

## 5. Core Design Decisions

### 5.1 Per-Domain Master Keys

Each protected app-data domain owns its own `Domain Master Key`.

This is the canonical design.

Rationale:

- aligns with current Contacts direction
- limits blast radius
- allows independent migration, export, import, and recovery behavior per domain
- avoids treating every app-owned state transition as a single all-or-nothing vault event

### 5.2 Device-Bound Wrapping

The current private-key design uses Secure Enclave indirect wrapping because OpenPGP private keys aren't directly managed by the Secure Enclave.

Protected app-data domains use a different primary model in v1:

- encrypted domain payloads remain app-managed on disk
- the domain unlock secret is gated by `LAPersistedRight`
- Apple documents `LAPersistedRight` as being backed by a unique key in the Secure Enclave

This means the v1 app-data proposal still relies on Secure Enclave-backed system authorization, but it does so through Apple's higher-level LocalAuthentication right model rather than through custom Secure Enclave wrapping as the primary gate.

Implementation rule:

- treat `LAPersistedRight` / `LASecret` as the primary authorization gate for app-data unlock secrets
- do not promise custom SE self-ECDH wrapping as the primary app-data design in v1
- reuse lower-level primitives only where they support the domain model without replacing the primary system gate

Expected properties:

- local-only
- system-gated access to the domain unlock secret
- app code must not receive that secret before authorization succeeds
- source-device authorization state must not be exported as part of portable recovery

### 5.3 App-Data Wrapping Access-Control Contract

`ProtectedDomainKeyManager` owns the lifecycle of the app-data domain unlock secret, but the primary authorization gate is the system-managed persisted right.

This policy is a normative requirement, not an implementation detail left for later.

Required rules:

- app-data domains use `LAPersistedRight` as the primary app-data authorization gate in v1
- all v1 app-data domains use `LAAuthenticationRequirement.default`
- app-data authorization must **not** call `AuthenticationMode.createAccessControl()`
- app-data authorization must **not** call `AuthenticationManager.createAccessControl(for:)`
- app-data authorization must **not** derive from the private-key authentication mode
- app-data domains must **not** inherit current `Standard` / `High Security` semantics
- app-data domains must **not** inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- per-domain authorization-policy variation is out of scope in v1
- protected app-data domains must never rewrap merely because private-key auth mode changes
- the system must not return the domain unlock secret before right authorization succeeds

The purpose of this contract is to prevent the new layer from attaching itself to the private-key access-control source of truth.

### 5.4 Session-Unlocked Access Model

Protected app-data domains unlock for the authenticated app session rather than per operation.

Canonical behavior:

- the app-data right is authorized by `ProtectedDataSessionCoordinator` after successful app launch or resume authentication
- the domain unlock secret is fetched only after authorization succeeds
- ordinary in-session reads and writes reuse the authorized session
- relock occurs on app lock, grace-period expiry, session loss, or app exit
- relock must also deauthorize the right and clear any cached unlock secret from memory

This model intentionally differs from the private-key domain.

The authoritative v1 orchestration model is:

- existing app launch/resume authentication remains the outer app-auth boundary
- `ProtectedDataSessionCoordinator` then authorizes the app-data right as the authoritative gate for app-data unlock
- app-data domains do not bypass the right by treating prior app-auth alone as sufficient to release the unlock secret

Repeated-prompt avoidance is a required design goal. The implementation must minimize duplicate authorization prompts within one launch/resume flow by making `ProtectedDataSessionCoordinator` the sole owner of app-data right authorization timing.

### 5.5 Recoverable App-Data Semantics

Protected app-data domains are recoverable domains even if future private-key behavior becomes stricter under `Special Security Mode`.

Required rule:

- app-data domains must not inherit private-key-style biometric re-enrollment invalidation semantics

Stated differently:

- future private-key protection may use stronger, loss-prone semantics
- protected app-data domains must continue to use recoverable semantics
- app-data access is governed by the authenticated session and local recoverability rules, not by private-key loss semantics

### 5.6 Runtime Policy Separation

The framework separates:

- **system authorization** of the app-data unlock secret
- **runtime session reuse** for ordinary access after that authorization

This separation is required so:

- protected app-data domains do not need rewrapping when private-key auth modes change
- the system, not only application code, prevents pre-auth access to the unlock secret
- the app can still enforce session reuse and relock behavior without coupling app-data semantics to private-key rewrap cycles

### 5.7 Bootstrap-Critical Settings Whitelist

The following settings are bootstrap-critical in v1 because current startup or pre-unlock behavior depends on them before protected domains unlock:

- `authMode`
- `gracePeriod`
- `requireAuthOnLaunch`
- `hasCompletedOnboarding`
- `colorTheme`

Rules:

- these keys remain in the early-readable layer in v1
- Phase 2 must not migrate them into `ProtectedSettingsStore`
- protected settings must not rely on a shadow copy to recreate early boot behavior
- any future migration of a bootstrap-critical setting requires a separately documented two-phase startup design

### 5.8 Startup Authentication Boundary

Protected app-data domains must follow a two-phase startup model.

#### Pre-Auth Bootstrap Phase

Before app-data authorization succeeds, the app may:

- read bootstrap-critical settings
- read file-side bootstrap metadata
- determine whether protected domains exist and require later unlock

Before app-data authorization succeeds, the app must **not**:

- fetch `LASecret`
- authorize a right implicitly from a repository/service initializer or getter
- attempt to open protected-domain generations
- classify final `locked / unlocked / recoveryNeeded` state from protected-domain contents

#### Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- authorize the right through `ProtectedDataSessionCoordinator`
- fetch the domain unlock secret
- open `current / previous / pending`
- classify final `locked / unlocked / recoveryNeeded`

This is a required implementation boundary, not a best-effort guideline.

The current app startup path already performs cold-start loading and recovery work. Future real protected domains must therefore treat this two-phase model as an explicit startup-architecture migration, not as a mere local refactor inside one new service.

## 6. Storage Model

### 6.1 Domain Location

Protected app-data domains should live under app-owned `Application Support` storage in a dedicated subtree such as:

```text
Application Support/ProtectedData/<domain-id>/
```

Domain payloads are app-private and are not treated as user-managed document exports.

### 6.2 Encrypted Payloads

Each protected app-data domain stores encrypted payloads in versioned envelopes.

Canonical envelope properties:

- explicit envelope version
- domain identifier
- generation identifier
- nonce
- authenticated ciphertext
- integrity-protected associated metadata required to open the payload safely

Default envelope posture:

- authenticated encryption with `AES.GCM`
- random nonce per generation write
- associated data includes at minimum the domain identifier, schema version, and generation identifier

Any domain that wants to deviate from this default must document the reason explicitly in its own domain TDD.

### 6.3 Generations And Recovery

Protected domains use deterministic generation handling modeled after the future Contacts direction.

Minimum generation set:

- `current`
- `previous`
- `pending`

Write sequence:

1. mutate unlocked in-memory model
2. serialize canonical plaintext payload
3. encrypt into a fresh `pending` envelope
4. write `pending`
5. read back and validate `pending`
6. promote `current` to `previous`
7. promote `pending` to `current`
8. clean up stale artifacts only after successful promotion

Startup recovery sequence:

1. inspect available generations
2. after authorization, attempt to open candidates using the local domain master key
3. keep only structurally valid, decryptable generations
4. select the highest valid generation as authoritative
5. retain the next-highest valid generation as `previous` when present
6. enter `recoveryNeeded` if no readable authoritative generation exists

The framework must never silently create a new empty domain because the prior local state is unreadable.

The generation model in v1 provides crash consistency only. It does **not** provide freshness or anti-rollback guarantees.

### 6.4 Domain Master Key Persistence Model

The v1 persistence model for each protected app-data domain is:

- the domain payload generations are stored as encrypted envelopes on disk
- the `Domain Master Key` is not stored in plaintext on disk
- a domain unlock secret is persisted behind `LAPersistedRight`
- the `Domain Master Key` is persisted in a protected form that can only be reopened after the unlock secret is released by the system gate

The protected form of the `Domain Master Key` must satisfy these lifecycle rules:

- creation is atomic with first successful protected-domain initialization
- updates must not leave a window where both the old readable form and the new readable form are lost
- deletion must remove both the protected key material and the persisted right / secret association for that domain
- recovery must distinguish between:
  - unreadable payload generations
  - unreadable protected master-key state
  - unreadable or missing persisted-right-protected unlock secret

The v1 docs do not permit multiple equally valid persistence shapes for the master key. Any implementation must use one documented protected-form model and apply the same model consistently across startup, relock, deletion, migration, and recovery.

### 6.5 Bootstrap Metadata

Bootstrap metadata may exist beside encrypted generations, but it must remain minimal.

In v1, bootstrap metadata is file-side metadata stored beside encrypted generations. It is not stored in Keychain.

Bootstrap metadata must not become a plaintext shadow database.

Recommended bootstrap contents:

- domain existence
- schema version
- expected current generation identifier
- coarse recovery flag or reason code

Bootstrap metadata is a cold-start and recovery routing hint, not a secret-bearing store.

Bootstrap metadata should still receive explicit platform-appropriate local static protection even though it is not part of the encrypted payload.

### 6.6 File-Protection Policy

Protected domain files must use explicit platform-appropriate local static protection instead of relying on defaults.

#### iOS / iPadOS / visionOS

Required policy:

- protected domain files in app-owned storage use `complete` file protection
- bootstrap metadata files also use explicit `complete` file protection
- temporary protected-domain scratch files must be created with explicit file protection at creation time

The implementation must not rely on default `completeUntilFirstUserAuthentication` behavior for protected app-data files.

#### macOS

Required policy:

- protected-domain files must live inside the app's sandbox/container `Application Support` area
- the implementation must use the strongest platform-supported local static protection it can enforce for app-owned files
- the documentation must not claim identical iOS-style data-protection semantics on macOS unless a later implementation and platform review explicitly prove them

The macOS guarantee is stated in terms of container confinement plus platform-supported local static protection, not as a claim of identical iOS-style data-protection classes.

For v1 review purposes, the concrete macOS contract is:

- protected-domain files live only in app-owned container storage
- bootstrap metadata lives only in the same app-owned container boundary
- no protected-domain payloads are stored in user-managed document locations by default
- review and testing verify containment, ownership, and absence of fallback to broader storage locations

This is the v1 acceptance floor. Stronger macOS protection claims require later explicit design and validation.

## 7. Key And Session Lifecycle

### 7.1 Domain Master Key Lifecycle

For each protected app-data domain:

1. generate random 256-bit `Domain Master Key`
2. generate a domain unlock secret and persist it behind `LAPersistedRight`
3. authorize the right before retrieving the unlock secret
4. use the authorized secret to unwrap or derive access to the domain master key
5. zeroize plaintext secret and master-key buffers after persistence or relock as appropriate

The primary v1 contract is that the system must not release the unlock secret before authorization succeeds.

The v1 `Domain Master Key` lifecycle must also define:

- creation-time persistence of the protected master-key form
- stable re-open behavior across relock/relaunch
- explicit deletion semantics for both the protected master-key material and its right-protected unlock secret
- recovery behavior when either the persisted right or the protected master-key form becomes unreadable

### 7.2 Keychain Namespace Rule

If any domain-specific auxiliary Keychain material is used in support of the app-data domain, it must remain separate from current private-key storage names.

In v1, bootstrap metadata is not stored in Keychain. The primary authorization state for app-data unlock is the persisted right and its associated protected secret.

### 7.3 Session Unlock

`ProtectedDataSessionCoordinator` is responsible for domain unlock orchestration.

Required behavior:

- authorize the right after authenticated app launch/resume
- fetch the domain unlock secret only after authorization succeeds
- reuse the authorized app-data session
- avoid domain-specific redundant prompts during ordinary in-session use
- expose domain availability as locked/unlocked/recoveryNeeded

### 7.4 Relock

Relock must invalidate:

- in-memory domain unlock secret
- in-memory domain master keys
- decrypted domain payloads in memory
- plaintext serialization scratch buffers
- plaintext in-memory search or lookup indexes derived from protected domains

Sensitive buffers must be zeroized rather than only dereferenced.

Relock must also deauthorize the right for the current session.

## 8. New Framework Interfaces And Types

The new layer should live primarily in new files under:

```text
Sources/Security/ProtectedData/
```

Recommended initial files and responsibilities:

### `ProtectedDataDomain.swift`

Defines:

- `ProtectedDataDomainID`
- domain identity rules
- shared domain metadata such as version or namespace descriptors

### `ProtectedDomainEnvelope.swift`

Defines:

- `ProtectedDomainEnvelope`
- envelope header fields
- encode/decode rules
- associated-data composition rules

### `ProtectedDomainBootstrapStore.swift`

Owns:

- bootstrap metadata persistence
- domain presence markers
- generation routing metadata
- coarse recovery state markers

### `ProtectedDomainKeyManager.swift`

Owns:

- domain unlock secret creation and lifecycle
- domain master key lifecycle after secret retrieval
- system-gated unlock-secret retrieval backed by `LAPersistedRight`
- zeroization of transient key material

### `ProtectedDataSessionCoordinator.swift`

Owns:

- right authorization, session unlock, relock, and deauthorize state
- reuse of authenticated app-session context
- domain runtime visibility as locked / unlocked / recoveryNeeded

### `ProtectedDomainRecoveryCoordinator.swift`

Owns:

- pending/current/previous inspection
- generation validation
- authoritative generation selection
- deterministic recovery routing

### `ProtectedSettingsStore.swift`

First concrete adopter.

Purpose:

- validate the framework on a low-risk domain before Contacts
- reduce security-sensitive plaintext preferences over time
- prove the framework without touching private-key semantics

## 9. Integration Rules

### 9.1 Composition Rule

The framework must reuse:

- `SecureEnclaveManageable`
- `KeychainManageable`

by composition.

Do not refactor the private-key path merely to force code sharing.

### 9.2 Narrow Integration Seams

Expected initial integration points:

- `AppContainer` for wiring the new services
- `AppStartupCoordinator` for protected-domain startup recovery
- app lock / resume flow for relock and session reuse
- future Contacts domain owner

This still implies explicit startup-ordering work when a real protected domain is introduced. It is a narrow code ownership boundary, not a promise of zero initialization-flow changes.

### 9.3 Contacts Relationship

Contacts must later plug into this framework as a domain-specific consumer.

Contacts is **not** allowed to become a second independent security architecture if this framework exists.

In practical terms:

- Contacts owns person/key/tag/list semantics
- the protected app-data framework owns key lifecycle, envelope rules, generation recovery, and relock posture

## 10. Migration Rules

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

### 10.1 Persisted-State Classification Inventory

Before any real protected domain migration, implementation planning must maintain one reviewed inventory of currently persisted app-owned state.

Each item must be classified as:

- `early-readable`
- `protected-after-unlock`
- `remain plaintext with rationale`

At minimum this inventory must include the currently persisted `AppConfiguration` keys and auth/recovery flags already stored in `UserDefaults`.

Initial classification baseline:

| Item | Current location | v1 class | Notes |
|------|------------------|----------|-------|
| `authMode` | `UserDefaults` | `early-readable` | Read before app-data authorization |
| `gracePeriod` | `UserDefaults` | `early-readable` | Read before app-data authorization |
| `requireAuthOnLaunch` | `UserDefaults` | `early-readable` | Read before app-data authorization |
| `hasCompletedOnboarding` | `UserDefaults` | `early-readable` | Affects startup routing |
| `colorTheme` | `UserDefaults` | `early-readable` | Affects early scene presentation |
| `encryptToSelf` | `UserDefaults` | `protected-after-unlock` candidate | Not required for pre-auth bootstrap |
| `clipboardNotice` | `UserDefaults` | `protected-after-unlock` candidate | Not required for pre-auth bootstrap |
| `guidedTutorialCompletedVersion` | `UserDefaults` | `protected-after-unlock` candidate | Keep early-readable only if future startup flow proves it necessary |
| `rewrapInProgress` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `rewrapTargetMode` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `modifyExpiryInProgress` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `modifyExpiryFingerprint` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |

## 11. Domain Recovery Contracts

Each protected domain must declare a recovery contract explicitly.

Allowed v1 categories:

- `import-recoverable`
- `resettable-with-confirmation`
- `blocking`

No protected domain may silently reset on corruption or unreadable local state.

### 11.1 First-Domain Rule

`ProtectedSettingsStore`-style non-bootstrap settings/control state are `resettable-with-confirmation`.

Required behavior:

- entering `recoveryNeeded` must surface a destructive reset path
- reset must require explicit user confirmation
- reset must rebuild only that domain, not wipe unrelated protected domains

### 11.2 Contacts Rule

Contacts remains `import-recoverable`.

Required behavior:

- `recoveryNeeded` offers import-based recovery guidance
- Contacts must not become silently resettable merely because it reuses the shared framework

## 12. Validation Matrix

### 12.1 Unlock / Relock

- the right is authorized only after authenticated app session unlock
- the domain unlock secret is fetched only after authorization
- ordinary in-session access triggers no redundant prompts
- relock deauthorizes the right
- relock clears cached unlock secrets
- relock clears in-memory domain master keys
- relock clears decrypted payloads and derived indexes

### 12.2 Crash Recovery

- interrupted `pending` writes recover deterministically
- valid `current` and `previous` generations are selected consistently
- no unreadable local state silently resets to empty domain content
- `recoveryNeeded` is explicit and stable

### 12.3 File Protection

- iOS / iPadOS / visionOS protected-domain files are created with explicit `complete` file protection
- macOS protected-domain files live inside the app sandbox/container and use the strongest platform-supported local static protection defined by the implementation
- bootstrap metadata and temporary scratch files follow the same platform-specific protection policy as their host platform

### 12.4 Zeroization

- plaintext serialization buffers are zeroized after use
- cached unlock secrets are zeroized on relock
- unlocked master-key buffers are zeroized on relock
- decrypted domain snapshots or derived sensitive indexes are zeroized on relock

### 12.5 Failure Paths

- wrong auth does not unlock the domain
- pre-auth attempts must not fetch `LASecret`
- unreadable authorized domain state enters `recoveryNeeded`
- corrupted envelope hard-fails on authentication or structural validation
- interrupted migration does not destroy readable source state
- `ProtectedSettingsStore` reset requires explicit destructive confirmation
- Contacts recovery remains import-based
- anti-rollback is not implied by `current / previous / pending`

## 13. Implementation Readiness Expectations

This TDD is only acceptable if an implementer can proceed without making hidden architectural decisions.

At minimum, an implementer must be able to tell:

- that the current private-key domain should remain semantically unchanged
- that protected app data uses per-domain master keys
- that `LAPersistedRight` is the primary app-data authorization gate in v1
- that app-data domains are recoverable rather than private-key-style invalidating
- that file protection must be explicit
- that startup is split into pre-auth bootstrap and post-auth unlock phases
- that the generation model does not promise anti-rollback semantics
- that Contacts later depends on the framework rather than inventing its own vault base layer
