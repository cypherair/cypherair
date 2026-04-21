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
- persisted in a protected form wrapped by the shared app-data secret
- lazy-unwrapped on first domain access inside an already authorized app-data session
- remains independent from other domain DMKs for envelope, deletion, recovery, and future rekey behavior

### 3.4 Shared App-Data Secret

The shared app-data secret is the only system-gated secret released by the shared `LAPersistedRight`.

Properties:

- one shared app-data right/secret pair covers all app-data domains in v1
- the secret acts as the session KEK for per-domain DMKs
- the secret may remain in memory for the authorized app-data session
- the secret must be zeroized on relock
- the secret does not replace per-domain DMKs

### 3.5 Bootstrap Metadata

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

### 3.6 Locked / Unlocked / RecoveryNeeded

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
- keeps domain boundaries at the DMK/envelope/recovery layer even when authorization is shared

### 5.2 Device-Bound Wrapping

The current private-key design uses Secure Enclave indirect wrapping because OpenPGP private keys aren't directly managed by the Secure Enclave.

Protected app-data domains use a different primary model in v1:

- encrypted domain payloads remain app-managed on disk
- one shared app-data secret is gated by one shared `LAPersistedRight`
- Apple documents `LAPersistedRight` as being backed by a unique key in the Secure Enclave
- per-domain DMKs remain distinct and are wrapped by the shared app-data secret

This means the v1 app-data proposal still relies on Secure Enclave-backed system authorization, but it does so through Apple's higher-level LocalAuthentication right model rather than through custom Secure Enclave wrapping as the primary gate.

Implementation rule:

- treat one shared `LAPersistedRight` / `LASecret` pair as the primary authorization gate for app-data unlock
- do not promise custom SE self-ECDH wrapping as the primary app-data design in v1
- reuse lower-level primitives only where they support the domain model without replacing the primary system gate

Expected properties:

- local-only
- system-gated access to the shared app-data secret
- app code must not receive that secret before authorization succeeds
- one successful authorization covers all app-data domains in the current session
- source-device authorization state must not be exported as part of portable recovery

### 5.3 App-Data Wrapping Access-Control Contract

`ProtectedDataSessionCoordinator` owns the lifecycle of the shared app-data authorization gate, while `ProtectedDomainKeyManager` owns per-domain DMK lifecycle under that gate.

This policy is a normative requirement, not an implementation detail left for later.

Required rules:

- app-data domains use one shared `LAPersistedRight` as the primary app-data authorization gate in v1
- the shared app-data right uses `LAAuthenticationRequirement.default`
- app-data authorization must **not** call `AuthenticationMode.createAccessControl()`
- app-data authorization must **not** call `AuthenticationManager.createAccessControl(for:)`
- app-data authorization must **not** derive from the private-key authentication mode
- app-data domains must **not** inherit current `Standard` / `High Security` semantics
- app-data domains must **not** inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- per-domain authorization-policy variation is out of scope in v1
- per-domain right authorization is out of scope in v1
- protected app-data domains must never rewrap merely because private-key auth mode changes
- the system must not return the shared app-data secret before right authorization succeeds

The purpose of this contract is to prevent the new layer from attaching itself to the private-key access-control source of truth.

### 5.4 Session-Unlocked Access Model

Protected app-data domains unlock for the authenticated app session rather than per operation.

Canonical behavior:

- `ProtectedDataSessionCoordinator` owns the authoritative app-data unlock boundary
- that boundary is the shared `LAPersistedRight.authorize(...)`
- the shared app-data secret is fetched only after authorization succeeds
- per-domain DMKs are lazy-unwrapped on first domain access
- already-opened domain DMKs remain in memory until relock
- unopened domains do not preload their DMKs
- ordinary in-session reads and writes reuse the authorized session
- authorization survives background / inactive transitions while the app remains inside the current grace window
- relock occurs on explicit app lock, grace-period expiry, session loss, or app exit
- relock must also deauthorize the shared right and clear any cached shared secret and any unwrapped domain DMKs from memory

This model intentionally differs from the private-key domain.

The authoritative v1 orchestration model is:

- `ProtectedDataSessionCoordinator` authorizes the shared app-data right and owns app-data session reuse
- existing `AuthenticationManager` / `AuthenticationMode` launch-resume auth is not the normative app-data authorization source
- if current shipped app-shell privacy auth remains in place, it is treated as separate UX and not as the required gate for future app-data unlock semantics
- app-data domains do not bypass the shared right by treating prior app-auth alone as sufficient to release the shared app-data secret
- opening a second or third app-data domain inside the same app-data session must not require another authorization prompt

Repeated-prompt avoidance is a required design goal. The v1 proposal must not rely on undocumented prompt coalescing between different authorization systems. Instead, the proposal treats `ProtectedDataSessionCoordinator` and its right authorization as the only normative app-data unlock contract.

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

- **system authorization** of the shared app-data secret
- **runtime session reuse** plus lazy per-domain DMK unlock after that authorization

This separation is required so:

- protected app-data domains do not need rewrapping when private-key auth modes change
- the system, not only application code, prevents pre-auth access to the shared app-data secret
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
- authorize the shared app-data right implicitly from a repository/service initializer or getter
- unwrap any domain DMK
- attempt to open protected-domain generations
- classify final `locked / unlocked / recoveryNeeded` state from protected-domain contents

#### Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- fetch the shared app-data secret
- lazy-unlock each domain DMK on first access
- open `current / previous / pending` for domains that are accessed
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
- one shared app-data secret is persisted behind one shared `LAPersistedRight`
- each domain DMK is persisted in one protected form wrapped by that shared app-data secret
- there is no v1 model where each domain owns its own independent right
- there is no v1 single global DMK for all app-data domains
- the shared secret is the only system-gated secret released by `LAPersistedRight`

The canonical v1 lifecycle is:

- create: ensure the shared app-data right/secret exists, create the domain DMK, wrap it with the shared secret, then write initial domain state; if initialization fails, remove partial domain files and the wrapped DMK state, and remove the shared right only if it was created solely for this first domain
- steady-state updates: rewrite domain generations only; do not rotate the shared app-data secret or the domain DMK unless a later domain-specific design explicitly introduces rekey
- delete domain: remove domain generations, bootstrap metadata, and wrapped DMK state for that domain; do not remove the shared right unless the last protected domain is being removed
- recovery: distinguish between:
  - unreadable payload generations
  - unreadable wrapped domain DMK state
  - missing shared persisted right
  - unreadable or missing shared-right-protected secret data

The v1 docs do not permit multiple equally valid persistence shapes for the master key ladder. The shared-gate / per-domain-DMK model above is the single canonical v1 model and must be applied consistently across startup, relock, deletion, migration, and recovery.

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

The shared app-data session lifecycle is:

1. create one shared app-data `LAPersistedRight`
2. persist one shared app-data secret behind that right
3. authorize the shared right before retrieving `LASecret.rawData`
4. use the authorized shared secret as the KEK for per-domain DMKs
5. zeroize plaintext shared-secret buffers on relock

For each protected app-data domain:

1. generate random 256-bit `Domain Master Key`
2. wrap that DMK with the shared app-data secret
3. persist the wrapped DMK in the domain's protected metadata state
4. lazy-unwrap the DMK on first domain access after shared authorization succeeds
5. zeroize plaintext DMK buffers on relock or explicit domain eviction if later introduced

The primary v1 contract is that the system must not release the shared app-data secret before authorization succeeds.

The v1 `Domain Master Key` lifecycle must also define:

- creation-time persistence of the wrapped domain DMK
- stable re-open behavior across relock/relaunch
- explicit deletion semantics for domain files, wrapped DMK state, and the shared right when no protected domains remain
- recovery behavior when either the shared persisted right, the shared secret, or a wrapped domain DMK becomes unreadable

### 7.2 Keychain Namespace Rule

If any auxiliary Keychain material is used in support of the app-data domain, it must remain separate from current private-key storage names.

In v1, bootstrap metadata is not stored in Keychain. The primary authorization state for app-data unlock is the shared persisted right, and the only system-gated secret released by that right is the shared app-data secret.

### 7.3 Session Unlock

`ProtectedDataSessionCoordinator` is responsible for domain unlock orchestration.

Required behavior:

- authorize the shared right as the authoritative app-data unlock boundary
- fetch the shared app-data secret only after authorization succeeds
- reuse the authorized app-data session
- lazy-unlock domain DMKs on first domain access
- avoid domain-specific redundant prompts during ordinary in-session use
- expose domain availability as locked/unlocked/recoveryNeeded

### 7.4 Relock

Relock must invalidate:

- in-memory shared app-data secret
- all in-memory unwrapped domain DMKs
- decrypted domain payloads in memory
- plaintext serialization scratch buffers
- plaintext in-memory search or lookup indexes derived from protected domains

Sensitive buffers must be zeroized rather than only dereferenced.

Relock must also deauthorize the shared right for the current session.

App-data relock does **not** occur merely because the app entered background or inactive state while the current grace window remains valid.

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

- per-domain DMK creation and wrapped-DMK persistence
- lazy per-domain DMK unwrap under the shared app-data secret
- deletion and zeroization of per-domain key material
- zeroization of transient key material

### `ProtectedDataSessionCoordinator.swift`

Owns:

- shared right authorization, session unlock, relock, and deauthorize state
- shared app-data secret lifecycle
- reuse of authenticated app-session context
- domain runtime visibility as locked / unlocked / recoveryNeeded

### `ProtectedDomainRecoveryCoordinator.swift`

Owns:

- pending/current/previous inspection
- wrapped-DMK state validation
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
| `encryptToSelf` | `UserDefaults` | `protected-after-unlock` | Not required for pre-auth bootstrap |
| `clipboardNotice` | `UserDefaults` | `protected-after-unlock` | Not required for pre-auth bootstrap |
| `guidedTutorialCompletedVersion` | `UserDefaults` | `protected-after-unlock` | Not required for pre-auth bootstrap in the current proposal |
| `rewrapInProgress` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `rewrapTargetMode` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `modifyExpiryInProgress` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `modifyExpiryFingerprint` | `UserDefaults` | `remain plaintext with rationale` | Private-key recovery flag; stays outside app-data domain in v1 |
| `Documents/contacts/*.gpg` | App sandbox documents | `remain plaintext with rationale` | Existing Contacts storage stays outside this round until Contacts docs are revised |
| `Documents/contacts/contact-metadata.json` | App sandbox documents | `remain plaintext with rationale` | Existing Contacts metadata stays outside this round until Contacts docs are revised |
| `Documents/self-test/` | App sandbox documents | `remain plaintext with rationale` | Diagnostic output remains outside protected-domain scope in v1 |
| future protected-domain bootstrap metadata | App-owned bootstrap files | `early-readable` | Read before app-data authorization by design |

Proposed protected-data storage concepts for v1 design work:

| Concept | Proposed location | v1 class | Notes |
|---------|-------------------|----------|-------|
| shared app-data `LAPersistedRight` / secret | System-managed LocalAuthentication persistent store | `protected-after-unlock` | Shared gate for all app-data domains |
| per-domain wrapped DMK state | App-owned protected-domain metadata under each domain directory | `protected-after-unlock` | Lazy-unwrapped after shared app-data authorization |

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

- one shared `LAPersistedRight.authorize(...)` is the single normative app-data authorization boundary
- the shared app-data secret is fetched only after authorization
- a second or third app-data domain does not require another authorization prompt inside the active app-data session
- domain DMKs are lazy-unwrapped on first access
- ordinary in-session access triggers no redundant prompts
- relock deauthorizes the right
- relock clears cached unlock secrets
- relock clears all in-memory unwrapped domain DMKs
- relock clears decrypted payloads and derived indexes
- backgrounding within the active grace window does not deauthorize app-data access

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
