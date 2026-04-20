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
- wrapped using device-bound local protection
- re-established independently on import or recovery flows when needed

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

Domain master keys use device-bound local protection built from the existing Secure Enclave and Keychain primitives.

Implementation rule:

- reuse `SecureEnclaveManageable` and `KeychainManageable` by composition
- define app-data-domain-specific wrapping namespaces and HKDF info strings
- do not reuse private-key HKDF prefixes or Keychain naming directly

Expected properties:

- local-only
- `ThisDeviceOnly`
- wrapped master key never stored in plaintext
- source-device wrapping material never exported as part of portable recovery

### 5.3 App-Data Wrapping Access-Control Contract

`ProtectedDomainKeyManager` owns a dedicated app-data wrapping policy.

This policy is a normative requirement, not an implementation detail left for later.

Required rules:

- app-data wrapping keys must **not** call `AuthenticationMode.createAccessControl()`
- app-data wrapping keys must **not** call `AuthenticationManager.createAccessControl(for:)`
- app-data wrapping keys must **not** derive `SecAccessControl` from the private-key authentication mode
- app-data wrapping keys must **not** inherit current `Standard` / `High Security` semantics
- app-data wrapping keys must **not** inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- app-data wrapping in v1 provides device binding only
- runtime authorization for ordinary app-data access is handled solely by `ProtectedDataSessionCoordinator`
- protected app-data domains must never rewrap merely because private-key auth mode changes

The purpose of this contract is to prevent the new layer from attaching itself to the private-key access-control source of truth.

### 5.4 Session-Unlocked Access Model

Protected app-data domains unlock for the authenticated app session rather than per operation.

Canonical behavior:

- domain unlock occurs after successful app launch or resume authentication
- ordinary in-session reads and writes reuse the unlocked session
- relock occurs on app lock, grace-period expiry, session loss, or app exit

This model intentionally differs from the private-key domain.

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

- **device-bound static protection** of the domain master key
- **runtime session authorization** for ordinary access

This separation is required so:

- protected app-data domains do not need rewrapping when private-key auth modes change
- the app can enforce the user's selected runtime lock policy without coupling domain storage semantics to private-key rewrap cycles

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
2. attempt to open candidates using the local domain master key
3. keep only structurally valid, decryptable generations
4. select the highest valid generation as authoritative
5. retain the next-highest valid generation as `previous` when present
6. enter `recoveryNeeded` if no readable authoritative generation exists

The framework must never silently create a new empty domain because the prior local state is unreadable.

### 6.4 Bootstrap Metadata

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

### 6.5 File-Protection Policy

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

## 7. Key And Session Lifecycle

### 7.1 Domain Master Key Lifecycle

For each protected app-data domain:

1. generate random 256-bit `Domain Master Key`
2. generate or reuse a domain-specific device-bound wrapping key using the dedicated app-data wrapping policy
3. wrap the master key into a domain-specific wrapped bundle
4. store wrapped bundle in a domain-specific Keychain namespace
5. zeroize plaintext master-key creation buffers after successful persistence

Domain-specific namespaces and HKDF info strings must not collide with private-key wrapping identifiers.

The app-data wrapping policy must remain independent from private-key auth-mode access-control generation.

### 7.2 Keychain Namespace Rule

Each protected app-data domain must define its own namespace, for example:

- `com.cypherair.protected-data.v1.<domain>.se-key`
- `com.cypherair.protected-data.v1.<domain>.salt`
- `com.cypherair.protected-data.v1.<domain>.sealed-master-key`

This namespace is separate from current private-key storage names.

In v1, bootstrap metadata is not stored in Keychain. Keychain stores only the wrapped domain master-key bundle and related key material.

### 7.3 Session Unlock

`ProtectedDataSessionCoordinator` is responsible for domain unlock orchestration.

Required behavior:

- reuse the authenticated app launch/resume session
- avoid domain-specific redundant prompts during ordinary in-session use
- expose domain availability as locked/unlocked/recoveryNeeded

### 7.4 Relock

Relock must invalidate:

- in-memory domain master keys
- decrypted domain payloads in memory
- plaintext serialization scratch buffers
- plaintext in-memory search or lookup indexes derived from protected domains

Sensitive buffers must be zeroized rather than only dereferenced.

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

- domain master key creation
- domain master key wrapping and unwrapping
- domain-specific Keychain namespace handling
- zeroization of transient key material

### `ProtectedDataSessionCoordinator.swift`

Owns:

- session unlock and relock state
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

## 11. Validation Matrix

### 11.1 Unlock / Relock

- domain unlock occurs only after authenticated app session unlock
- ordinary in-session access triggers no redundant prompts
- relock clears in-memory domain master keys
- relock clears decrypted payloads and derived indexes

### 11.2 Crash Recovery

- interrupted `pending` writes recover deterministically
- valid `current` and `previous` generations are selected consistently
- no unreadable local state silently resets to empty domain content
- `recoveryNeeded` is explicit and stable

### 11.3 File Protection

- iOS / iPadOS / visionOS protected-domain files are created with explicit `complete` file protection
- macOS protected-domain files live inside the app sandbox/container and use the strongest platform-supported local static protection defined by the implementation
- bootstrap metadata and temporary scratch files follow the same platform-specific protection policy as their host platform

### 11.4 Zeroization

- plaintext serialization buffers are zeroized after use
- unlocked master-key buffers are zeroized on relock
- decrypted domain snapshots or derived sensitive indexes are zeroized on relock

### 11.5 Failure Paths

- wrong auth does not unlock the domain
- unreadable wrapped master key enters `recoveryNeeded`
- corrupted envelope hard-fails on authentication or structural validation
- interrupted migration does not destroy readable source state

## 12. Implementation Readiness Expectations

This TDD is only acceptable if an implementer can proceed without making hidden architectural decisions.

At minimum, an implementer must be able to tell:

- that the current private-key domain should remain semantically unchanged
- that protected app data uses per-domain master keys
- that app-data domains are recoverable rather than private-key-style invalidating
- that file protection must be explicit
- that Contacts later depends on the framework rather than inventing its own vault base layer
