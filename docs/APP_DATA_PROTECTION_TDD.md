# App Data Protection Technical Design Document

> **Version:** Draft v1.0  
> **Status:** Draft future technical spec. This document does not describe current shipped behavior.  
> **Purpose:** Define the reusable technical substrate for protected app-owned persistent data outside the existing private-key domain.  
> **Audience:** Engineering, security review, QA, and AI coding tools.  
> **Companion document:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md)  
> **Detailed proposal documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)
> **Related documents:** [SECURITY](SECURITY.md) · [ARCHITECTURE](ARCHITECTURE.md) · [TESTING](TESTING.md) · [CONTACTS_TDD](CONTACTS_TDD.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Technical Scope

This document defines the reusable framework for protecting app-owned persistent data at rest while keeping the existing private-key architecture separate.

This TDD is the primary app-data technical source for:

- shared terminology for protected app-data domains
- architecture boundaries between app-data protection and the private-key domain
- shared session and relock behavior
- domain master key lifecycle
- protected-domain storage roles and recovery boundaries
- explicit file-protection posture for protected-domain files
- framework-level and domain-level recovery contracts

The detailed framework mechanics, migration sequencing, and validation checklists live in:

- [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md)
- [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md)
- [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)

This TDD does not redesign the current private-key system.

## 2. Non-Goals

This document does not authorize or require:

- rewrites of the current private-key wrapping path
- changes to Standard / High Security behavior
- changes to private-key auth-mode switching semantics
- merging app-data recovery and private-key recovery into one shared state machine
- a literal single global DMK design for all app-data domains
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
- persisted only in wrapped form under the shared app-data secret
- lazy-unwrapped on first domain access inside an already authorized app-data session
- remains independent from other domains for deletion, recovery, and future rekey behavior

### 3.4 Shared App-Data Secret

The shared app-data secret is the only system-gated secret released by the shared `LAPersistedRight`.

Properties:

- one shared right/secret pair covers all protected app-data domains in v1
- the secret acts as the session-level KEK for per-domain DMKs
- the secret may remain in memory for the active shared app-data session
- the secret must be zeroized on relock
- the secret does not replace per-domain DMKs

### 3.5 WrappedDomainMasterKeyRecord

The persisted representation of one domain DMK.

Required properties:

- one wrapped-DMK record per protected domain
- stored as stable domain metadata, not as part of ordinary payload generation rotation
- integrity-bound to at least the domain ID and wrap-version metadata
- created or replaced only through an explicit wrapped-DMK write transaction

### 3.6 ProtectedDataRegistry

The single bootstrap manifest that is authoritative for protected-domain membership and shared-resource lifecycle.

Required responsibilities:

- committed domain membership
- shared-resource lifecycle state
- optional pending mutation state
- recovery reconciliation ordering

### 3.7 SharedResourceLifecycleState

The durable lifecycle state of the shared app-data right/secret pair as committed in the registry.

Allowed values:

- `absent`: no committed protected domain currently requires the shared authorization resource
- `ready`: committed membership is non-empty and the shared right/secret must exist and be usable
- `cleanupPending`: committed membership is empty, but deletion of the shared right/secret is incomplete and must resume before the empty steady state is restored

Rules:

- this state records committed framework state only
- this state must not double as a mutation execution phase
- first-domain provisioning progress is recorded only in `pendingMutation`

### 3.8 PendingMutation

The single in-flight registry journal entry that describes uncommitted create/delete work.

Canonical shape:

- `createDomain(targetDomainID, CreateDomainPhase)`
- `deleteDomain(targetDomainID, DeleteDomainPhase)`

Rules:

- at most one pending mutation may exist at a time
- pending mutation records execution progress, not committed membership
- committed domain membership never uses transient `creating` or `deleting` states
- when there is no pending mutation, there is no execution phase

### 3.9 CreateDomainPhase

The execution phase for a pending `createDomain` mutation.

Allowed values:

- `journaled`
- `sharedResourceProvisioned`
- `artifactsStaged`
- `validated`
- `membershipCommitted`

`sharedResourceProvisioned` appears only when the mutation is staging the first committed protected domain.

### 3.10 DeleteDomainPhase

The execution phase for a pending `deleteDomain` mutation.

Allowed values:

- `journaled`
- `artifactsDeleted`
- `membershipRemoved`
- `sharedResourceCleanupStarted`

`sharedResourceCleanupStarted` appears only when deleting the last committed protected domain.

### 3.11 Framework Session State

The framework exposes explicit shared-session state:

- `sessionLocked`
- `sessionAuthorized`
- `frameworkRecoveryNeeded`
- `restartRequired`

`frameworkRecoveryNeeded` means the framework cannot safely determine or use the shared authorization resource and therefore must block all protected-domain access.

`restartRequired` means relock, zeroization, or deauthorization failed inside the current process. This state is fail-closed, blocks all future protected-domain access in that process, and clears only by process restart. It is not persisted into the registry.

### 3.12 Domain Runtime State

Each protected domain exposes explicit runtime state:

- `locked`: the domain is committed, but its DMK is not active in memory
- `unlocked`: the domain DMK is active in memory and the domain may be opened
- `recoveryNeeded`: local state exists, but no readable authoritative domain state can be opened with the local wrapped-DMK or payload generations

Protected domains must never silently substitute an empty state for `locked` or `recoveryNeeded`.

### 3.13 Bootstrap Metadata

Minimal non-secret metadata stored outside encrypted domain payloads so cold start and deterministic recovery remain possible.

Allowed examples:

- registry version
- committed domain membership
- shared-resource lifecycle state
- pending mutation kind and phase
- generation identifiers
- wrapped-DMK record version
- coarse recovery state flags

Disallowed examples:

- decrypted domain content
- relationship graph information
- user text, notes, tags, recipient sets, or meaningful business data
- plaintext caches or search indexes

## 4. Design Principles

The framework must satisfy these principles:

- offline-only operation
- composition over invasive refactor of the private-key domain
- per-domain isolation with shared infrastructure
- deterministic crash recovery
- registry-first recovery classification from explicit consistency rules
- no silent reset to empty state
- explicit session unlock and relock behavior
- fail-closed relock that blocks the current process on cleanup failure
- system-enforced authorization before the app receives the shared app-data secret
- explicit zeroization expectations for sensitive in-memory buffers
- explicit file-protection policy instead of relying on platform defaults

## 5. Core Design Decisions

### 5.1 Per-Domain Master Keys Under One Shared Gate

Each protected app-data domain owns its own `Domain Master Key`, but all domains share one system-gated app-data right and one shared app-data secret.

This is the canonical design.

Rationale:

- aligns with current Contacts direction
- limits blast radius
- allows independent migration, export, import, and recovery behavior per domain
- avoids treating every app-owned state transition as a single all-or-nothing vault event
- avoids repeated authorization prompts inside one active app-data session

### 5.2 Device-Bound Wrapping

The current private-key design uses Secure Enclave indirect wrapping because OpenPGP private keys are not directly managed by the Secure Enclave.

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
- one successful authorization covers all protected app-data domains in the current session
- source-device authorization state must not be exported as part of portable recovery

### 5.3 App-Data Access-Control Contract

`ProtectedDataSessionCoordinator` owns the shared app-data authorization resource, while `ProtectedDomainKeyManager` owns per-domain DMK lifecycle under that gate.

This policy is a normative requirement, not an implementation detail left for later.

Required rules:

- app-data domains use one shared `LAPersistedRight` as the primary app-data authorization gate in v1
- the shared app-data right uses `LAAuthenticationRequirement.default`
- app-data authorization must not call `AuthenticationMode.createAccessControl()`
- app-data authorization must not call `AuthenticationManager.createAccessControl(for:)`
- app-data authorization must not derive from the private-key authentication mode
- app-data domains must not inherit current `Standard` / `High Security` semantics
- app-data domains must not inherit future `Special Security Mode` or `biometryCurrentSet` semantics
- per-domain authorization-policy variation is out of scope in v1
- per-domain right authorization is out of scope in v1
- protected app-data domains must never rewrap merely because private-key auth mode changes
- the system must not return the shared app-data secret before right authorization succeeds

The purpose of this contract is to prevent the new layer from attaching itself to the private-key access-control source of truth.

### 5.4 ProtectedDataRegistry Is The Only Membership Authority

`ProtectedDataRegistry` is the single authoritative source for:

- committed protected-domain membership
- shared-resource lifecycle state
- optional pending mutation state
- recovery reconciliation ordering

Normal lifecycle rules:

- committed domains may be only `active` or domain-scoped `recoveryNeeded`
- uncommitted create/delete work is represented only by `pendingMutation`
- shared-resource lifecycle state may be only `absent`, `ready`, or `cleanupPending`
- `cleanupPending` is valid only when committed membership is empty
- shared-resource lifecycle state must not double as mutation execution phase
- orphaned directories, bootstrap metadata, or wrapped-DMK artifacts never implicitly become members
- the shared right and shared secret must exist whenever committed membership is non-empty and shared-resource lifecycle state is `ready`
- the shared right and shared secret may be deleted only after committed membership becomes empty and the registry has committed `cleanupPending`

Recovery rules:

- recovery reads registry first and validates registry consistency before consulting evidence
- on-disk artifacts are evidence for repair, quarantine, or cleanup
- no implementation may infer "last domain removed" from filesystem state alone
- any registry row that violates the documented consistency invariants enters `frameworkRecoveryNeeded`

The detailed registry manifest, invariants, transaction rules, and consistency matrix live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.1-2.6.

### 5.5 AppSessionOrchestrator And ProtectedDataSessionCoordinator

The target architecture uses two layers:

- `AppSessionOrchestrator`
- `ProtectedDataSessionCoordinator`

`AppSessionOrchestrator` is the app-wide session owner.

Required responsibilities:

- grace-window policy ownership
- launch/resume privacy-auth sequencing
- app lock / relock initiation
- scene lifecycle intake
- deciding when protected-domain access is allowed to proceed

`ProtectedDataSessionCoordinator` is the app-data subsystem coordinator under that orchestrator.

Required responsibilities:

- strong reference to the shared `LAPersistedRight`
- shared app-data secret lifetime in memory
- shared right authorize/deauthorize
- framework session state exposure
- relock orchestration
- relock-time zeroization of the shared secret and all unwrapped DMKs
- fail-closed blocking through `restartRequired` when relock cannot complete safely

`ProtectedDataSessionCoordinator` is therefore not a second grace owner and not an app-wide UX owner.

### 5.6 Session-Unlocked Access Model

Protected app-data domains unlock for the authenticated app session rather than per operation.

Canonical behavior:

- launch/resume enters `AppSessionOrchestrator`
- if app session is not active, the orchestrator completes app-level privacy unlock first
- `first real protected-domain access` means the first route in the current app session that actually needs protected-domain content, not process launch by itself
- on that first real protected-domain access, the orchestrator asks `ProtectedDataSessionCoordinator` to authorize the shared right
- if cold start or resume immediately continues into a route that needs protected-domain content while the shared app-data session is inactive, that same orchestrated flow may authorize the shared right and activate the shared app-data session there
- after shared authorization succeeds, the requested domain DMK may lazy-unlock
- launch/resume authentication alone does not imply that the shared app-data session is already active
- ordinary in-session reads and writes reuse the active shared app-data session
- second or third domains in that same session do not trigger another authorization prompt
- authorization survives background/inactive transitions while the app remains inside the active grace window
- relock occurs on explicit app lock, grace-period expiry, session loss, or app exit
- relock deauthorizes the shared right and clears the shared secret plus every unwrapped DMK from memory
- if relock cannot complete safely, the current process enters `restartRequired` and may not unlock protected domains again until restart

This model intentionally differs from the private-key domain.

Repeated-prompt avoidance is a required design goal. The v1 proposal must not rely on undocumented prompt coalescing between different authorization systems. Instead, the proposal treats the orchestrator-driven shared right authorization as the only normative app-data unlock contract, and the user-visible launch/resume flow should remain one understandable unlock path even when its first protected-domain access occurs inside that same orchestrated sequence.

### 5.7 Recoverable App-Data Semantics

Protected app-data domains are recoverable domains even if future private-key behavior becomes stricter under `Special Security Mode`.

Required rule:

- app-data domains must not inherit private-key-style biometric re-enrollment invalidation semantics

Stated differently:

- future private-key protection may use stronger, loss-prone semantics
- protected app-data domains must continue to use recoverable semantics
- app-data access is governed by the authenticated session and local recoverability rules, not by private-key loss semantics

### 5.8 Runtime Policy Separation

The framework separates:

- system authorization of the shared app-data secret
- app-wide session orchestration owned by `AppSessionOrchestrator`
- per-domain DMK unwrap and payload access after shared authorization

This separation is required so:

- protected app-data domains do not need rewrapping when private-key auth modes change
- the system, not only application code, prevents pre-auth access to the shared app-data secret
- one owner controls grace-window and launch/resume sequencing
- per-domain unlock remains lazy and isolated

### 5.9 Bootstrap-Critical Settings Whitelist

The following settings are bootstrap-critical in v1 because current startup or pre-unlock behavior depends on them before protected domains unlock:

- `authMode`
- `gracePeriod`
- `requireAuthOnLaunch`
- `hasCompletedOnboarding`
- `colorTheme`

Rules:

- these keys remain in the early-readable layer in v1
- the first `ProtectedSettingsStore` adopter must not migrate them
- protected settings must not rely on a shadow copy to recreate early boot behavior
- any future migration of a bootstrap-critical setting requires a separately documented two-phase startup design

The detailed rollout and inventory handling for these settings live in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) Sections 2.3, 3.1, and 4.

### 5.10 Deterministic Registry Recovery Model

Framework recovery begins from a registry row, not from filesystem inference.

Required rules:

- shared-resource lifecycle state and pending mutation phase are independent inputs
- startup recovery must first validate registry schema plus documented consistency invariants
- a valid registry row must classify to exactly one recovery disposition
- a row that cannot be classified by the documented matrix enters `frameworkRecoveryNeeded`

Allowed framework recovery dispositions:

- `resumeSteadyState`
- `continuePendingMutation`
- `frameworkRecoveryNeeded`

`cleanupOnly` is not a standalone framework recovery disposition. It is the named post-classification orphan shared-resource cleanup action that may run only under the empty steady-state row (`0 / absent / none / n/a`) before `resumeSteadyState` is returned.

The detailed matrix and evidence ordering rules live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.2-2.6.

### 5.11 Recovery Evidence Ordering

Recovery follows a fixed ordering:

1. read `ProtectedDataRegistry`
2. validate schema and consistency invariants
3. use the classified registry row to decide which external evidence is allowed to be consulted
4. inspect only that allowed evidence
5. produce one recovery disposition

Evidence may:

- authorize post-classification `cleanupOnly` under the empty steady-state row without changing row classification or final disposition
- prove a pending mutation advanced far enough that recovery should continue it

Evidence must not:

- change the classified registry row
- create committed membership
- substitute for a committed shared-resource promise
- turn an uncommitted domain into a committed member

The operational details live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 2.6.

### 5.12 Startup Authentication Boundary

Protected app-data domains must follow a two-phase startup model.

#### Pre-Auth Bootstrap Phase

Before app-data authorization succeeds, the app may:

- read bootstrap-critical settings
- read `ProtectedDataRegistry`
- read file-side per-domain bootstrap metadata
- determine whether protected domains exist and require later unlock

Before app-data authorization succeeds, the app must not:

- fetch `LASecret`
- authorize the shared app-data right implicitly from a repository/service initializer or getter
- unwrap any domain DMK
- attempt to open protected-domain generations
- classify final framework or domain state from protected-domain contents alone

#### Post-Auth Unlock Phase

After app-data authorization succeeds, the app may:

- continue the orchestrated launch/resume flow into shared-right authorization when the initial route immediately requires protected-domain content
- fetch the shared app-data secret
- lazy-unlock the requested domain DMK
- open `current / previous / pending` for that domain
- classify final framework and domain state

This is a required implementation boundary, not a best-effort guideline.

The current app startup path already performs cold-start loading and recovery work. Future real protected domains must therefore treat this two-phase model as an explicit startup-architecture migration, not as a mere local refactor inside one new service. The current owner split that this migration must absorb is documented in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) Section 3.4.

The rollout sequencing details live in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) Section 3.1.

## 6. Storage Model

### 6.1 ProtectedData Root Location

Protected app-data storage should live under app-owned `Application Support` storage in a dedicated subtree such as:

```text
Application Support/ProtectedData/
```

The subtree contains:

- the global `ProtectedDataRegistry`
- one directory per protected domain

Protected-domain payloads are app-private and are not treated as user-managed document exports.

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

### 6.3 Generations And Domain Recovery

Protected domains use a `current / previous / pending` generation model to preserve deterministic crash consistency and explicit domain recovery behavior.

This section establishes the high-level guarantees:

- writes validate a new generation before promotion
- recovery selects an authoritative readable generation after authorization
- unreadable local state must lead to domain-scoped `recoveryNeeded`, not a silent reset
- the generation model does not imply anti-rollback or freshness guarantees in v1

The detailed write sequence, promotion order, and domain recovery flow live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 3.1.

### 6.4 ProtectedDataRegistry Manifest

`ProtectedDataRegistry` is a plaintext bootstrap artifact with explicit local file protection.

This TDD keeps the normative roles:

- the registry is authoritative for committed domain membership and shared-resource lifecycle
- registry shape must support committed membership, shared-resource state, and optional `pendingMutation`
- recovery begins from the registry row before filesystem evidence is consulted
- rows that violate the documented consistency rules enter `frameworkRecoveryNeeded`

The detailed manifest fields, invariants, transaction rules, consistency matrix, and evidence ordering live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.1-2.6.

### 6.5 Wrapped-DMK Persistence Model

The v1 persistence model for each protected app-data domain is:

- domain payload generations are stored as encrypted envelopes on disk
- the DMK is not stored in plaintext on disk
- one shared app-data secret is persisted behind one shared `LAPersistedRight`
- each domain DMK is persisted only as a `WrappedDomainMasterKeyRecord`
- there is no v1 model where each domain owns its own independent right
- there is no v1 single global DMK for all app-data domains
- the shared secret is the only system-gated secret released by `LAPersistedRight`

Required `WrappedDomainMasterKeyRecord` properties:

- explicit wrap format/version
- domain ID
- nonce
- authenticated ciphertext
- authentication tag
- associated data that includes at minimum domain ID and wrap-version metadata

Wrapped-DMK persistence remains a stable, non-rotating part of domain metadata unless a later design explicitly introduces rekey. The detailed staged-write transaction and lifecycle rules live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 3.2.

### 6.6 Bootstrap Metadata

Per-domain bootstrap metadata may exist beside encrypted generations, but it must remain minimal.

In v1, per-domain bootstrap metadata is file-side metadata stored beside encrypted generations. It is not stored in Keychain.

Per-domain bootstrap metadata must not become a plaintext shadow database and must not override registry authority.

Recommended per-domain bootstrap contents:

- schema version
- expected current generation identifier
- coarse domain recovery flag or reason code
- wrapped-DMK record presence/version

Bootstrap metadata is a cold-start and recovery routing hint, not a secret-bearing store.

### 6.7 File-Protection Policy

Protected-domain files must use explicit platform-appropriate local static protection instead of relying on defaults.

#### iOS / iPadOS / visionOS

Required policy:

- protected-domain files in app-owned storage use `complete` file protection
- `ProtectedDataRegistry` also uses explicit `complete` file protection
- per-domain bootstrap metadata files also use explicit `complete` file protection
- temporary protected-domain scratch files must be created with explicit file protection at creation time

The implementation must not rely on default `completeUntilFirstUserAuthentication` behavior for protected app-data files.

#### macOS

Required policy:

- protected-domain files must live inside the app's sandbox/container `Application Support` area
- the implementation must use the strongest platform-supported local static protection it can enforce for app-owned files
- the documentation must not claim identical iOS-style data-protection semantics on macOS unless a later implementation and platform review explicitly prove them

The macOS guarantee is stated in terms of container confinement plus platform-supported local static protection, not as a claim of identical iOS-style data-protection classes.

For v1 review purposes, the concrete macOS contract is:

- registry and protected-domain files live only in app-owned container storage
- bootstrap metadata lives only in the same app-owned container boundary
- no protected-domain payloads are stored in user-managed document locations by default
- review and testing verify containment, ownership, and absence of fallback to broader storage locations

This is the v1 acceptance floor. Stronger macOS protection claims require later explicit design and validation.

## 7. Key And Session Lifecycle

### 7.1 Shared Authorization Resource Lifecycle

The shared app-data authorization resource lifecycle is governed by the registry:

- `absent`: no committed protected domain requires the shared authorization resource and shared-right authorization may not begin
- `ready`: committed membership is non-empty and the shared right/secret must exist and be usable before protected-domain access proceeds
- `cleanupPending`: committed membership is empty, but shared-resource cleanup must resume before the framework returns to the empty steady state

Required rules:

- first-domain provisioning may begin only after `createDomain(..., journaled)` is written to the registry
- shared-resource lifecycle state may become `ready` only in the same registry commit that first makes committed membership non-empty
- last-domain deletion may move shared-resource lifecycle state to `cleanupPending` only in the same registry commit that makes committed membership empty
- shared-resource lifecycle state may return to `absent` only after shared-resource cleanup succeeds and the pending delete mutation is ready to clear
- authorization of the shared right is permitted only while lifecycle state is `ready`
- the shared app-data secret may remain in memory only while the shared app-data session is active
- zeroization of the shared secret remains required on relock

The primary v1 contract is that the system must not release the shared app-data secret before authorization succeeds.

### 7.2 Domain Master Key Lifecycle

For each protected app-data domain:

1. generate a random 256-bit DMK
2. wrap that DMK with the shared app-data secret
3. persist the wrapped-DMK record
4. write initial domain state
5. commit domain membership in `ProtectedDataRegistry`
6. on later access, lazy-unwrap the DMK only after shared authorization succeeds
7. zeroize the plaintext DMK on relock

The v1 domain lifecycle must also define:

- creation-time persistence of wrapped-DMK state before domain membership commit
- stable re-open behavior across relock/relaunch
- explicit deletion semantics for domain files, wrapped-DMK state, and registry membership
- recovery behavior when either wrapped-DMK state or payload generations become unreadable

The detailed persistence mechanics live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.3-2.4 and 3.1-3.2.

### 7.3 Session Unlock

`AppSessionOrchestrator` is responsible for app-wide sequencing.

`ProtectedDataSessionCoordinator` is responsible for shared app-data session unlock.

Required behavior:

- only `AppSessionOrchestrator` may decide that protected-domain access can proceed
- only `ProtectedDataSessionCoordinator` may authorize the shared right
- the shared app-data secret is fetched only after authorization succeeds
- per-domain DMKs are lazy-unwrapped on first domain access
- the shared app-data session is reused for ordinary in-session access
- domain availability is exposed as framework state plus domain state, not as one merged state machine

### 7.4 Relock

Relock is fail-closed. It is not a best-effort cleanup path.

Relock must invalidate:

- in-memory shared app-data secret
- all in-memory unwrapped domain DMKs
- decrypted domain payloads in memory
- plaintext serialization scratch buffers
- plaintext in-memory search or lookup indexes derived from protected domains

Sensitive buffers must be zeroized rather than only dereferenced.

Relock executes in this order:

1. close new protected-domain access for the current process
2. invoke every registered `ProtectedDataRelockParticipant`
3. zeroize the shared app-data secret and all unwrapped domain DMKs
4. deauthorize the shared right for the current session

Participant fan-out is non-short-circuit. One participant failure does not permit skipping later participant cleanup or skipping shared-secret / DMK cleanup.

If any relock step fails, `ProtectedDataSessionCoordinator` must enter `restartRequired`.

In `restartRequired`:

- all protected-domain access remains blocked for the current process
- no new shared-right authorization may begin
- no in-process retry or recovery path exists
- recovery is limited to a fresh app launch and normal startup recovery
- the state is runtime-only and must not be persisted into the registry

Relock failure diagnostics must remain generic and must not expose domain IDs, paths, membership counts, or other sensitive recovery details.

App-data relock does not occur merely because the app entered background or inactive state while the current grace window remains valid.

## 8. New Framework Interfaces And Types

The initial framework files, type responsibilities, and directory layout are part of the detailed framework specification rather than the core architecture contract.

This TDD keeps the ownership boundaries in Sections 5, 7, and 9. The concrete file/type breakdown for the first implementation lives in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 4.

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
- app lock / resume flow through `AppSessionOrchestrator`
- future Contacts domain owner

This still implies explicit startup-ordering work when a real protected domain is introduced. It is a narrow code ownership boundary, not a promise of zero initialization-flow changes.

The expanded interface/file breakdown lives in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 4-5.

### 9.3 Contacts Relationship

Contacts must later plug into this framework as a domain-specific consumer.

Contacts is not allowed to become a second independent security architecture if this framework exists.

In practical terms:

- Contacts owns person/key/tag/list semantics
- the protected app-data framework owns registry authority, shared-session authority, wrapped-DMK lifecycle, envelope rules, generation recovery, and relock posture

Contacts-specific adoption behavior now lives directly in [CONTACTS_PRD](CONTACTS_PRD.md), [CONTACTS_TDD](CONTACTS_TDD.md), and the rollout sequencing sections of [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md).

## 10. Migration Rules

Migration from current plaintext or non-uniform state into protected domains must preserve readable source state, avoid silent reset behavior, and make unreadable converted state a recovery surface instead of a wipe.

This TDD keeps the cross-cutting rule set:

- preserve readable source state until the protected destination is confirmed valid
- never silently reset to empty state on conversion failure
- require explicit post-cutover cleanup rules
- keep `ProtectedSettingsStore` constrained to non-bootstrap settings/control state in the first-domain round

The phased rollout, startup adoption sequencing, inventory table, and first-domain detail live in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) Sections 2-5.

### 10.1 Persisted-State Classification Inventory

Implementation planning must maintain one reviewed inventory of currently persisted app-owned state in app-data migration scope, with each item tracked by target class and migration readiness and with reviewed private-key-domain exclusions called out explicitly.

The full inventory baseline and first-domain adoption rules live in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) Sections 4-5.

## 11. Recovery Contracts

### 11.1 Framework-Level Recovery

`frameworkRecoveryNeeded` is entered when the framework cannot safely determine or use the shared authorization resource.

Required triggers:

- missing or unreadable `ProtectedDataRegistry`
- registry rows that violate documented consistency invariants
- registry rows that cannot be classified by the documented consistency matrix
- committed membership that expects `ready`, but the shared persisted right is missing
- committed membership that expects `ready`, but shared-right-protected secret data is unreadable or missing
- a row already classified to the shared-resource cleanup path (`0 / cleanupPending / deleteDomain(..., membershipRemoved or sharedResourceCleanupStarted)`) remains indeterminate after its matrix-authorized cleanup evidence is inspected

This trigger does not apply to the empty steady-state row (`0 / absent / none / n/a`): that row may still run post-classification orphan `cleanupOnly`, but its final recovery disposition remains `resumeSteadyState`.

Required behavior:

- all protected domains are blocked
- no domain may independently bypass framework recovery
- recovery must reconcile from registry first, then only from matrix-authorized evidence

`restartRequired` is not a persisted framework-recovery state. It is a current-process fatal runtime stop entered only when relock cannot complete safely.

### 11.2 Domain-Level Recovery

Each protected domain must declare a recovery contract explicitly.

Allowed v1 categories:

- `import-recoverable`
- `resettable-with-confirmation`
- `blocking`

No protected domain may silently reset on corruption or unreadable local state.

Domain-scoped `recoveryNeeded` is entered when:

- wrapped-DMK state is unreadable
- no readable authoritative payload generation exists
- domain-specific recovery policy requires blocked access

Framework-level and domain-level recovery must not be conflated.

### 11.3 First-Domain Rule

`ProtectedSettingsStore`-style non-bootstrap settings/control state are `resettable-with-confirmation`.

Required behavior:

- entering domain-scoped `recoveryNeeded` must surface a destructive reset path
- reset must require explicit user confirmation
- reset must rebuild only that domain, not wipe unrelated protected domains

### 11.4 Contacts Rule

Contacts remains `import-recoverable`.

Required behavior:

- domain-scoped `recoveryNeeded` offers import-based recovery guidance
- Contacts must not become silently resettable merely because it reuses the shared framework
- Contacts does not become the owner of shared-session or registry authority

## 12. Validation Matrix

The app-data proposal must still be validated across registry authority, unlock/relock behavior, crash recovery, file protection, zeroization, and failure paths.

This TDD keeps validation as a required outcome, but the detailed matrix and checklist now live in [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) Section 2.

## 13. Implementation Readiness Expectations

This proposal is only acceptable if an implementer can proceed without making hidden architectural decisions.

The detailed readiness criteria, review questions, and document-level acceptance checks now live in [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) Sections 3-5.
