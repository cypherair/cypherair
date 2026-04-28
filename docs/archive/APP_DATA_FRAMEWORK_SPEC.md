# App Data Framework Specification

> **Status:** Archived historical AppData framework specification snapshot.
> **Archived on:** 2026-04-28.
> **Archival reason:** The reusable ProtectedData framework for Phase 1-6 has moved from proposal detail into current architecture, security, TDD, and testing documentation.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [APP_DATA_MIGRATION_GUIDE](../APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_ROADMAP_STATUS](../APP_DATA_ROADMAP_STATUS.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**

Original snapshot metadata follows.

> **Version:** Draft v1.0
> **Status:** Draft future implementation detail. This document does not describe current shipped behavior.
> **Purpose:** Define the concrete framework mechanics that implement the architecture and security constraints in the app-data protection TDD.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Primary authority:** [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) for architecture boundaries, security posture, and core design constraints.
> **Companion documents:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_MIGRATION_GUIDE](../APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)
> **Related documents:** [CONTACTS_TDD](../CONTACTS_TDD.md)

## 1. Scope And Precedence

This document exists to hold the detailed framework execution rules that would otherwise overload the main app-data protection TDD.

It specifies:

- registry manifest shape and registry-driven transaction behavior
- detailed generation write, promotion, and recovery flow
- wrapped-DMK persistence and staged-write requirements
- initial framework files, responsibilities, and integration seams

If this document ever conflicts with [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md), the TDD wins. This document refines the TDD; it does not redefine the architecture or security model.

## 2. Registry Execution Model

### 2.1 ProtectedDataRegistry Manifest

`ProtectedDataRegistry` is a plaintext bootstrap artifact with explicit local file protection.

Required manifest concepts:

- registry format version
- shared-resource record
  - shared root-secret Keychain identifier
  - `SharedResourceLifecycleState`
- committed domain membership map
  - `domainID`
  - committed domain state (`active` or `recoveryNeeded`)
  - domain directory location
  - wrapped-DMK record presence/version
  - domain recovery contract category
- optional `pendingMutation`
  - mutation ID
  - tagged union payload (`createDomain` or `deleteDomain`)
  - target domain
  - phase enum

The registry remains authoritative even when on-disk artifacts disagree.

### 2.2 Registry Consistency Invariants

The registry row must satisfy all of the following:

- if committed membership is empty and there is no pending delete cleanup, shared-resource lifecycle state is `absent`
- if committed membership is non-empty, shared-resource lifecycle state is `ready`
- `cleanupPending` appears only when committed membership is empty
- if `pendingMutation` is absent, no execution phase is present
- for `createDomain` phases before `membershipCommitted`, the target domain is absent from committed membership and shared-resource lifecycle state remains `absent`
- for `createDomain`, the target domain is absent from committed membership until phase `membershipCommitted`
- for `createDomain` phase `membershipCommitted`, the target domain is present in committed membership and shared-resource lifecycle state is `ready`
- for `deleteDomain`, the target domain remains present in committed membership until phase `membershipRemoved`
- for `deleteDomain` phase `membershipRemoved`, the target domain is absent from committed membership
- if `deleteDomain` phase is `membershipRemoved` or `sharedResourceCleanupStarted` and committed membership is empty, shared-resource lifecycle state is `cleanupPending`
- committed membership never stores transient `creating` or `deleting` values
- at most one `pendingMutation` may exist at a time

Any registry row that violates these invariants is classified as `frameworkRecoveryNeeded`.

### 2.3 Registry-Backed Create Transaction

Domain creation must follow this order:

1. read and lock `ProtectedDataRegistry`
2. write `pendingMutation = createDomain(targetDomainID, journaled)`
3. if the mutation stages the first committed protected domain, provision the shared root-secret Keychain record and advance the phase to `sharedResourceProvisioned`
4. create the domain directory, staged wrapped-DMK state, and initial payload generation, then advance the phase to `artifactsStaged`
5. validate wrapped-DMK state and initial payload readability, then advance the phase to `validated`
6. commit the target domain into membership and, when this is the first committed domain, commit shared-resource lifecycle state to `ready` in the same registry write; advance the phase to `membershipCommitted`
7. clear `pendingMutation`

If the create operation is not staging the first committed domain, step 3 is skipped and shared-resource lifecycle state remains `ready`.

The target domain is not a committed member until step 6 succeeds.

### 2.4 Registry-Backed Delete Transaction

Domain deletion must follow this order:

1. read and lock `ProtectedDataRegistry`
2. write `pendingMutation = deleteDomain(targetDomainID, journaled)`
3. delete the target domain payloads, per-domain bootstrap metadata, and wrapped-DMK state, then advance the phase to `artifactsDeleted`
4. remove the target domain from committed membership and, when that removal empties membership, commit shared-resource lifecycle state to `cleanupPending` in the same registry write; advance the phase to `membershipRemoved`
5. if shared-resource lifecycle state is `cleanupPending`, begin shared-resource cleanup and advance the phase to `sharedResourceCleanupStarted`
6. if shared-resource cleanup was required, commit shared-resource lifecycle state back to `absent` and clear `pendingMutation` in the same registry write
7. if shared-resource cleanup was not required, clear `pendingMutation`

If committed membership remains non-empty after step 4, steps 5 and 6 are skipped and shared-resource lifecycle state remains `ready`.

The "last domain removed" decision happens only after step 4 commits successfully.

### 2.5 Registry Consistency Matrix

Startup recovery must classify the registry row through this matrix before it inspects external evidence.

| Committed membership | Shared-resource state | Pending mutation | Target relation | Allowed external evidence | Recovery disposition |
|----------------------|-----------------------|------------------|-----------------|---------------------------|----------------------|
| `0` | `absent` | none | n/a | none required; orphan shared-resource evidence may authorize post-classification `cleanupOnly` | `resumeSteadyState` |
| `>0` | `ready` | none | n/a | committed domain directories, wrapped-DMK records, and generations for committed members | `resumeSteadyState` |
| `0` | `absent` | `createDomain(..., journaled)` | target absent from membership | staged domain artifacts may be absent or partial; no committed shared-resource promise exists yet | `continuePendingMutation` |
| `0` | `absent` | `createDomain(..., sharedResourceProvisioned or artifactsStaged or validated)` | target absent from membership | staged domain artifacts plus provisioned shared-resource evidence | `continuePendingMutation` |
| `>0` | `ready` | `createDomain(..., membershipCommitted)` | target present in membership | committed domain artifacts for the new target plus any residual staging evidence | `continuePendingMutation` |
| `>0` | `ready` | `deleteDomain(..., journaled or artifactsDeleted)` | target still present in membership | target domain artifacts may still exist or be partially removed | `continuePendingMutation` |
| `>0` | `ready` | `deleteDomain(..., membershipRemoved)` | target absent from membership | residual cleanup evidence for a non-last-domain delete | `continuePendingMutation` |
| `0` | `cleanupPending` | `deleteDomain(..., membershipRemoved or sharedResourceCleanupStarted)` | target absent from membership | shared-resource cleanup evidence plus any orphan target cleanup evidence | `continuePendingMutation` |
| any other row | any other value | any unclassifiable mutation row | any other relation | evidence inspection is not authorized | `frameworkRecoveryNeeded` |

Rows that classify to `continuePendingMutation` may continue the journaled transaction or, when the documented step is already satisfied, finish by clearing `pendingMutation`. They do not create new committed membership beyond what the registry row already declares.

Bootstrap APIs must preserve `continuePendingMutation` as an explicit output. It must not be collapsed into ordinary steady-state `sessionLocked` semantics.

The empty steady-state row (`0 / absent / none / n/a`) may run the documented post-classification `cleanupOnly` action when orphan shared-resource evidence is present, but that action does not change row classification or the final `resumeSteadyState` recovery disposition.

### 2.6 Recovery Evidence Ordering

Recovery uses registry-first ordering:

1. read `ProtectedDataRegistry`
2. validate schema and consistency invariants
3. classify the row through the consistency matrix
4. inspect only the external evidence authorized by that matrix row
5. emit exactly one recovery disposition

External evidence may:

- authorize post-classification `cleanupOnly` under the empty steady-state row
- prove that a pending mutation advanced far enough to continue

External evidence must not:

- change the classified registry row
- change the final `resumeSteadyState` disposition of the empty steady-state row
- create committed membership
- satisfy a missing committed shared-resource requirement by inference alone
- reinterpret an uncommitted target domain as committed state

## 3. Domain Storage And Key Material Execution

### 3.1 Generations And Domain Recovery

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

Startup recovery sequence for one domain:

1. inspect available generations
2. after authorization, attempt to open candidates using the unwrapped domain DMK
3. keep only structurally valid, decryptable generations
4. select the highest valid generation as authoritative
5. retain the next-highest valid generation as `previous` when present
6. enter domain-scoped `recoveryNeeded` if no readable authoritative generation exists

The framework must never silently create a new empty domain because prior local state is unreadable.

The generation model in v1 provides crash consistency only. It does not provide freshness or anti-rollback guarantees.

### 3.2 Wrapped-DMK Persistence Model

The v1 persistence model for each protected app-data domain is:

- domain payload generations are stored as encrypted envelopes on disk
- the DMK is not stored in plaintext on disk
- one shared app-data root secret is persisted as a Keychain item protected by `SecAccessControl`
- the root-secret Keychain item uses this-device-only accessibility and the access-control flags selected by `AppSessionAuthenticationPolicy`
- the v2 payload for that row is a Secure Enclave device-bound root-secret envelope rather than raw root-secret bytes
- the ProtectedData SE device-binding key uses `WhenPasscodeSetThisDeviceOnly + .privateKeyUsage` and does not add Face ID / Touch ID flags
- the v2 envelope is a binary-plist `CAPDSEV2` record with fixed `algorithmID = p256-ecdh-hkdf-sha256-aes-gcm-v1`
- v2 envelope public keys use P-256 X9.63 representation; salt is 32 bytes, nonce is 12 bytes, tag is 16 bytes, and root-secret ciphertext is 32 bytes
- HKDF sharedInfo and AES-GCM AAD bind the envelope version, AAD version, algorithm, shared-right identifier, device-binding key identifier, SE public-key hash, ephemeral public-key hash, ephemeral public-key length, and root-secret length
- v2 verification writes registry state plus a ThisDeviceOnly Keychain `format-floor` marker; if either says v2, later v1 raw root-secret payloads are downgrade/corruption and must fail closed
- normal root-secret reads supply the authenticated `LAContext` with `kSecUseAuthenticationContext`
- each domain DMK is persisted only as a `WrappedDomainMasterKeyRecord`
- there is no v1 model where each domain owns its own independent authorization resource
- there is no v1 single global DMK for all app-data domains
- the shared root secret is the only system-gated secret released by the Keychain root-secret gate

Required `WrappedDomainMasterKeyRecord` properties:

- explicit wrap format/version
- domain ID
- nonce
- authenticated ciphertext
- authentication tag
- associated data that includes at minimum domain ID and wrap-version metadata

The v1 `WrappedDomainMasterKeyRecord` implementation profile is fixed:

- raw root-secret bytes are never used directly as the DMK wrapping key
- v2 root-secret payloads must first open through the ProtectedData SE device-binding envelope; if that fails, authorization fails closed
- derive `AppDataWrappingRootKey` first with `HKDF-SHA256`
  - salt: `"CypherAir.AppData.WrapRoot.Salt.v1"`
  - info: `"CypherAir.AppData.WrapRoot.Info.v1"`
  - output: 32 bytes
- zeroize the raw root-secret bytes immediately after root-key derivation
- derive `DomainWrappingKey` per domain with `HKDF-SHA256`
  - salt: `"CypherAir.AppData.DomainWrap.Salt.v1"`
  - info: `WrappedDMKKeyInfoV1(domainID, wrapVersion = 1)`
  - output: 32 bytes
- wrap the 32-byte DMK with `AES.GCM`
  - nonce: 12 random bytes
  - tag: 16 bytes
- canonical AAD bytes are:
  - magic `"CADMKAD1"`
  - `wrapVersion = 1`
  - `domainIDLength` as `UInt16 big-endian`
  - domain ID UTF-8 bytes
  - `wrappedKeyLength = 32`
- persisted record files use versioned binary property-list encoding

The canonical wrapped-DMK lifecycle is:

- create: journal `createDomain` first, provision the shared root-secret Keychain record only after that journal exists, then stage and validate the wrapped-DMK record plus initial domain state before committing membership
- steady-state updates: rewrite payload generations only; do not rotate the wrapped-DMK record unless a later design explicitly introduces rekey
- delete domain: journal `deleteDomain` first, remove domain generations/bootstrap metadata/wrapped-DMK state, then remove the domain from committed membership
- last-domain cleanup: only after committed membership becomes empty and shared-resource lifecycle state commits to `cleanupPending` may shared root-secret Keychain deletion proceed

Wrapped-DMK writes must use an explicit transaction:

1. write staged wrapped-DMK state
2. read back and validate the staged record
3. atomically promote the staged record to committed wrapped-DMK state

Validation of the staged record must:

1. decode the staged property-list record
2. re-derive `DomainWrappingKey`
3. unwrap the staged DMK successfully
4. only then promote the staged file to committed state

The v1 docs do not permit multiple equally valid persistence shapes for the master-key ladder. The shared-gate / wrapped-DMK model above is the single canonical v1 model and must be applied consistently across startup, relock, deletion, migration, and recovery.

### 3.3 Bootstrap Metadata Details

Per-domain bootstrap metadata may exist beside encrypted generations, but it must remain minimal.

In v1, per-domain bootstrap metadata is file-side metadata stored beside encrypted generations. It is not stored in Keychain.

Per-domain bootstrap metadata must not become a plaintext shadow database and must not override registry authority.

Recommended per-domain bootstrap contents:

- schema version
- expected current generation identifier
- coarse domain recovery flag or reason code
- wrapped-DMK record presence/version

Bootstrap metadata is a cold-start and recovery routing hint, not a secret-bearing store.

### 3.4 Launch / Resume LAContext Handoff

The target launch/resume handoff is:

1. `AppSessionOrchestrator` determines that app-session authentication is required.
2. `AppSessionOrchestrator` evaluates the dedicated `AppSessionAuthenticationPolicy` and receives an authenticated `LAContext`.
3. If the initial route immediately requires protected-domain content, `AppSessionOrchestrator` passes that same `LAContext` to `ProtectedDataSessionCoordinator`.
4. `ProtectedDataSessionCoordinator` reads the shared root-secret Keychain record with `kSecUseAuthenticationContext`.
5. If the Keychain payload is v2, the ProtectedData Secure Enclave device-binding key silently opens the root-secret envelope without adding a second user-authentication prompt.
6. The raw root-secret bytes are used only to derive `AppDataWrappingRootKey`, then are zeroized.
7. Domain DMKs remain lazy-unwrapped; activating the shared app-data session does not open every protected domain.

When a legacy v1 raw root-secret payload is migrated to v2, the verified v2
payload becomes the only normal authorization source. A one-restart v1 safety
copy, if implemented, must live only in an explicit `legacy-cleanup` staging
row, must never authorize access, and must be deleted after the next successful
v2 open.

If root-secret retrieval fails with an already authenticated context, the framework must not fall back to app-managed plaintext state or silently retry with a different authorization mechanism. User-cancelled or denied authentication remains a normal access outcome; a missing or unreadable root-secret record for a `ready` registry row is framework recovery.

## 4. Initial Framework Interfaces And File Layout

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

### `ProtectedDataRegistry.swift`

Owns:

- registry manifest encode/decode
- committed membership
- shared-resource lifecycle record
- optional pending mutation record

### `ProtectedDataRegistryStore.swift`

Owns:

- single-writer access to `ProtectedDataRegistry`
- registry lock scope and transaction boundaries
- advancement and clearing of `pendingMutation`
- enforcement of registry consistency invariants
- framework-level recovery classification before external evidence inspection
- synchronous empty-registry bootstrap when the protected-data root contains no artifacts
- bootstrap outcome construction that can represent:
  - trusted empty steady-state registry
  - trusted loaded registry plus recovery disposition
  - framework-recovery with no trusted registry
- fresh-install/reset storage-contract validation that treats a missing `ProtectedData` root as clean only when no protected-data artifacts remain

### `ProtectedDomainBootstrapStore.swift`

Owns:

- per-domain bootstrap metadata persistence
- generation routing metadata
- wrapped-DMK presence/version hints
- coarse domain recovery state markers

### `ProtectedDomainKeyManager.swift`

Owns:

- per-domain DMK creation
- wrapped-DMK persistence and validation
- lazy DMK unwrap after shared app-data session activation succeeds
- zeroization of transient key material

### `ProtectedDataSessionCoordinator.swift`

Owns:

- root-secret Keychain retrieval through authenticated `LAContext`
- raw root-secret zeroization after wrapping-root-key derivation
- derived wrapping-root-key lifetime
- framework session state
- reuse of active shared app-data session
- no independent grace-window or launch/resume UX ownership
- relock orchestration
- zeroization of the derived wrapping root key and all unwrapped DMKs on relock
- latching `restartRequired` and blocking further protected-domain access in the current process
- post-bootstrap root-secret validation before protected-domain access proceeds
- explicit cleanup when app-session authentication succeeds but root-secret loading or root-key derivation fails

### `ProtectedDataRelockParticipant.swift`

Owns:

- zeroization or destruction of domain-local decrypted payloads
- zeroization or destruction of plaintext scratch buffers
- zeroization or destruction of derived in-memory indexes or lookup structures
- relock success/failure reporting without short-circuiting peer cleanup

### `ProtectedDomainRecoveryCoordinator.swift`

Owns:

- matrix-guided external evidence inspection after registry classification
- pending/current/previous inspection
- wrapped-DMK state validation
- generation validation
- authoritative generation selection
- domain-scoped recovery routing
- distinction between `frameworkRecoveryNeeded` and domain-scoped `recoveryNeeded`

### `AppSessionOrchestrator.swift`

Owns:

- grace-window policy
- launch/resume privacy-auth sequencing
- single user-visible unlock sequencing for launch/resume plus first protected-domain handoff when the initial route requires protected contents
- scene lifecycle intake
- app lock/relock initiation
- handoff of the authenticated `LAContext` to `ProtectedDataSessionCoordinator` when launch/resume should also activate the shared app-data session
- protected-data access-gate evaluation that distinguishes:
  - framework recovery
  - pending mutation recovery required
  - authorization required
  - already authorized
  - no protected domain present

Phase 1 implementation note:

- `CypherAirApp.init()` performs only synchronous pre-auth bootstrap through `AppStartupCoordinator`
- the bootstrap may create an empty steady-state registry
- no root-secret Keychain retrieval, legacy `LARightStore`, or legacy `LASecret` call is permitted from that path
- if the `ProtectedData` root or base directory does not yet exist, storage capability checks use the nearest existing parent directory; ordinary validation must not create the root just to probe the volume
- actual root and registry creation remains part of bootstrap/write execution and must apply and verify explicit `complete` file protection

### `ProtectedSettingsStore.swift`

First concrete adopter.

Purpose:

- validate the framework on a low-risk domain before later product domains, including Contacts
- reduce security-sensitive plaintext preferences over time
- prove the framework without touching private-key semantics

## 5. Integration Expansion

### 5.1 Composition Rule

The framework must reuse:

- `SecureEnclaveManageable`
- `KeychainManageable`

by composition.

Do not refactor the private-key path merely to force code sharing.

### 5.2 Narrow Integration Seams

Expected initial integration points:

- `AppContainer` for wiring the new services
- `AppStartupCoordinator` for protected-domain startup recovery
- app lock / resume flow through `AppSessionOrchestrator`
- `ProtectedDataPostUnlockCoordinator` for opening registered committed domains after app privacy authentication
- `ProtectedDomainRecoveryCoordinator` plus domain-specific handlers for pending mutation continuation and cleanup
- future protected-domain owners, including Contacts

This still implies explicit startup-ordering work when a real protected domain is introduced. It is a narrow code ownership boundary, not a promise of zero initialization-flow changes.

### 5.3 Contacts Relationship

Contacts must later plug into this framework as a domain-specific consumer after the earlier app-data phases have completed.

Contacts is not allowed to become a second independent security architecture if this framework exists.

In practical terms:

- Contacts owns person/key/tag/list semantics
- the protected app-data framework owns registry authority, shared-session authority, wrapped-DMK lifecycle, envelope rules, generation recovery, and relock posture
