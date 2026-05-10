# App Data Protection Migration Plan

> **Status:** Archived historical AppData roadmap snapshot.
> **Archived on:** 2026-04-28.
> **Archival reason:** AppData implementation details have been absorbed into long-lived current-state documentation, and Phase 8 follow-on work now lives in Contacts-specific docs.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](../CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**

Original snapshot metadata follows.

> **Version:** Draft v1.0  
> **Status:** Draft active roadmap. This document does not describe current shipped behavior.  
> **Purpose:** Define the migration strategy for introducing a protected app-data layer beside the existing private-key security architecture.  
> **Audience:** Engineering, security review, QA, and AI coding tools.  
> **Companion document:** [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)  
> **Detailed proposal documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md)
> **Current progress record:** [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md)
> **Related documents:** [SECURITY](../SECURITY.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [TESTING](../TESTING.md) · [CONTACTS_PRD](../CONTACTS_PRD.md) · [CONTACTS_TDD](../CONTACTS_TDD.md) · [SPECIAL_SECURITY_MODE](../SPECIAL_SECURITY_MODE.md)

## 1. Intent

CypherAir already applies strong hardware-backed protection to private keys:

- Secure Enclave wrapping
- Keychain storage with `WhenUnlockedThisDeviceOnly`
- per-operation authentication for decrypt, sign, export, and other private-key actions
- explicit Standard / High Security semantics

That private-key path remains the authoritative security domain for key material.

This roadmap exists because the rest of the app's persistent state does not yet share a uniform protection model. Contacts, security-sensitive app state, recovery state, and future local caches should ultimately live inside a dedicated protected app-data architecture rather than relying on ad hoc file or preferences storage.

This initiative introduces a new protected app-data layer. It is not a rewrite of the private-key system.

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

The current proposal direction is also too dependent on app-managed authorization timing. For app-data domains, the revised v1 goal is to make the first release of the shared app-data root secret itself a system-enforced boundary rather than a convention owned only by application code.

## 3. Hard Constraints

This roadmap is bounded by the following non-negotiable constraints:

- zero network access remains a hard requirement
- no notification, share-extension, or other extension-specific assumptions are allowed in the baseline design
- existing private-key protection must not be weakened to make the new layer easier to build
- the new layer must preserve a minimal bootstrap boundary for cold start and recovery
- protected app-data domains must not silently reset to empty state after corruption or unreadable local state
- future implementation should prefer new files and composition over invasive edits to current private-key code

### 3.1 Private-Key Stability Rule

Unless a concrete security defect is discovered, this initiative does not change:

- current Secure Enclave private-key wrapping semantics
- current Standard / High Security behavior
- current per-operation private-key authentication boundaries

Private-key protection is treated as already sound enough to remain the separate authority for secret key material.

## 4. Target Architecture Decisions

### 4.1 Separate Security Domains

CypherAir will explicitly separate the Private Key Domain from Protected App Data Domains. Secret key material remains under the existing private-key design, while recoverable app-owned persistent data moves into the new app-data framework.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 3.1, 3.2, and 5.7.

### 4.2 Shared Root-Secret Gate With Per-Domain Master Keys

Protected app data will use one shared Keychain-protected app-data root secret and one `Domain Master Key` per protected domain. The root-secret Keychain item is protected by `SecAccessControl` and is released only through an authenticated `LAContext`, allowing launch/resume authentication and App Data session activation to be sequenced through one system authentication. This keeps authorization shared at the session boundary while preserving per-domain isolation for lifecycle, deletion, and recovery.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.1 and 6.5, plus [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 3.2.

### 4.3 Recoverable App-Data Domains

Protected app-data domains remain device-bound and session-authenticated, but they are recoverable domains rather than private-key-style invalidating domains. They must not inherit future private-key loss semantics from `Special Security Mode`.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.7 and 11.2-11.4.

### 4.4 System-Gated App-Data Authorization

The first normative gate for app-data unlock is the system-managed Keychain root-secret boundary, not an app-level convention. One successful app-session authentication can cover all protected domains in the current app-data session when the authenticated `LAContext` is handed to the root-secret read.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.2 and 5.3.

### 4.5 ProtectedDataRegistry As Lifecycle Authority

Protected app-data must use one global `ProtectedDataRegistry` as the sole authority for committed domain membership, shared-resource lifecycle state, pending mutation state, and recovery reconciliation order.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 5.4 and Section 6.4. Detailed execution rules live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.1-2.6.

### 4.6 Unified Session Orchestration

The target app-data architecture uses `AppSessionOrchestrator` as the app-wide session owner and `ProtectedDataSessionCoordinator` as the app-data subsystem coordinator under that owner. Grace-window policy, launch/resume sequencing, relock initiation, and fail-closed relock behavior must not split across competing owners.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.5-5.8 and 7.1-7.4.

### 4.7 Minimal Bootstrap Metadata

The system may keep minimal non-secret bootstrap metadata outside encrypted payloads for cold start, recovery, and migration routing. This metadata must remain insufficient to recreate meaningful business data and must never outrank registry authority.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 3.13, 6.4, and 6.6, plus [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Section 3.3.

### 4.8 Private-Key And App-Data Secure Enclave Boundary

Using Keychain / `SecAccessControl` / `LAContext` as the primary app-data gate does not make the gate app-managed. It means the app-data design relies on Apple's system authorization and Keychain access-control path instead of reusing the private-key wrapping model or the superseded `LAPersistedRight` model as the primary gate.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 5.2.

### 4.9 Dedicated App-Data Authorization Policy

Protected app-data authorization is a separate policy surface from private-key authentication mode. App-data must not derive from `AuthenticationMode`, `AuthenticationManager.createAccessControl(for:)`, or future private-key-only semantics.

The dedicated app-data policy is represented as `AppSessionAuthenticationPolicy`. It governs launch/resume authentication and root-secret Keychain access, while private-key `AuthenticationMode` continues to govern only private-key Secure Enclave wrapping and per-operation private-key use.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 5.3.

### 4.10 Deterministic Registry Recovery Model

Startup recovery begins from the registry row, not filesystem inference. Shared-resource lifecycle state and pending mutation phase remain distinct inputs, every valid row must classify to one documented recovery disposition, and orphan shared-resource cleanup is limited to an optional post-classification `cleanupOnly` action under the empty steady-state row.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.10-5.12 and 11.1, plus [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 2.2-2.6.

### 4.11 Fail-Closed Relock Failure Semantics

Relock is not best-effort cleanup. New protected-domain access must close first, cleanup must still fan out even after earlier failures, and any unsafe relock outcome must enter runtime-only `restartRequired`.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 7.4 and Section 11.1.

## 5. Migration Order

Implementation should follow this sequence.

### Phase 1: Protected App-Data Framework

Build the reusable protected app-data substrate first so later domains inherit a shared architecture instead of inventing one-off vault behavior.

Detailed phase goals and framework mechanics live in [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 2.1 and [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md).

### Phase 2: File-Protection Baseline

Establish the platform-specific file/static-protection baseline for registry files, protected-domain files, bootstrap metadata, and scratch files before any real protected domain ships.

See [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 2.2 and [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 6.7.

### Phase 3: First Low-Risk Real Domain

Use a low-risk domain such as protected-after-unlock settings or recovery/control state as the first concrete adopter. In the current implementation, this phase is limited to `ProtectedSettingsStore` plus the migrated `clipboardNotice` setting; remaining ordinary settings stay in Phase 7.

See [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 2.3 and Section 5, plus [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) for current progress.

### Phase 4: Post-Unlock Multi-Domain Orchestration And Framework Hardening

Extend the established post-unlock orchestration so app privacy authentication can automatically open additional required protected domains without extra Face ID prompts. This phase also hardens second-domain create/delete/recovery behavior, pending-mutation continuation, and last-domain cleanup before later product domains depend on them.

This phase does not migrate Contacts or any private-key-adjacent source of truth.

### Phase 5: Private-Key Control Domain

Create the `private-key-control` ProtectedData domain, migrate `authMode` and the private-key recovery journal, and move rewrap / modify-expiry recovery detection out of pre-auth startup without moving private-key material into ProtectedData.

Current status: implemented. See [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) for the code-backed boundary and remaining downstream work.

### Phase 6: Key Metadata Domain

Create the `key metadata` ProtectedData domain, migrate `PGPKeyIdentity` metadata out of the transitional Keychain metadata account, and avoid empty-key-list flashes during unlock.

Current status: implemented. See [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) for the code-backed boundary and remaining downstream work.

### Phase 7: Non-Contacts Protected-After-Unlock Domains

Migrate ordinary protected-after-unlock settings, self-test policy, and related local file/static-protection cleanup once their synchronous read paths have been removed or replaced.

### Phase 8: Contacts Protected Domain

Migrate Contacts onto the shared protected app-data framework only after the earlier key-metadata and non-Contacts protected-after-unlock work has been completed. Contacts must remain a domain-specific consumer of the shared framework, not a second independent vault architecture.

See [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](../CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) for the deferred Contacts-internal PR sequence. AppData Phase 4 and Phase 5 are prerequisites, but Contacts PR1-PR8 remain Phase 8 work behind the remaining Phase 6-7 gates.

### Phase 9: Future Persistent Domains

Migrate future app-owned persistent domains that are not covered by the current inventory, in order of security value and implementation risk.

### 5.1 Startup Authentication Boundary

All future implementations derived from this roadmap must follow a two-phase startup model with a pre-auth bootstrap phase and a post-auth unlock phase. This remains a roadmap-level constraint rather than an implementation detail.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Section 5.12 and [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 3.1.

### 5.2 App-Data Session Lifetime

The shared app-data session follows the current grace-window model, but the grace window has only one owner: `AppSessionOrchestrator`.

`First real protected-domain access` means the first route in the current app session that actually needs protected-domain contents, not process launch by itself. If launch or resume immediately enters such a route, the same orchestrated unlock flow may pass the authenticated `LAContext` into root-secret Keychain retrieval so the user does not encounter a second distinct app-data prompt. Root-secret retrieval must still remain fail-closed and must not be triggered merely because process launch or service initialization happened.

See [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) Sections 5.5-5.8 and 7.3-7.4, plus [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 3.2.

### 5.3 Persistent-State Classification Inventory

Implementation planning must maintain a complete inventory of persisted app-owned state in app-data migration scope, with target class, target phase or exception, current status, and migration readiness tracked explicitly and with reviewed private-key-domain exclusions called out explicitly.

The detailed inventory table and first-domain readiness rules live in [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Sections 4-5. Current roadmap status lives in [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md).

### 5.4 Startup Architecture Impact

Protected app-data is not only a local service addition. Any real protected-domain rollout must treat startup ordering, service initialization timing, locked-state routing, and orchestrator wiring as explicit migration surfaces.

See [APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT](APP_DATA_MIGRATION_GUIDE_PHASE1_6_SNAPSHOT.md) Section 3.4.

## 6. Explicit Do-Not-Change List

This roadmap does not authorize broad edits to the current private-key security path.

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
- use one shared Keychain-protected root secret as the primary app-data authorization gate in v1
- treat any current `LAPersistedRight` / `LASecret` implementation as superseded legacy state and a future migration source
- reuse existing lower-level primitives by composition only where they support, rather than replace, that system gate
- never attach the new layer to the private-key access-control source of truth
- no "cleanup refactor" of the private-key domain just to make the new layer look symmetrical

This proposal also does not require future protected domains to depend on the current `AuthenticationMode` gate in order to reach app-data authorization.

## 7. Code / Interface Direction

The new protected app-data layer should primarily appear as new code under a dedicated area such as:

```text
Sources/Security/ProtectedData/
```

This roadmap keeps only the high-level direction: new files, clear ownership boundaries, and narrow integration seams. The detailed file/type breakdown and initial responsibilities live in [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) Sections 4-5.

## 8. Canonicalization Plan

These proposal documents are planning and design inputs first. They are not yet canonical replacements for current-state docs.

After approval and implementation maturity:

- fold accepted app-data protection rules into [SECURITY](../SECURITY.md)
- update [ARCHITECTURE](../ARCHITECTURE.md) with the new domain boundaries and startup wiring
- update [TESTING](../TESTING.md) with protected-domain validation requirements
- update [PRD](../PRD.md) or future domain-specific PRDs when user-visible behavior changes
- update [TDD](../TDD.md) only for durable cross-cutting technical rules that become current-state

Until then:

- current code and canonical docs outrank this roadmap for shipped behavior
- this roadmap exists to prevent inconsistent one-off implementations

## 9. Review Questions For Future Implementation

This roadmap no longer carries the detailed checklist inline. Use [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) Sections 2-5 as the review, readiness, and acceptance source for future implementation work.
