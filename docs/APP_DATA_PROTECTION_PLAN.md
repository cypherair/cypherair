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

### 4.4 Minimal Bootstrap Metadata

The system may keep a minimal layer of plaintext bootstrap metadata outside encrypted domain payloads when required for cold start, recovery, or migration routing.

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

## 5. Migration Order

Implementation should follow this sequence.

### Phase 1: Protected App-Data Framework

Build the reusable protected app-data substrate first.

Goals:

- establish shared terminology and lifecycle
- define common envelope and recovery rules
- define common key-wrapping approach for app-data domains
- define common relock and session-unlock semantics

This phase should land before Contacts migration so Contacts can depend on the shared framework instead of creating its own parallel architecture.

### Phase 2: First Low-Risk Real Domain

Use a low-risk domain such as protected non-private-key app settings or recovery/control state as the first adopter.

Goals:

- exercise the new framework without touching the private-key domain
- validate session unlock, relock, and recovery behavior on real app-owned data
- reduce plaintext or lightly protected security-sensitive preferences over time

### Phase 3: Explicit File-Protection Hardening

After the basic framework exists, harden app-owned file persistence with explicit Apple file-protection policy rather than relying on defaults.

Goals:

- define a repository-wide file-protection posture for protected app-data files
- define protected handling for temporary files generated by exports, imports, or other local app-owned flows
- make file-protection behavior part of the documented security contract

### Phase 4: Contacts Vault On Shared Framework

Migrate Contacts to the shared protected app-data framework rather than letting Contacts become a one-off vault system.

Goals:

- preserve the Contacts product and TDD direction
- ensure Contacts remains a domain-specific consumer of the shared substrate
- avoid duplicating domain key lifecycle, envelope handling, recovery logic, and relock rules

### Phase 5: Remaining Persistent Domains

Migrate remaining app-owned persistent domains in order of security value and implementation risk.

Candidate areas include:

- additional settings or recovery state not yet moved in Phase 2
- future local drafts or protected caches
- future user-managed local data that should not remain plaintext at rest

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
- reuse of existing lower-level primitives by composition
- no "cleanup refactor" of the private-key domain just to make the new layer look symmetrical

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
- app lock / resume flow for relock and authenticated session reuse
- future Contacts integration

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
- does it keep app-data domains recoverable rather than private-key-style invalidating?
- does it keep bootstrap metadata minimal and non-sensitive?
- does it harden file protection explicitly instead of relying on platform defaults?
- does it make Contacts a consumer of the framework rather than the owner of a separate architecture?

