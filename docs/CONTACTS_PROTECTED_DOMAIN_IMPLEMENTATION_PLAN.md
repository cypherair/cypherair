# Contacts Protected Domain Implementation Plan

> **Version:** Draft v0.1
> **Status:** Draft implementation-prep plan. This document does not describe current shipped behavior.
> **Purpose:** Bridge the gap between the current shared ProtectedData framework, the active Contacts documents, and the deferred Contacts protected-domain work so the later implementation can proceed through a stable, reviewable PR sequence.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Companion document:** [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)
> **Primary authority:** [CONTACTS_TDD](CONTACTS_TDD.md) for Contacts design intent and [ARCHITECTURE](ARCHITECTURE.md) / [SECURITY](SECURITY.md) / [TDD](TDD.md) for current shared ProtectedData architecture.
> **Related documents:** [CONTACTS_PRD](CONTACTS_PRD.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) · [TESTING](TESTING.md)

## 1. Scope And Relationship

This document is an implementation-prep companion for the deferred Contacts protected-domain phase. It exists because the repository has landed the shared ProtectedData foundation and Phase 1-6 domains, while Contacts still needs a current-state implementation path that accounts for remaining Phase 7 gates.

This document specifies:

- the current-state deltas that materially affect implementation planning
- the implementation decisions that must be frozen before code work starts
- the PR sequence and dependency order for Contacts protected-domain adoption
- the validation and migration scenarios that each future PR must satisfy

This document does not replace the existing formal specs.

If this document conflicts with:

- [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), or [TDD](TDD.md) on current shared-framework architecture or security rules, those long-lived docs win
- [CONTACTS_TDD](CONTACTS_TDD.md) on Contacts target behavior, the Contacts TDD wins
- [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) on roadmap order, the migration guide wins unless this document is explicitly used to refine the missing implementation detail needed to realize that order

This document refines implementation sequencing and repository-specific integration detail. It does not create a third architecture.

## 2. Why This Document Exists

The active Contacts and app-data documents already establish the correct target direction:

- Contacts is a protected domain on the shared app-data framework
- Contacts must be `import-recoverable`
- `AppSessionOrchestrator` owns app-session sequencing
- `ProtectedDataSessionCoordinator` owns shared app-data root-secret retrieval
- Contacts must not invent a second vault architecture

The repository, however, still has material current-state behavior that must be unwound before that target can land safely. The biggest gaps are not only storage-related:

- startup still loads plaintext Contacts before protected-domain root-secret activation and Contacts domain unlock
- verification-capable services still use Contacts as direct cryptographic verification input
- Contacts access and mutation entrypoints are scattered across app surfaces and service helpers
- empty-install recovery import is required by the Contacts TDD but not yet represented in the current access-gate model
- certification support exists as a crypto workflow, but not as Contacts-owned projected state with reconciliation metadata

This document turns those deltas into a concrete PR sequence with explicit dependencies and validation gates.

## 3. Current-State Delta To Freeze

This section records the current repository facts that materially change implementation planning.

### 3.1 Startup And Source-Of-Truth Delta

Current code still treats Contacts as startup-readable plaintext content:

- `AppStartupCoordinator.performPreAuthBootstrap(...)` calls `contactService.loadContacts()`
- `ContactService` persists `Documents/contacts/*.gpg`
- `ContactService` persists `Documents/contacts/contact-metadata.json`
- `ContactsView` still calls `loadContacts()` directly on `.task`

This conflicts with the Contacts TDD rule that Contacts payload generations must not be opened before shared app-data root-secret retrieval succeeds and the Contacts domain DMK unlocks. Contacts protected-domain adoption therefore requires both storage migration and startup sequencing migration.

### 3.2 Verification Contract Delta

Current verification-capable services still consume Contacts as direct verification input rather than as optional post-verification enrichment:

- `DecryptionService` builds verification keys from Contacts plus own keys
- `SigningService` builds verification keys from Contacts plus own keys
- `PasswordMessageService` builds verification keys from Contacts plus own keys

Current tests also encode the old semantics:

- when a signer is not present in Contacts or own keys, verification degrades to `.unknownSigner`
- this behavior is currently asserted in decrypt and signing tests

This means Contacts protected-domain adoption cannot be achieved by UI-layer locked-state handling alone. The service contract itself must be refactored first.

Because the current Rust/UniFFI layer only exposes signer fingerprint information when a provided verification key is already known, that refactor must include lower-level verification contract expansion rather than a Swift-only output reshaping.

### 3.3 Access / Mutation Surface Delta

Contacts access and mutation is not centralized in a single route boundary today. In addition to the obvious Contacts list and detail routes, current code directly reaches `ContactService` from:

- URL import coordination
- import confirmation workflow
- delete actions
- manual verification promotion actions
- Encrypt recipient resolution
- decrypt / verify signer identity enrichment
- certificate-signature workflows

Because these surfaces are distributed, Contacts protected-domain adoption requires an explicit inventory and PR-by-PR coverage checklist rather than relying on memory or a short prose summary.

### 3.4 Recovery And Empty-Install Import Delta

The Contacts TDD requires recovery import to work even when the target installation has no protected domains yet. In that case the framework, not Contacts, owns first-domain provisioning.

Current access-gate behavior still maps empty steady-state protected-data bootstrap to `.noProtectedDomainPresent`. That is correct for ordinary route access, but it means Contacts protected-domain adoption must explicitly define how recovery import transitions from empty steady-state into framework-owned first-domain provisioning.

This is not an optional extension scenario. It is a documented Contacts protected-domain requirement.

### 3.5 Certification Projection Delta

Current certification support is still workflow-oriented:

- `CertificateSignatureService` discovers, verifies, and generates certification artifacts
- it does not persist Contacts-owned certification projection state
- it does not maintain reconciliation metadata at the `ContactKeyRecord` level

The Contacts TDD requires:

- certification projection on each `ContactKeyRecord`
- enough source reference or revision metadata for later reconciliation
- reconciliation on unlock and import when needed

Therefore certification projection cannot be treated as a late-stage UI-only finishing task.

## 4. Frozen Implementation Decisions

The following decisions are fixed by this document and should not be reopened during implementation unless a blocking defect appears.

### 4.1 Contacts Uses A Dual-Layer Verification Model

Future verification-capable services must split:

- **core cryptographic verification**
  - packet parsing
  - signature verification outcome
  - signer fingerprint or equivalent key-handle level evidence exposed through Rust/UniFFI when the lower layer can determine it without Contacts
- **Contacts enrichment**
  - matching signer identity to `ContactIdentity`
  - mapping signer evidence into contact / own-key recognition state
  - surfacing manual verification and certification projection
  - mapping historical / preferred / additional keys to the same person record

This separation is required for Contacts protected-domain adoption because Contacts can be locked while cryptographic verification remains meaningful.

Core verification must not depend on Contacts having already supplied verification certificates or an unlocked Contacts domain.

Route policy after the split:

- `Decrypt` may complete plaintext delivery and core verification while Contacts enrichment remains pending
- password-message decrypt follows the same split when signed content is present
- `Verify` route requires Contacts unlock before presenting its intended final contacts-aware result
- `SigningService` verification helpers must no longer encode Contacts presence as the only way to avoid `.unknownSigner`

### 4.2 Verification Contract Refactor Lands As Its Own PR

The verification contract refactor is not folded into the lifecycle wiring PR.

It lands as a dedicated, earlier PR because it changes:

- Rust verification outputs and UniFFI contract surface
- service outputs
- route expectations
- unit-test baselines
- Contacts-lock semantics across multiple consumers

This PR explicitly owns the Rust/UniFFI verification contract expansion plus the corresponding Swift service contract refactor.

This keeps the later Contacts lifecycle PR focused on access gating, state wiring, and route behavior instead of also redefining core verification semantics at the same time.

### 4.3 `ContactService` Remains The Only UI Facade

Views and app coordinators continue to depend on a single `ContactService`.

`ContactService` must evolve from a flat-list/plaintext owner into a facade that covers:

- `ContactsAvailability`
- route-aware open / unlock coordination for Contacts-dependent surfaces
- Contacts query APIs
- Contacts mutation APIs
- import / merge / recovery actions
- recipient resolution by `ContactIdentity`
- signer enrichment lookup over unlocked Contacts runtime state

Internal implementation may split into:

- `ContactsDomainRepository`
- `ContactsMigrationCoordinator`
- `ContactsSearchIndex`
- projection / reconciliation helpers

But those remain behind the `ContactService` facade.

### 4.4 Contacts Snapshot Schema Freezes Early

Before any migration or cutover PR, the Contacts protected-domain implementation must freeze the first meaningful Contacts domain snapshot shape as a compatibility skeleton, including placeholders or initial fields for:

- `ContactsDomainSnapshot`
- `ContactIdentity`
- `ContactKeyRecord`
- `RecipientList`
- tag representation
- preferred/additional/historical key usage state
- manual verification state
- certification projection
- certification reconciliation metadata

This avoids a second schema turn after migration and projection work has already started.

This early freeze is a schema and compatibility contract only. It may define fields, default values, encode/decode behavior, and compatibility projections, but it must not implement the later business semantics owned by dedicated PRs:

- certification projection writes and reconciliation belong to the certification projection PR
- merge, preferred-key, additional-key, and historical-key behavior belong to the person-centered model PR
- search, tags, recipient-list management, and related UI finish belong to the final product-capability PR

### 4.5 Surface Inventory Is A Required Companion Artifact

The companion [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) document is not optional background material.

It is the required execution checklist for later implementation.

Every future implementation PR must:

- declare which inventory rows it covers
- update the coverage status for those rows
- avoid expanding behavior outside the rows explicitly owned by that PR

### 4.6 Certification Projection Is A Separate Pre-Cutover Capability

Certification projection and reconciliation lands as its own pre-cutover capability PR.

It is intentionally separated from:

- the early schema skeleton / facade PR
- the later UI finishing PR

This keeps the sequence stable:

- snapshot schema can reserve the necessary fields early
- projection persistence and reconciliation can be implemented before migration / cutover depends on them
- later UI work can consume an already-defined projection model instead of inventing it on the fly

### 4.7 Recovery PR Owns Empty-Install Restore

The recovery export/import PR must explicitly include:

- replace-domain import
- empty-install restore
- framework-owned first-domain provisioning
- post-import readability validation

Empty-install restore is not deferred to migration or cutover.

## 5. Companion Inventory Document

The companion [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) file records all Contacts-required access and mutation surfaces.

It is responsible for:

- classifying whether a surface is a read, mutation, recovery action, or optional Contacts enrichment
- defining whether the surface requires Contacts unlocked, framework gate only, or no Contacts access
- freezing the target locked-state behavior
- assigning each surface to a future Contacts-internal PR

This implementation plan references the inventory by behavior group rather than repeating every row inline.

## 6. Prerequisites And Planned Contacts PR Sequence

This section freezes the later implementation order and separates completed shared AppData prerequisites from Contacts-internal PRs. Contacts PR1-PR8 remain AppData Phase 8 work and do not begin until the remaining Phase 7 roadmap gate is implemented or explicitly resolved, unless the AppData roadmap is revised.

### 6.1 Shared AppData Prerequisites

Completed prerequisites:

- Phase 1 reusable ProtectedData framework is implemented.
- Phase 2 file-protection baseline is implemented for ProtectedData storage.
- Phase 3 first low-risk protected domain completed its narrow `protected-settings` / `clipboardNotice` scope.
- Phase 4 post-unlock multi-domain orchestration and framework hardening is implemented.
- Phase 5 `private-key-control` is implemented for `authMode` and private-key recovery journal state.
- Phase 6 `key-metadata` is implemented for `PGPKeyIdentity` payloads.

Remaining prerequisite:

- Phase 7 non-Contacts protected-after-unlock domains and local file/static-protection cleanup must be implemented or explicitly resolved before Contacts PR1 starts.

### 6.2 Contacts PR1 — Contacts Schema Skeleton And Compatibility Facade

**Goals**

- introduce the first concrete Contacts protected-domain foundation without cutting over any user-visible source of truth
- freeze the initial Contacts snapshot schema skeleton and `ContactService` facade direction

**Key Changes**

- add `ContactsDomainSnapshot`
- add `ContactIdentity`, `ContactKeyRecord`, and `RecipientList`
- add the `ContactsAvailability` type shape
- add a domain repository layer under `ContactService`
- preserve a compatibility projection so existing UI and service consumers can still operate during the migration sequence
- keep ordinary runtime reads on the legacy plaintext source through Contacts PR5; compatibility projection exists to preserve consumers, not to switch source of truth early
- register Contacts as a `ProtectedDataRelockParticipant`
- clear decrypted snapshot state, serialization scratch buffers, search index state, and signer-recognition state on relock

**Not In Scope**

- no Contacts lifecycle gate wiring
- no legacy plaintext cutover
- no verification semantics change yet
- no certification projection writes or reconciliation behavior
- no merge, preferred-key, additional-key, or historical-key behavior
- no search, tag, recipient-list management, or final Contacts UI behavior

**Inventory Coverage**

- foundational types only; no rows are considered fully migrated yet

**Validation**

- snapshot encode/decode and schema validation
- compatibility-projection tests
- relock cleanup assertions for snapshot, scratch-buffer, search-index, and signer-recognition teardown

### 6.3 Contacts PR2 — Verification Contract Refactor

**Goals**

- expand the lower-level verification contract before splitting Swift service outputs
- split core verification from Contacts enrichment in service contracts
- remove the assumption that Contacts must provide the only verification keys used to avoid `.unknownSigner`

**Key Changes**

- extend Rust verification results and UniFFI surfaces to expose non-Contacts core signer evidence when the lower layer can determine it
- refactor `DecryptionService`
- refactor `SigningService`
- refactor `PasswordMessageService`
- change Swift verification-capable services to consume core evidence plus explicit Contacts enrichment status instead of treating Contacts-provided certificates as the only path out of `.unknownSigner`
- rewrite test baselines around split verification / enrichment semantics

**Required Outcomes**

- Decrypt-capable flows can return plaintext plus core verification even when Contacts enrichment is unavailable
- core verification no longer depends on Contacts being unlocked and having already supplied verification certificates
- Rust/UniFFI exposes signer fingerprint or equivalent key-handle level evidence when the lower layer can determine it without Contacts
- Verify-capable flows expose enough contract surface for route policy to decide whether to block on Contacts unlock
- Contacts enrichment only maps core signer evidence into identity/contact/projection state; it does not decide whether core verification exists
- Contacts enrichment status can distinguish locked, framework-unavailable, and available outcomes

**Not In Scope**

- no route-level Contacts availability UI yet
- no Contacts migration or cutover

**Inventory Coverage**

- decrypt enrichment surfaces
- verify enrichment surfaces
- password-message signed decrypt enrichment surfaces

**Validation**

- updated Rust, UniFFI-surface, and decrypt/signing/password-message tests
- explicit regression tests for lower-level signer evidence being available without unlocked Contacts state when the engine can determine it
- explicit regression tests for locked Contacts vs absent signer data

### 6.4 Contacts PR3 — Contacts Lifecycle Wiring And Surface Gating

**Goals**

- stop all ordinary Contacts route access and mutations from bypassing shared protected-domain lifecycle rules
- remove pre-auth Contacts loading from startup and direct route tasks

**Key Changes**

- remove startup-time Contacts payload loading before shared root-secret activation and Contacts domain unlock
- ensure launch/resume may activate the shared app-data session through authenticated `LAContext` reuse without opening Contacts payload generations eagerly
- gate Contacts list, detail, import commit, delete, manual verification, Encrypt recipient resolution, and certificate-signature entry through `ContactsAvailability`
- gate certificate-signature verification-time candidate signer reads so `CertificateSignatureService` cannot consume Contacts-backed `candidateSigners` while the Contacts domain is locked
- implement route-level locked / recovery-needed / framework-unavailable behavior

**Required Outcomes**

- Contacts browsing requires an unlocked Contacts domain
- import inspection can remain pre-commit, but import commit requires the Contacts domain path
- Decrypt route can show core result with Contacts enrichment pending
- Verify route requires Contacts unlock for its final contacts-aware result

**Not In Scope**

- no legacy plaintext cutover
- no empty-install recovery import
- no projection persistence yet

**Inventory Coverage**

- startup and routing rows
- Contacts browse/detail rows
- URL import / import confirmation commit rows
- delete and manual verification rows
- Encrypt recipient-resolution rows
- certificate-signature route entry and verification-input rows

**Validation**

- macOS route and UI smoke coverage
- unit coverage for lock-state mapping across the gated surfaces

### 6.5 Contacts PR4 — Certification Projection And Reconciliation Capability

**Goals**

- land Contacts-owned certification projection state before migration or cutover depends on it
- define the boundary between `CertificateSignatureService` and Contacts projection persistence

**Key Changes**

- add certification projection storage on `ContactKeyRecord`
- add reconciliation metadata storage
- add reconciliation triggers on unlock and import where required
- keep manual verification and certification distinct in the model

**Not In Scope**

- no final UI polish for all certification presentation
- no recovery export/import yet

**Inventory Coverage**

- certificate-signature enrichment / projection-supporting rows
- projection/reconciliation maintenance rows

**Validation**

- projection persistence tests
- reconciliation trigger tests
- regression tests confirming crypto workflow and Contacts projection are not collapsed into one state

### 6.6 Contacts PR5 — Contacts Recovery Export / Import

**Goals**

- implement import-recoverable Contacts domain behavior before migration cutover
- make recovery work both for empty-install restore and replace-domain import

**Key Changes**

- portable recovery artifact
- passphrase-based export encryption
- import-time validation and rewrite into local protected-domain state
- framework-owned first-domain provisioning when the target installation has no protected domains yet

**Required Outcomes**

- export requires unlocked Contacts plus fresh authentication
- import handles empty steady-state installations
- import also handles replacing an existing Contacts domain
- import requires framework availability plus app-session unlock and root-secret availability, not a previously unlocked Contacts domain
- post-import readability validation is mandatory

**Not In Scope**

- no legacy plaintext migration yet

**Inventory Coverage**

- recovery export row
- recovery import row
- empty-install restore row

**Validation**

- wrong-passphrase failure
- memory-guard validation
- empty-install restore
- replace-domain import

### 6.7 Contacts PR6 — Legacy Contacts Migration, Quarantine, And Cutover

**Goals**

- move existing plaintext Contacts into the protected Contacts domain
- preserve deterministic rollback and recovery behavior during cutover

**Key Changes**

- read legacy `.gpg` files and `contact-metadata.json`
- build protected-domain snapshot from legacy source
- validate protected target
- switch the authoritative source of truth only after protected destination readability is proven through the normal post-auth open path
- enter quarantine instead of immediate deletion
- delete quarantine only after a later successful Contacts domain open

**Not In Scope**

- no search / tags / recipient lists yet

**Inventory Coverage**

- migration and cutover rows
- quarantine and cleanup rows

**Validation**

- interrupted migration recovery
- quarantine inactivity for normal Contacts access
- post-open deletion rules

### 6.8 Contacts PR7 — Person-Centered Contacts Model And Multi-Key Behavior

**Goals**

- complete the semantic shift from flat public-key records to person-centered Contacts
- land merge and key-usage-state behavior before higher-level organization features depend on it

**Key Changes**

- preferred / additional / historical key state
- explicit merge behavior
- signer recognition across historical keys
- recipient resolution by contact identity instead of flat fingerprint list

**Not In Scope**

- no search / tags / recipient-list UI finish yet

**Inventory Coverage**

- merge rows
- preferred-key management rows
- signer-recognition rows
- recipient-resolution semantics rows

**Validation**

- merge invariants
- preferred-key fallback rules
- historical-key signer recognition

### 6.9 Contacts PR8 — Search, Tags, Recipient Lists, And UI Finish

**Goals**

- complete the remaining Contacts product capabilities once lifecycle, recovery, migration, and model semantics are already stable

**Key Changes**

- Contacts and Encrypt search
- tag normalization, filtering, and suggestions
- recipient lists bound to `ContactIdentity`
- final UI surfaces for multi-key management and organization workflows

**Not In Scope**

- no new core security architecture

**Inventory Coverage**

- search rows
- tag rows
- recipient-list rows
- final Contacts detail / management rows

**Validation**

- search relevance and tie-break behavior
- tag normalization and duplicate suppression
- recipient-list resolution via preferred encryptable key

## 7. Validation And Scenario Matrix

The later implementation PRs must collectively satisfy the following scenario set.

### 7.1 Verification Semantics

- Contacts locked during decrypt yields:
  - plaintext delivered
  - core verification delivered
  - Contacts enrichment pending, not silently downgraded to generic unknown-signer behavior
- locked Contacts and truly absent signer data remain distinguishable because core signer evidence comes from the lower-level verification contract, not from unlocked Contacts state alone
- Verify route requiring Contacts context:
  - prompts for unlock
  - stops when unlock is denied or canceled
- Password-message signed decrypt:
  - preserves the same core/enrichment split as ordinary decrypt

### 7.2 Lifecycle And Surface Coverage

- pre-auth bootstrap does not open Contacts payload content
- Contacts list and detail do not silently substitute empty state for locked or recovery-needed state
- URL import and import confirmation do not bypass Contacts gate on commit
- delete and manual verification mutations do not bypass Contacts gate
- Encrypt recipient selection and recipient resolution use Contacts availability rather than startup-loaded plaintext state

### 7.3 Recovery And Restore

- export/import recovery works on installations with existing protected domains
- export/import recovery works on empty steady-state installations
- framework-owned first-domain provisioning is used when required
- import requires framework availability plus app-session unlock and root-secret availability, not a pre-existing unlocked Contacts domain
- replace-domain import remains explicit and deterministic

### 7.4 Migration And Cutover

- legacy plaintext remains authoritative until protected destination readability is proven
- source-of-truth cutover occurs only after that readability proof succeeds
- quarantine state is inactive for ordinary Contacts display and resolution
- post-open deletion occurs only after a later successful Contacts domain open
- interrupted migration is idempotent

### 7.5 Projection And Reconciliation

- certification projection is persisted at the `ContactKeyRecord` level
- reconciliation metadata is sufficient to detect stale projected state
- projection work does not collapse manual verification and certification into one status

## 8. Documentation Acceptance Criteria

This implementation-prep document is only complete if a later implementer can answer all of the following without inventing new architecture:

- why Contacts protected-domain adoption needs more than a storage swap
- why completed shared framework hardening remains a prerequisite rather than a Contacts-internal PR
- why Contacts PR1-PR8 remain Phase 8 work behind the remaining Phase 7 gate
- what the Contacts schema skeleton may define before later behavior PRs
- why verification contract refactor must happen before lifecycle wiring
- which Contacts entrypoints are gated and which are only enrichment consumers
- where certification projection lands relative to migration and cutover
- how empty-install recovery import is supposed to work
- which PR owns which behavior and what each PR explicitly avoids

The companion inventory document must also be detailed enough that an implementer does not need to rediscover Contacts-dependent surfaces by searching the repository from scratch.

## 9. Assumptions

- This document prepares implementation. It does not authorize direct code changes by itself.
- Current shared-framework docs and existing Contacts docs remain the architecture and product authorities.
- Future implementation proceeds with conservative, smaller PRs rather than a single large Contacts protected-domain rollout.
- Verification contract refactor is a dedicated earlier PR.
- Certification projection / reconciliation is a dedicated pre-cutover capability PR.
- Empty-install restore is part of the recovery PR, not a late migration detail.
