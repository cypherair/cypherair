# Contacts Protected Domain Implementation Plan

> **Version:** Draft v0.1
> **Status:** Draft implementation-prep plan for unblocked Phase 8 work. This document does not describe current shipped behavior.
> **Purpose:** Bridge the gap between the current shared ProtectedData framework, the active Contacts documents, and the Phase 8 Contacts protected-domain work so the later implementation can proceed through a stable, reviewable PR sequence.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Companion document:** [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)
> **Primary authority:** [CONTACTS_TDD](CONTACTS_TDD.md) for Contacts design intent and [ARCHITECTURE](ARCHITECTURE.md) / [SECURITY](SECURITY.md) / [TDD](TDD.md) for current shared ProtectedData architecture.
> **Related documents:** [CONTACTS_PRD](CONTACTS_PRD.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) · [TESTING](TESTING.md)

## 1. Scope And Relationship

This document is an implementation-prep companion for the Contacts protected-domain phase. It exists because the repository has landed the shared ProtectedData foundation plus completed Phase 7 non-Contacts work, while Contacts still needs a current-state implementation path.

This document specifies:

- the current-state deltas that materially affect implementation planning
- the implementation decisions that must be frozen before code work starts
- the PR sequence and dependency order for Contacts protected-domain adoption
- the validation and migration scenarios that each future PR must satisfy

This document does not replace the existing formal specs.

If this document conflicts with:

- [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), or [TDD](TDD.md) on current shared-framework architecture or security rules, those long-lived docs win
- [CONTACTS_TDD](CONTACTS_TDD.md) on Contacts target behavior, the Contacts TDD wins
- Contacts PR1-PR8 sequencing or inventory ownership, this document is the active authority unless a later Contacts implementation plan replaces it

This document refines implementation sequencing and repository-specific integration detail. It does not create a third architecture.

## 2. Why This Document Exists

The active Contacts and shared-framework documents already establish the correct target direction:

- Contacts is a protected domain on the shared app-data framework
- Contacts package export/import supports explicit one-or-more-contact exchange, not whole-domain recovery
- `AppSessionOrchestrator` owns app-session sequencing
- `ProtectedDataSessionCoordinator` owns shared app-data root-secret retrieval
- Contacts must not invent a second vault architecture

The repository, however, still has material current-state behavior that must be unwound before that target can land safely. The biggest gaps are not only storage-related:

- startup still loads plaintext Contacts before protected-domain root-secret activation and Contacts domain unlock
- verification-capable services still use Contacts as direct cryptographic verification input
- Contacts access and mutation entrypoints are scattered across app surfaces and service helpers
- local reset and tutorial/test sandbox paths must be explicitly classified so they do not bypass or pollute the real Contacts domain
- certification support exists as a crypto workflow, but not as Contacts-owned projected state with saved signature artifacts and redesigned UX

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

### 3.4 Package Export / Import And Maintenance Delta

Whole-domain Contacts backup, replace-domain restore, and empty-install Contacts restore are no longer in scope for Phase 8.

The target package feature instead exports and imports selected contact public material through a `.cypherair-contacts` package. That package may contain one or more contacts, public-certificate-derived display labels, optional explicitly selected local relationship / custom labels, and optional saved certification signature artifacts, but it must not transport local protected-domain state, manual verification state, tags, notes, recipient lists, root-secret material, wrapped-DMK records, registry state, or source-device authorization material.

Current reset and sandbox paths are also relevant implementation deltas:

- `LocalDataResetService` currently deletes the legacy contacts directory and clears `ContactService` in-memory state
- tutorial sandbox containers use isolated temporary Contacts directories and must remain outside real protected Contacts migration
- future package export/import temporary artifacts must be covered by reset/cleanup paths

### 3.5 Certification Projection Delta

Current certification support is still workflow-oriented:

- `CertificateSignatureService` discovers, verifies, and generates certification artifacts
- it does not persist Contacts-owned certification projection state
- it does not save valid imported or locally generated certification signature artifacts as protected Contacts data
- the current Contacts UI exposes direct-key verification, User ID binding verification, and certification generation as a three-mode technical page

The Contacts TDD requires:

- certification projection on each `ContactKeyRecord`
- enough source reference, selector, signer, and revision metadata for later revalidation
- protected persistence for saved certification signature artifacts
- a redesigned contact-centered workflow that preserves all current capabilities without keeping the three-mode technical UI

Therefore certification projection and UX cannot be treated as late-stage UI polish.

## 4. Frozen Implementation Decisions

The following decisions are fixed by this document and should not be reopened during implementation unless a blocking defect appears.

### 4.1 Contacts Uses An Accurate Verification / Enrichment Model

Future verification-capable services must split:

- **core decrypt / signature packet detection**
  - plaintext delivery after authenticated decryption succeeds
  - packet parsing
- **certificate-backed signature verification**
  - signature verification outcome only when a suitable verification certificate is available
  - verified signer fingerprint only when certificate-backed verification actually succeeded
  - explicit unavailable state when the signer certificate or Contacts verification context is missing
- **Contacts enrichment**
  - matching signer identity to `ContactIdentity`
  - mapping certificate-backed signer fingerprints into contact / own-key recognition state
  - surfacing manual verification and certification projection
  - mapping historical / preferred / additional keys to the same person record

This separation is required for accuracy. Contacts can be unavailable while plaintext decryption remains meaningful, but the app must not claim completed cryptographic signature verification or signer identity without the verification certificate that made that claim possible.

Issuer/key-handle metadata from a signature packet is intentionally not a user identity clue. UI and service code only resolve signer identity from certificate-backed verification results.

Verification output must distinguish:

- verified signature
- invalid signature
- signer certificate unavailable
- Contacts verification context unavailable

Route policy after the split:

- `Decrypt` may complete plaintext delivery while signature verification or Contacts enrichment remains unavailable
- password-message decrypt follows the same split when signed content is present
- `Verify` route requires required verification context before presenting its intended final contacts-aware result
- `SigningService` verification helpers must no longer encode Contacts presence as the only way to avoid `.unknownSigner`

### 4.2 Verification Contract Refactor Lands As Its Own PR

The verification contract refactor is not folded into the lifecycle wiring PR.

It lands as a dedicated, earlier PR because it changes:

- Rust verification outputs and UniFFI contract surface
- service outputs
- route expectations
- unit-test baselines
- Contacts-unavailable semantics across multiple consumers

This PR explicitly owns the Rust/UniFFI verification contract expansion plus the corresponding Swift service contract refactor.

This keeps the later Contacts lifecycle PR focused on access gating, state wiring, and route behavior instead of also redefining core verification semantics at the same time.

### 4.3 `ContactService` Remains The Only UI Facade

Views and app coordinators continue to depend on a single `ContactService`.

`ContactService` must evolve from a flat-list/plaintext owner into a facade that covers:

- `ContactsAvailability`
- route-aware open / unlock coordination for Contacts-dependent surfaces
- Contacts query APIs
- Contacts mutation APIs
- import / merge / contact-package actions
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
- saved certification signature artifact references

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

### 4.6 Certification Redesign Is A Separate Capability

Certification projection, saved signature artifacts, and the redesigned contact-centered certification workflow land as their own capability PR.

It is intentionally separated from:

- the early schema skeleton / facade PR
- the later package export/import PR
- the final search / tags / recipient-list finish PR

This keeps the sequence stable:

- snapshot schema can reserve the necessary fields early
- projection persistence and signature artifact storage can be implemented before package export/import depends on them
- the old three-mode technical page can be replaced by a clearer workflow without waiting for final Contacts organization UI

The redesigned workflow must cover all capabilities of the current page:

- direct-key signature verification
- User ID binding signature verification
- external certification signature text/file import
- certification generation with one of the user's private keys
- generated certification signature export/share
- signer identity resolution
- target certificate selector validation
- certification-kind display

### 4.7 Package Export / Import Is Not Domain Recovery

The package PR owns selected-contact exchange only:

- one-contact export from Contact Detail
- one-or-more-contact export from Contacts list selection mode
- `.cypherair-contacts` Apple Archive-backed package generation
- package preview before import commit
- protected Contacts commit after framework/domain availability

It explicitly does not own whole-domain backup, replace-domain restore, empty-install restore, or framework-owned first-domain recovery import.

## 5. Companion Inventory Document

The companion [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) file records all Contacts-required access and mutation surfaces.

It is responsible for:

- classifying whether a surface is a read, mutation, package action, maintenance action, or optional Contacts enrichment
- defining whether the surface requires Contacts unlocked, framework gate only, or no Contacts access
- freezing the target locked-state behavior
- assigning each surface to a future Contacts-internal PR

This implementation plan references the inventory by behavior group rather than repeating every row inline.

## 6. Prerequisites And Planned Contacts PR Sequence

This section freezes the later implementation order and separates completed shared AppData prerequisites from Contacts-internal PRs. Contacts PR1-PR8 remain AppData Phase 8 work and are unblocked because Phase 7 is complete.

### 6.1 Shared AppData Prerequisites

Completed prerequisites:

- Phase 1 reusable ProtectedData framework is implemented.
- Phase 2 file-protection baseline is implemented for ProtectedData storage.
- Phase 3 first low-risk protected domain completed its narrow `protected-settings` / `clipboardNotice` scope.
- Phase 4 post-unlock multi-domain orchestration and framework hardening is implemented.
- Phase 5 `private-key-control` is implemented for `authMode` and private-key recovery journal state.
- Phase 6 `key-metadata` is implemented for `PGPKeyIdentity` payloads.
- Phase 7 non-Contacts protected-after-unlock domains and local file/static-protection cleanup are implemented and closed through PR 5 documentation/gate closure.

No remaining Phase 7 prerequisite blocks Contacts PR1. Contacts implementation still follows the PR1-PR8 sequence below and does not start from this document alone.

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
- keep ordinary runtime reads on the legacy plaintext source through Contacts PR3; compatibility projection exists to preserve consumers, not to switch source of truth early
- register Contacts as a `ProtectedDataRelockParticipant`
- clear decrypted snapshot state, serialization scratch buffers, search index state, signer-recognition state, and all `ContactService`-exposed runtime / compatibility projection state on relock

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
- relock cleanup assertions for snapshot, scratch-buffer, search-index, signer-recognition, and `ContactService` runtime projection teardown

### 6.3 Contacts PR2 — Verification Accuracy Refactor

**Goals**

- make decrypt / verify outputs accurately distinguish plaintext delivery, certificate-backed signature verification, and Contacts enrichment
- remove the assumption that missing Contacts certificates can be represented as generic `.unknownSigner`
- stop claiming completed signature verification when no suitable verification certificate was available

**Key Changes**

- extend Rust verification results and UniFFI surfaces only as needed to separate detailed signature state from legacy unknown-signer folding
- refactor `DecryptionService`
- refactor `SigningService`
- refactor `PasswordMessageService`
- change Swift verification-capable services to return explicit statuses for signer certificate unavailable, Contacts context unavailable, verified, expired, and invalid
- rewrite test baselines around accurate verification / enrichment semantics

**Required Outcomes**

- Decrypt-capable flows can return plaintext while signature verification remains unavailable
- signature verification is reported as completed only when a suitable verification certificate was used
- Rust/UniFFI exposes certificate-backed verification fingerprints only when a suitable verification certificate was used
- Verify-capable flows expose enough contract surface for route policy to decide whether required verification context is missing
- Contacts enrichment maps certificate-backed signer fingerprints into identity/contact/projection state, but it does not invent a verification result

**Not In Scope**

- no route-level Contacts availability UI yet
- no Contacts migration or cutover

**Inventory Coverage**

- decrypt enrichment surfaces
- verify enrichment surfaces
- password-message signed decrypt enrichment surfaces

**Validation**

- updated Rust, UniFFI-surface, and decrypt/signing/password-message tests
- explicit regression tests for signer certificate unavailable vs Contacts context unavailable
- explicit regression tests that no path claims signature verification without an available verification certificate

### 6.4 Contacts PR3 — Contacts Post-Auth Lifecycle And Surface Availability

**Goals**

- stop all ordinary Contacts route access and mutations from bypassing shared protected-domain lifecycle rules
- remove pre-auth Contacts loading from startup and direct route tasks
- move Contacts availability behind shared post-auth / post-unlock gating in normal app use without cutting over the source of truth

**Key Changes**

- remove startup-time Contacts payload loading before shared root-secret activation and Contacts domain unlock
- introduce the `ContactsAvailability` lifecycle surface consumed by Contacts-dependent routes and services
- reuse the app-authenticated `LAContext` for root-secret retrieval when available
- place the legacy plaintext compatibility source behind the post-auth Contacts gate until the PR4 migration and cutover move the source of truth into the protected Contacts domain
- gate Contacts list, detail, import commit, delete, manual verification, Encrypt recipient resolution, and certificate-signature entry through `ContactsAvailability`
- gate certificate-signature verification-time candidate signer reads so `CertificateSignatureService` cannot consume Contacts-backed `candidateSigners` while the Contacts domain is locked
- implement route-level opening / locked / recovery-needed / framework-unavailable behavior

**Required Outcomes**

- Contacts-dependent surfaces are normally available after successful app authentication and the post-auth Contacts gate finishes loading the current authoritative source for that stage
- import inspection can remain pre-commit, but import commit requires the Contacts domain path
- Decrypt route can show plaintext with explicit missing verification context when needed
- Verify route requires required verification context for its final contacts-aware result

**Not In Scope**

- no legacy plaintext cutover
- no protected Contacts source-of-truth cutover
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

### 6.5 Contacts PR4 — Legacy Contacts Migration, Quarantine, And Cutover

**Goals**

- move existing plaintext Contacts into the protected Contacts domain
- preserve deterministic rollback behavior during cutover
- make the protected Contacts domain the authoritative Contacts source only after readability is proven

**Key Changes**

- read legacy `.gpg` files and `contact-metadata.json`
- build protected-domain snapshot from legacy source
- validate protected target
- switch the authoritative source of truth only after protected destination readability is proven through the normal post-auth open path
- enter quarantine instead of immediate deletion
- delete quarantine only after a later successful Contacts domain open

**Not In Scope**

- no search / tags / recipient lists yet
- no contact package export/import yet
- no certification UI redesign yet

**Inventory Coverage**

- migration and cutover rows
- quarantine and cleanup rows

**Validation**

- interrupted migration recovery
- quarantine inactivity for normal Contacts access
- post-open deletion rules

### 6.6 Contacts PR5 — Person-Centered Contacts Model And Multi-Key Behavior

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

### 6.7 Contacts PR6 — Certification Projection Persistence And UX Redesign

**Goals**

- persist Contacts-owned certification projection and signature artifacts
- replace the current three-mode technical page with a contact-centered workflow
- keep manual verification and OpenPGP certification visibly distinct

**Key Changes**

- add certification projection storage on `ContactKeyRecord`
- add `ContactCertificationRecord` or equivalent saved signature artifact model
- save valid imported and locally generated certification signature artifacts as protected Contacts data
- implement Contact Detail trust/certification summary
- implement `Certify This Contact` as the common action from Contact Detail
- implement a certification details surface for saved history, exportable signature material, raw details, and secondary external signature import/verification
- retain coverage for direct-key verification, User ID binding verification, external text/file import, certification generation, generated signature export/share, signer identity resolution, selector validation, and certification-kind display

**Not In Scope**

- no contact package export/import yet
- no search / tags / recipient-list finish yet

**Inventory Coverage**

- certification summary row
- certify-contact action row
- certification details rows
- external certification signature import/verification rows
- projection/artifact persistence rows

**Validation**

- projection persistence tests
- saved signature artifact persistence tests
- external signature import validation tests
- generated certification save and export/share tests
- regression tests confirming manual verification and OpenPGP certification are not collapsed

### 6.8 Contacts PR7 — `.cypherair-contacts` Package Export / Import

**Goals**

- implement selected-contact package exchange after the person-centered and certification persistence models are stable
- support one-contact export from Contact Detail and one-or-more-contact export from Contacts list selection mode
- support safe preview-then-commit import

**Key Changes**

- Apple Archive-backed `.cypherair-contacts` package generation
- package manifest with `contacts[]`, public-certificate-derived labels, optional explicitly selected local relationship / custom labels, key file references, selector metadata, and optional certification signature references
- selected-contact export through the existing protected temporary export/fileExporter pattern
- package import parser and preview model
- package commit through `ContactService` / `ContactsDomainRepository`
- validation for path traversal, absolute paths, parent-directory references, links, duplicate logical paths, unknown required features, excessive size/count, invalid certificates, and invalid certification signatures

**Not In Scope**

- no whole-domain backup
- no replace-domain restore
- no empty-install restore
- no standard ZIP support

**Inventory Coverage**

- Contact Detail single-contact export row
- Contacts list multi-select export row
- package import preview row
- package import commit row
- package temporary artifact cleanup row

**Validation**

- single-contact and multi-contact export tests
- package preview without mutation
- package commit into protected Contacts state
- malformed package rejection tests
- package export omits private keys, manual verification state, tags, notes, recipient lists, root-secret material, wrapped-DMK records, registry state, and source-device authorization state; local relationship / custom labels are exported only when explicitly selected and default to off

### 6.9 Contacts PR8 — Search, Tags, Recipient Lists, And UI Finish

**Goals**

- complete the remaining Contacts product capabilities once lifecycle, migration, model semantics, certification persistence, and package exchange are already stable

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

- Contacts verification context unavailable during decrypt yields:
  - plaintext delivered
  - signature verification reported as unavailable when no suitable verification certificate is available
  - Contacts enrichment unavailable or pending, not silently downgraded to generic unknown-signer behavior
- locked Contacts and missing signer certificate remain distinguishable
- unverified signature issuer/key-handle metadata is not presented as signer identity
- Verify route requiring Contacts context or signer certificate:
  - prompts for app-data unlock only when it can make the required context available
  - reports required verification context unavailable when unlock is denied or canceled
- Password-message signed decrypt:
  - preserves the same accurate verification / enrichment split as ordinary decrypt

### 7.2 Lifecycle And Surface Coverage

- pre-auth bootstrap does not open Contacts payload content
- post-auth domain orchestration opens Contacts in normal app use
- Contacts list and detail do not silently substitute empty state for opening, locked, or recovery-needed state
- URL import and import confirmation do not bypass Contacts gate on commit
- delete and manual verification mutations do not bypass Contacts gate
- Encrypt recipient selection and recipient resolution use Contacts availability rather than startup-loaded plaintext state

### 7.3 Certification Redesign

- direct-key signature verification remains supported
- User ID binding signature verification remains supported
- external certification signature text/file import remains supported behind a secondary action
- `Certify This Contact` generates, saves, and can export/share certification signatures
- signer identity resolution, target selector validation, and certification-kind display remain supported
- certification projection and saved signature artifacts persist as protected Contacts data
- manual verification and OpenPGP certification remain separate

### 7.4 Contact Package Exchange

- `.cypherair-contacts` export supports one or more selected contacts
- Contact Detail can export the current contact
- Contacts list selection mode can export multiple contacts
- package import previews before mutating Contacts
- package import commit requires protected Contacts availability
- malformed packages fail closed for path traversal, links, excessive size/count, invalid manifests, invalid certificates, and invalid certification signatures
- package export/import never acts as whole-domain backup, replace-domain restore, or empty-install restore

### 7.5 Migration And Cutover

- legacy plaintext remains authoritative until protected destination readability is proven
- source-of-truth cutover occurs only after that readability proof succeeds
- quarantine state is inactive for ordinary Contacts display and resolution
- post-open deletion occurs only after a later successful Contacts domain open
- interrupted migration is idempotent

### 7.6 Reset, Cleanup, And Sandbox Boundaries

- local reset deletes legacy Contacts, protected Contacts artifacts, and package temporary artifacts
- local reset clears `ContactService` runtime state
- tutorial sandbox Contacts directories remain isolated from real Contacts migration and package exchange
- package temporary files are cleaned after completion or cancellation

## 8. Documentation Acceptance Criteria

This implementation-prep document is only complete if a later implementer can answer all of the following without inventing new architecture:

- why Contacts protected-domain adoption needs more than a storage swap
- why completed shared framework hardening remains a prerequisite rather than a Contacts-internal PR
- why Contacts PR1-PR8 remain Phase 8 work after Phase 7 completion
- what the Contacts schema skeleton may define before later behavior PRs
- why verification contract refactor must happen before lifecycle wiring
- which Contacts entrypoints are gated and which are only enrichment consumers
- where certification projection / artifact persistence lands relative to package exchange
- why whole-domain backup, replace-domain restore, and empty-install restore are not in scope
- how `.cypherair-contacts` one-or-more-contact package exchange is supposed to work
- which PR owns which behavior and what each PR explicitly avoids

The companion inventory document must also be detailed enough that an implementer does not need to rediscover Contacts-dependent surfaces by searching the repository from scratch.

## 9. Assumptions

- This document prepares implementation. It does not authorize direct code changes by itself.
- Current shared-framework docs and existing Contacts docs remain the architecture and product authorities.
- Future implementation proceeds with conservative, smaller PRs rather than a single large Contacts protected-domain rollout.
- Verification accuracy refactor is a dedicated earlier PR.
- Certification projection, saved signature artifacts, and UX redesign are a dedicated capability PR.
- `.cypherair-contacts` package export/import is selected-contact exchange, not whole-domain recovery.
- Empty-install restore is out of scope for Contacts Phase 8.
