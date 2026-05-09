# Contacts Protected Domain Implementation Plan

> **Version:** Draft v0.4
> **Status:** Draft implementation-prep plan for remaining Contacts feature work, updated with Contacts PR6 certification persistence and UX coverage notes.
> **Purpose:** Bridge the gap between the current shared ProtectedData framework, implemented Contacts protected-domain security/storage behavior, and the remaining Contacts feature work so later implementation can proceed through a stable, reviewable PR sequence.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Companion document:** [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)
> **Primary authority:** [CONTACTS_TDD](CONTACTS_TDD.md) for Contacts design intent and [ARCHITECTURE](ARCHITECTURE.md) / [SECURITY](SECURITY.md) / [TDD](TDD.md) for current shared ProtectedData architecture.
> **Related documents:** [CONTACTS_PRD](CONTACTS_PRD.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) · [TESTING](TESTING.md)

## 1. Scope And Relationship

This document is an implementation-prep companion for the Contacts follow-on phase. It exists because the repository has landed the shared ProtectedData foundation, completed Phase 7 non-Contacts work, the Contacts PR4 protected-domain security/storage cutover, the Contacts PR5 person-centered runtime model, and Contacts PR6 certification persistence/UX work, while package exchange and organization/search surfaces still need a stable implementation path.

This document specifies:

- the current-state deltas that materially affect implementation planning
- the implementation decisions that must be frozen before code work starts
- the PR sequence and dependency order for remaining Contacts feature adoption
- the validation and migration scenarios that remaining feature PRs must satisfy

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

The repository has already resolved the major PR3 / PR4 security-storage deltas that used to block protected Contacts. The remaining gaps are feature and verification-contract work rather than a missing protected-domain cutover:

- PR3 removed pre-auth plaintext Contacts startup loading and moved ordinary Contacts access behind the shared post-auth lifecycle surface
- PR4 migrated the flat compatibility snapshot into the protected `contacts` domain, quarantined legacy plaintext, and made legacy/quarantine storage cleanup-only after cutover
- verification-capable services still need the planned contract split between cryptographic verification and Contacts enrichment
- remaining feature work still includes selected-contact package exchange, search, tags, recipient-list UI, and organization workflows

This document preserves the historical PR sequence for review context and turns the remaining work into explicit dependencies and validation gates.

## 3. Current-State Delta To Freeze

This section records the current repository facts that materially change implementation planning.

### 3.1 Resolved Startup And Source-Of-Truth Delta

The pre-PR3 baseline treated Contacts as startup-readable plaintext content:

- `AppStartupCoordinator.performPreAuthBootstrap(...)` loaded Contacts during pre-auth bootstrap.
- `ContactService` persisted `Documents/contacts/*.gpg`.
- `ContactService` persisted `Documents/contacts/contact-metadata.json`.
- `ContactsView` opened the legacy source from a route `.task`.

Contacts PR3 removed that pre-auth ordinary read path. Startup records the load as deferred, and normal app use opens Contacts only after the shared post-auth protected-data gate reports an eligible state.

Contacts PR4 then migrated the flat compatibility source into the protected Contacts domain. Legacy files and quarantine are now migration/cleanup sources only, while ordinary route and service callsites continue to use the same post-auth lifecycle surface.

### 3.2 Remaining Verification Contract Delta

Current verification-capable services still consume Contacts as direct verification input rather than as optional post-verification enrichment:

- `DecryptionService` builds verification keys from Contacts plus own keys
- `SigningService` builds verification keys from Contacts plus own keys
- `PasswordMessageService` builds verification keys from Contacts plus own keys

Current tests also encode the old semantics:

- when a signer is not present in Contacts or own keys, verification degrades to `.unknownSigner`
- this behavior is currently asserted in decrypt and signing tests

This means remaining Contacts feature work cannot rely only on UI-layer locked-state handling. The service contract itself still needs the planned verification/enrichment refactor.

Because the current Rust/UniFFI layer only exposes signer fingerprint information when a provided verification key is already known, that refactor must include lower-level verification contract expansion rather than a Swift-only output reshaping.

### 3.3 Access / Mutation Surface Inventory

Contacts access and mutation is not centralized in a single route boundary today. In addition to the obvious Contacts list and detail routes, current code directly reaches `ContactService` from:

- URL import coordination
- import confirmation workflow
- delete actions
- manual verification promotion actions
- Encrypt recipient resolution
- decrypt / verify signer identity enrichment
- certificate-signature workflows

Because these surfaces are distributed, remaining Contacts feature work still requires an explicit inventory and PR-by-PR coverage checklist rather than relying on memory or a short prose summary.

### 3.4 Package Export / Import And Maintenance Delta

Whole-domain Contacts backup, replace-domain restore, and empty-install Contacts restore are no longer in scope for the remaining Contacts feature plan.

The target package feature instead exports and imports selected contact public material through a `.cypherair-contacts` package. That package may contain one or more contacts, public-certificate-derived display labels, optional explicitly selected local relationship / custom labels, and optional saved certification signature artifacts, but it must not transport local protected-domain state, manual verification state, tags, notes, recipient lists, root-secret material, wrapped-DMK records, registry state, or source-device authorization material.

Current reset and sandbox paths are also relevant implementation deltas:

- `LocalDataResetService` currently deletes the legacy contacts directory and clears `ContactService` in-memory state
- tutorial sandbox containers use isolated temporary Contacts directories and must remain outside real protected Contacts migration
- future package export/import temporary artifacts must be covered by reset/cleanup paths

### 3.5 Certification Projection Delta

Contacts PR6 resolves the certification persistence and UX delta that previously remained after the protected-domain cutover:

- `CertificateSignatureService` still owns cryptographic discovery, verification, signer resolution, selector validation, and User ID certification generation.
- Contacts now owns protected persistence of valid certification artifacts and the per-key certification projection derived from those saved records.
- Saved records include canonical binary signature bytes, a signature digest, source, target selector, target key fingerprint/key ID, signer fingerprints, certification kind, validation status, target certificate digest, timestamps, and export filename.
- Schema-v1 placeholder artifact payloads decode through compatibility defaults instead of making older protected Contacts snapshots unreadable.
- Contact Detail now exposes a compact trust/certification summary and a contact-centered `Certify This Contact` action.
- The certification details surface replaces the previous three-mode technical entry for ordinary navigation, while preserving direct-key verification, User ID binding verification, text/file import, generated certification, explicit export/share, signer identity resolution, selector validation, and certification-kind display.

Remaining package work may consume the PR6 artifact/revalidation APIs, but package exchange is not part of PR6.

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

### 4.4 Contacts Snapshot Schema Was Frozen Early

Before PR4 migration/cutover, the Contacts protected-domain implementation froze the first meaningful Contacts domain snapshot shape as a compatibility skeleton, including placeholders or initial fields for:

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

This section records completed shared AppData prerequisites, the implemented Contacts PR4 security/storage cutover, and the remaining Contacts-internal feature order.

### 6.1 Shared AppData Prerequisites

Completed prerequisites:

- Phase 1 reusable ProtectedData framework is implemented.
- Phase 2 file-protection baseline is implemented for ProtectedData storage.
- Phase 3 first low-risk protected domain completed its narrow `protected-settings` / `clipboardNotice` scope.
- Phase 4 post-unlock multi-domain orchestration and framework hardening is implemented.
- Phase 5 `private-key-control` is implemented for `authMode` and private-key recovery journal state.
- Phase 6 `key-metadata` is implemented for `PGPKeyIdentity` payloads.
- Phase 7 non-Contacts protected-after-unlock domains and local file/static-protection cleanup are implemented and closed through PR 5 documentation/gate closure.
- Contacts PR4 protected-domain security/storage cutover is implemented for the flat compatibility snapshot, including migration/quarantine, no legacy fallback after cutover, recovery states, and relock cleanup.

No remaining Phase 7 prerequisite blocks Contacts feature work. Later Contacts implementation still follows the remaining PR sequence below and does not start from this document alone.

### 6.2 Contacts PR1 — Contacts Schema Skeleton And Compatibility Facade

Status: implemented as the schema/facade foundation for the protected Contacts cutover.

**Goals**

- introduced the first concrete Contacts protected-domain foundation without cutting over any user-visible source of truth
- froze the initial Contacts snapshot schema skeleton and `ContactService` facade direction

**Key Changes**

- added `ContactsDomainSnapshot`
- added `ContactIdentity`, `ContactKeyRecord`, and `RecipientList`
- added the `ContactsAvailability` type shape
- added a domain repository layer under `ContactService`
- preserved a compatibility projection so existing UI and service consumers could operate during the migration sequence
- kept ordinary runtime reads on the gated legacy compatibility source through Contacts PR3; compatibility projection existed to preserve consumers, not to switch source of truth early
- registered Contacts as a `ProtectedDataRelockParticipant`
- cleared decrypted snapshot state, serialization scratch buffers, search index state, signer-recognition state, and all `ContactService`-exposed runtime / compatibility projection state on relock

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

Status: implemented as the lifecycle/access-gating bridge before PR4 protected-domain cutover.

**Goals**

- stopped all ordinary Contacts route access and mutations from bypassing shared protected-domain lifecycle rules
- removed pre-auth Contacts loading from startup and direct route tasks
- moved Contacts availability behind shared post-auth / post-unlock gating in normal app use without cutting over the source of truth

**Key Changes**

- removed startup-time Contacts payload loading before shared root-secret activation and Contacts domain unlock
- introduced the `ContactsAvailability` lifecycle surface consumed by Contacts-dependent routes and services
- reused the app-authenticated `LAContext` for root-secret retrieval when available
- placed the legacy plaintext compatibility source behind the post-auth Contacts gate during PR3; PR4 later moved the source of truth into the protected Contacts domain
- gated Contacts list, detail, import commit, delete, manual verification, Encrypt recipient resolution, and certificate-signature entry through `ContactsAvailability`
- gated certificate-signature verification-time candidate signer reads so `CertificateSignatureService` could not consume Contacts-backed `candidateSigners` while Contacts was unavailable
- implemented route-level opening / locked / recovery-needed / framework-unavailable behavior

**Gate Input Contract**

Contacts PR3 does not derive `ContactsAvailability` from `ProtectedDataPostUnlockOutcome` alone. The gate input is a dedicated `ContactsPostAuthGateResult` built from:

- `ProtectedDataPostUnlockOutcome`
- `ProtectedDataSessionCoordinator.frameworkState`

`frameworkState == .restartRequired` takes priority over all post-unlock outcomes and maps to `ContactsAvailability.restartRequired`. `frameworkState == .frameworkRecoveryNeeded` takes priority next and maps to `ContactsAvailability.frameworkUnavailable`.

Historical PR3 note: this stage used the authorized shared app-data session to read the then-current legacy compatibility source. It did not open or commit a Contacts protected-domain payload.

**Outcome Mapping**

| Gate input | Availability | Clear runtime | Allow legacy load | UI / behavior |
| --- | --- | --- | --- | --- |
| `frameworkState == .restartRequired` | `.restartRequired` | yes | no | Restart required |
| `frameworkState == .frameworkRecoveryNeeded` | `.frameworkUnavailable` | yes | no | Protected-data framework unavailable |
| `.opened(_) + .sessionAuthorized` | `.opening` -> success `.availableLegacyCompatibility` / failure `.recoveryNeeded` | yes, before load | yes | Loading, then list or recovery |
| `.noRegisteredDomainPresent + .sessionAuthorized` | `.opening` -> success `.availableLegacyCompatibility` / failure `.recoveryNeeded` | yes, before load | yes | Historical PR3 path using the authorized shared app-data session |
| `.noRegisteredOpeners + .sessionAuthorized` | `.opening` -> success `.availableLegacyCompatibility` / failure `.recoveryNeeded` | yes, before load | yes | Test / degraded path only; production should not normally hit it |
| `.noProtectedDomainPresent` | `.locked` | yes | no | Protected-data gate unavailable |
| `.noAuthenticatedContext` | `.locked` | yes | no | No authenticated context |
| `.authorizationDenied` | `.locked` | yes | no | User canceled or denied authentication |
| `.pendingMutationRecoveryRequired` | `.frameworkUnavailable` | yes | no | Pending mutation recovery blocks Contacts |
| `.frameworkRecoveryNeeded` | `.frameworkUnavailable` | yes | no | Framework recovery blocks Contacts |
| `.domainOpenFailed(_)` | `.frameworkUnavailable` | yes | no | Historical PR3 path where any protected-domain open failure blocked Contacts load |
| Any other outcome + `.sessionLocked` | `.locked` | yes | no | Session locked |

**Gated API Rule**

Production code must not call raw legacy loading or direct runtime storage. It must use `ContactService` gated accessors such as availability, available snapshots/lookups, recipient key resolution, and gated mutation methods. Raw legacy load and raw mutation implementation details remain private to `ContactService`; tests and tutorial sandbox code may use explicit helper entrypoints only.

Contacts PR3 includes a source audit test to prevent production `Sources` callsites from reintroducing `contactService.loadContacts()`, direct `contactService.contacts` reads, direct raw lookup, or private raw implementation calls outside the allowed implementation/sandbox files.

**Atomic Legacy Load**

`openLegacyCompatibilityAfterPostUnlock(gateResult:)` is fail-closed:

- clear contacts, verification states, and compatibility projection before entering `.opening`
- read legacy files, validate certificates, filter verification state, and rebuild compatibility projection into local values first
- publish runtime state only after the whole load succeeds
- on any read, validation, projection, or save failure, clear all runtime state again and set `.recoveryNeeded`
- relock and local data reset continue clearing runtime state and returning to `.locked`

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
- table-driven unit coverage for every gate outcome and framework-state override
- unit coverage for authorized legacy load, fail-closed load failure, relock cleanup, locked mutation blocking, and production source audit
- macOS route and UI smoke coverage for Contacts opening / locked / recovery / framework / restart states and Encrypt recipient locked state

### 6.5 Contacts PR4 — Legacy Contacts Migration, Quarantine, And Cutover

Status: implemented for the flat compatibility snapshot security/storage cutover. Later sections still describe remaining feature work.

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

Status: implemented as a Swift-only Contacts feature PR on top of the PR4 protected `contacts` domain.

**Goals**

- complete the semantic shift from flat public-key records to person-centered Contacts
- land merge and key-usage-state behavior before higher-level organization features depend on it

**Key Changes**

- `ContactService` now exposes identity and key-summary DTOs while keeping flat `Contact` as a compatibility projection
- protected-domain import updates same-fingerprint key records in place, creates new identities for same-email different-fingerprint imports, and returns strong/weak candidate matches for optional later merge
- Contact Detail and Contacts list are identity-centered; certificate-signature entry remains key-specific through fingerprint routes
- merge reassigns source keys to the surviving target identity, unions tags and recipient-list memberships, and preserves per-key manual verification plus certification projection/artifact references
- preferred / additional / historical key state is enforced for protected-domain mutations; historical keys stay visible for signer recognition and are excluded from encryption recipient resolution
- Encrypt selection stores contact IDs, resolves compatibility initial fingerprints to contact IDs on appear, and encrypts through preferred-key recipient resolution
- source audits forbid production fingerprint-recipient resolution outside compatibility seams

**Not In Scope**

- no search / tags / recipient-list UI finish yet
- no certification projection persistence/UX redesign beyond preserving the existing reserved per-key fields

**Inventory Coverage**

- merge rows are covered by Contact Detail merge entry and `ContactService.mergeContact(sourceContactId:into:)`
- preferred-key management rows are covered by `setPreferredKey` and `setKeyUsageState`
- signer-recognition rows are covered by verification context returning preferred, additional, and historical key projections
- recipient-resolution semantics rows are covered by contact-ID resolution through preferred encryptable keys

**Validation**

- protected import candidate matching, same-fingerprint key-record stability, merge invariants, tag/list union, preferred-key persistence/fail-closed behavior, historical-key exclusion from encryption, and historical-key signer recognition are covered by `ContactServiceTests`
- snapshot invariants cover one-preferred maximum, active-key encryptability, historical non-encryptable validity, and zero-preferred unresolved runtime state
- Encrypt model tests cover contact-ID selection and compatibility fingerprint bridging

### 6.7 Contacts PR6 — Certification Projection Persistence And UX Redesign

**Goals**

- persist Contacts-owned certification projection and signature artifacts
- replace the current three-mode technical page with a contact-centered workflow
- keep manual verification and OpenPGP certification visibly distinct

**Key Changes**

- added certification projection storage on `ContactKeyRecord`
- extended the saved certification artifact model with canonical binary signature bytes, digest, source, target selector, signer fingerprints, certification kind, validation status, target certificate digest, timestamps, and export filename
- saved only valid imported and locally generated certification signature artifacts as protected Contacts data
- deduplicated saved artifacts by target key, target selector, and signature digest
- exported saved artifacts by armoring canonical binary signature bytes on demand
- recomputed per-key certification projection after protected Contacts open and after artifact mutations
- implemented Contact Detail trust/certification summary
- implemented `Certify This Contact` as the common action from Contact Detail
- implemented a certification details surface for saved history, exportable signature material, raw details, and secondary external signature import/verification
- retained coverage for direct-key verification, User ID binding verification, external text/file import, certification generation, generated signature export/share, signer identity resolution, selector validation, and certification-kind display

**Not In Scope**

- no contact package export/import yet
- no search / tags / recipient-list finish yet

**Inventory Coverage**

- certification summary read row is covered by Contact Detail and key summary projection reads
- certify-contact action row is covered by the contact-centered details route and `ContactService.saveCertificationArtifact(_:)`
- certification details read row is covered by `ContactCertificationDetailsView` / `ContactCertificationDetailsScreenModel`
- external certification signature import/verification row is covered by preview-then-save gating
- projection/artifact persistence rows are covered by protected-domain save, export, revalidation, deduplication, removal pruning, and merge preservation behavior

**Validation**

- snapshot decode/validation covers legacy artifact defaults, digest mismatch, duplicate artifacts, wrong-key references, and projection recomputation
- `ContactServiceTests` cover save/reopen persistence, deduplication, export data generation, stale projection behavior, removal pruning, merge preservation, and manual verification separation
- `CertificateSignatureServiceTests` cover persistable validated metadata and selector/signer context behavior
- certification details screen-model tests cover generated certification save, explicit export, import preview, save gating, and locked Contacts handling
- UI smoke coverage verifies Contact Detail separates manual verification and OpenPGP certification signals

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

- why the remaining Contacts feature work needs more than a storage swap
- why completed shared framework hardening remains a prerequisite rather than a Contacts-internal PR
- which Contacts security/storage pieces are already implemented by PR4 and which feature pieces remain
- what the Contacts schema skeleton may define before later behavior PRs
- why verification contract refactor must happen before lifecycle wiring
- which Contacts entrypoints are gated and which are only enrichment consumers
- where certification projection / artifact persistence lands relative to package exchange
- why whole-domain backup, replace-domain restore, and empty-install restore are not in scope
- how `.cypherair-contacts` one-or-more-contact package exchange is supposed to work
- which PR owns which behavior and what each PR explicitly avoids

The companion inventory document must also be detailed enough that an implementer does not need to rediscover Contacts-dependent surfaces by searching the repository from scratch.

## 9. Assumptions

- This document prepares remaining feature implementation. It does not authorize direct code changes by itself.
- Current shared-framework docs and existing Contacts docs remain the architecture and product authorities.
- Future implementation proceeds with conservative, smaller PRs rather than a single large Contacts feature rollout.
- Verification accuracy refactor is a dedicated earlier PR.
- Certification projection, saved signature artifacts, and UX redesign are a dedicated capability PR.
- `.cypherair-contacts` package export/import is selected-contact exchange, not whole-domain recovery.
- Empty-install restore is out of scope for the remaining Contacts feature plan.
