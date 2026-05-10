# Contacts Technical Design Document (TDD)

> **Version:** Draft v1.3
> **Status:** Current Contacts domain design for implemented PR5/6/8 behavior plus future expansion boundaries. Current protected-domain security/storage behavior is owned by the current-state architecture, security, TDD, testing docs, and persisted-state inventory.
> **Purpose:** Technical design for implementing the Contacts enhancement initiative as a Contacts domain on the shared protected app-data framework.  
> **Audience:** Engineering, QA, and AI coding tools.  
> **Companion document:** [CONTACTS_PRD](CONTACTS_PRD.md)  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](archive/CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific technical direction.  
> **Primary framework references:** [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TDD](TDD.md)
> **Related documents:** [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) · [TESTING](TESTING.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Technical Scope

This document defines the implementation design for the Contacts enhancement initiative. It assumes the product direction in [CONTACTS_PRD](CONTACTS_PRD.md) is approved and fixed, and it assumes the shared ProtectedData framework plus the Contacts PR4 protected-domain security/storage cutover documented in the current architecture, security, TDD, and testing guides already exist before remaining Contacts feature work begins.

This TDD covers:

- person-centered Contacts modeling
- Contacts domain payload schema and runtime model
- shared-framework integration for Contacts domain access
- search, tags, recipient lists, and merge behavior
- manual verification and certification integration
- migration, quarantine, and final legacy deletion
- the boundary that withdraws Contacts package exchange and defers full Contacts backup to a separate mandatory encrypted design

This TDD does not redefine the shared ProtectedData framework. The following remain owned by the current shared-framework documentation:

- domain envelope rules
- wrapped-DMK persistence and transaction behavior
- `ProtectedDataRegistry` semantics
- shared root-secret activation and relock behavior
- framework-level recovery and `restartRequired`

This document does not redefine packet-level OpenPGP certification cryptography. It does define how Contacts owns the certification projection, saved certification artifacts, and user-facing certification workflow around the existing certificate-signature service.

## 2. Design Principles

The implementation must satisfy these principles:

- person-centered contact management
- offline-only operation
- no plaintext source of truth for the Contacts domain after migration
- no plaintext derivative caches persisted outside the protected Contacts domain
- Contacts is a domain-specific consumer of the shared protected app-data framework, not a second security architecture
- shared-session-authenticated Contacts access rather than Contacts-owned session ownership
- deterministic behavior for multi-key contacts
- conservative identity-linking behavior
- no unencrypted or optionally encrypted export of complete Contacts social-graph state
- full Contacts backup and device migration deferred to a separate mandatory encrypted design
- deterministic crash recovery with no silent reset to an empty Contacts domain
- stable UI dependency through a single `ContactService` facade

## 3. Domain Model

### 3.1 ContactIdentity

`ContactIdentity` is the stable local person/relationship entity.

Required conceptual fields:

- `contactId`
- `displayName`
- `primaryEmail` (optional)
- `tagIds` or normalized tag set
- `recipientListMembership` (derived or modeled externally)
- note field placeholder for future use
- timestamps for creation/update

`ContactIdentity` is the owner of all relationship-level data.

### 3.2 ContactKeyRecord

`ContactKeyRecord` is the per-key entity belonging to a `ContactIdentity`.

Required conceptual fields:

- `keyId` (internal stable record identifier)
- `contactId`
- `fingerprint`
- `primaryUserId`
- parsed `displayName`
- parsed `email`
- `keyVersion`
- `profile`
- `primaryAlgo`
- `subkeyAlgo`
- `hasEncryptionSubkey`
- `isRevoked`
- `isExpired`
- `manualVerificationState`
- `certificationProjection`
- saved certification artifact references for this key or User ID
- `usageState`
- timestamps

### 3.3 Key Usage State

Each `ContactKeyRecord` has one of three usage states:

- `preferred`
- `additionalActive`
- `historical`

Rules:

- only one key per contact may be `preferred`
- `preferred` and `additionalActive` must be currently encryptable
- `historical` keys are excluded from recipient resolution
- revoked or expired keys must not remain `preferred`

### 3.4 RecipientList

Recipient lists bind to contact identities, not fingerprints.

Required conceptual fields:

- `recipientListId`
- `name`
- ordered display metadata as needed
- member `contactId` set
- timestamps

Recipient resolution happens at send time by converting each `contactId` into that contact's current preferred encryptable key.

### 3.5 Verification State

Contacts uses a dual-layer per-key verification model.

#### Manual Verification State

This is the current local user-asserted fingerprint-check state.

Initial state:

- `verified` when the user chooses `Verify and Add`
- `unverified` when the user chooses `Add as Unverified`

This state is local-only and does not imply OpenPGP certification.

#### Certification State

Certification state is Contacts-owned projection over real OpenPGP certification signatures.

Contacts persists both a user-facing projection and the saved certification signature artifacts needed to inspect, export, and revalidate that projection later.

The minimum projection requirement is that Contacts can distinguish:

- certified
- not certified
- certification present but currently invalid or stale
- certification material present but requiring revalidation

Manual verification and certification are never collapsed. A manually verified contact key may still have no OpenPGP certification, and a saved OpenPGP certification does not imply that the local manual fingerprint-check state is `verified`.

## 4. Identity Linkage And Import Semantics

### 4.1 Normalized Fields

The implementation must define normalized matching helpers:

- normalized email = trimmed + lowercased parsed email
- normalized tag = trim outer whitespace + collapse repeated spaces + case-insensitive uniqueness

The Contacts feature must not rely on names as a primary identity key.

### 4.2 Candidate Match Rules

#### Strong Candidate

A strong candidate exists when the imported key's normalized email exactly matches the normalized email of an existing `ContactIdentity`.

If multiple identities produce the same strong match, the result is treated as ambiguous and must not auto-link.

#### Weak Candidate

A weak candidate exists when only weaker signals exist, such as the same primary `userId` without a strong normalized email match.

Weak candidates never auto-link.

### 4.3 Import Default

The default import action is conservative:

- create a new `ContactIdentity`
- create a new `ContactKeyRecord`
- preserve the imported key as its own contact entry

The system may then present:

- a strong-candidate prompt
- a weak-candidate prompt

But it does not automatically attach the key to an existing contact.

### 4.4 Import Verification Behavior

Import confirmation continues to own only manual verification state.

Import actions:

- `Verify and Add` -> `manualVerificationState = verified`
- `Add as Unverified` -> `manualVerificationState = unverified`

Certification actions are not part of import flow execution.

### 4.5 Merge Contacts

Merge is an explicit supported operation.

When merging contact A into contact B:

- one `ContactIdentity` survives
- all `ContactKeyRecord`s are reassigned to the surviving identity
- tags are unioned
- recipient list membership is unioned
- notes and future freeform fields must use deterministic merge rules in implementation

Deterministic default merge rules:

- surviving `ContactIdentity` is the merge target selected by the user
- tags are unioned
- recipient-list membership is unioned
- key records are unioned

Manual verification and certification states remain attached to the original key records.

## 5. Preferred Key Resolution

### 5.1 Preferred Key Rules

Each contact must have at most one preferred key.

Recipient resolution rules:

- use the `preferred` key if it is encryptable
- never use `historical` keys
- if no encryptable preferred key exists, the contact is not currently encryptable until resolved

### 5.2 Adding A New Valid Key

When a contact gains another valid encryptable key through merge or later reassignment:

- the app prompts the user that preferred-key selection may need review
- if the user does nothing, the current preferred key remains unchanged
- the new valid key becomes `additionalActive` by default

### 5.3 Invalid Preferred Key

If a preferred key becomes non-encryptable because it is revoked, expired, or otherwise unusable:

- it must be moved out of `preferred`
- if exactly one other encryptable key exists, that key becomes `preferred`
- if multiple other encryptable keys exist, the app must require the user to choose a new preferred key before future recipient resolution succeeds
- if no encryptable keys remain, the contact remains valid for history/signer recognition but is not selectable as an encryption recipient

### 5.4 Historical Keys

`historical` keys continue to participate in:

- signer recognition
- history mapping
- relationship continuity

They do not participate in:

- Encrypt recipient resolution
- recipient list key resolution

## 6. Search And Tag Rules

### 6.1 Search Ranking

Default lists use:

`displayName -> email -> shortKeyId`

Search results use tiered relevance:

1. exact match
2. prefix match
3. substring match

Tie-breakers use stable ordering.

Matching inputs:

- display name
- email
- tags
- full fingerprint
- short key ID

### 6.2 Tag Normalization

Tags are normalized as follows:

- trim outer whitespace
- collapse repeated internal whitespace into single spaces
- case-insensitive duplicate suppression
- preserve the display casing of the first accepted form
- no synonym resolution

Normalization is applied at write time, not only at display time.

## 7. Contacts Domain On Protected App-Data Framework

### 7.1 Domain Storage Model

The Contacts source of truth is one protected app-data domain managed through the shared framework. User-facing product copy may continue to say "Contacts vault," but the technical design uses Contacts protected-domain terminology.

The row-level persisted-state classification for the Contacts payload, legacy cleanup-only sources, runtime-only indexes, and export/temp exceptions lives in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). This TDD defines Contacts domain semantics and no-plaintext-cache rules.

Storage ownership is split as follows.

Framework-owned storage mechanics:

- protected-domain directory location
- `current / previous / pending` generation mechanics
- encrypted domain envelope rules
- wrapped-DMK persistence and validation
- per-domain bootstrap metadata
- registry membership and lifecycle authority

Contacts-owned domain content:

- canonical Contacts snapshot payload
- Contacts schema versioning
- Contacts-specific decode and validation rules
- no-plaintext-derivative-cache rule for Contacts business data

No plaintext search index, tag cache, recipient-resolution cache, or signer-recognition cache may be persisted outside the encrypted Contacts domain payload.

### 7.2 Canonical Payload

The Contacts domain payload is a single canonical snapshot.

The payload contains:

- `ContactIdentity` records
- `ContactKeyRecord` records
- recipient lists
- normalized tag representations or equivalent
- certification projection state and reconciliation metadata
- saved certification signature artifact metadata and protected payload references
- Contacts domain metadata

Contacts owns the snapshot schema. The framework owns how that snapshot is encrypted, staged, promoted, reopened, and recovered on disk.

### 7.3 Runtime Model And Availability Mapping

The unlocked runtime state contains:

- contact graph
- key graph
- recipient list graph
- search index
- contacts-aware signer-recognition lookup cache

`ContactService` derives its availability from framework session state plus Contacts domain runtime state. The minimum user-visible distinctions are:

- `locked`: the framework is healthy, but the Contacts domain is not currently open in memory
- `unlocked`: the framework session is authorized and the Contacts domain snapshot is open in memory
- `recoveryNeeded`: the framework is healthy enough to route domain access, but the Contacts domain itself cannot open a readable authoritative state
- `frameworkUnavailable`: framework-level blocked state such as `frameworkRecoveryNeeded` or `restartRequired`

In normal app use, `locked` is a boundary state rather than a long-lived state after app authentication. Once `AppSessionOrchestrator` completes privacy authentication, shared post-unlock orchestration should open registered protected domains, including Contacts. `locked` remains visible when authentication is canceled, the app relocks, the session is unavailable, or the domain has not yet finished opening.

Contacts must never present `frameworkUnavailable` as an empty dataset or as a Contacts package-import screen.

### 7.4 Domain Write And Failure Responsibilities

`ContactsDomainRepository` is the single-writer subsystem for Contacts business data.

Write sequence at the Contacts layer:

1. mutate unlocked in-memory model
2. serialize a canonical Contacts snapshot
3. hand the snapshot to the shared framework write path
4. rely on the framework to encrypt, stage, validate, and promote generations according to the shared `current / previous / pending` contract
5. rebuild in-memory derived state from the committed authoritative snapshot

Startup and recovery boundary:

1. before shared app-data session activation, Contacts may consult only framework-readable bootstrap inputs such as registry state and minimal per-domain bootstrap metadata
2. before shared app-data session activation, Contacts must not attempt to open domain payload generations
3. after shared app-data session activation succeeds, shared post-unlock orchestration opens the Contacts domain and the framework may select an authoritative readable generation
4. Contacts then validates schema and business invariants for the selected snapshot
5. if no readable authoritative Contacts state exists, the Contacts domain enters `recoveryNeeded`

Contacts never silently creates a new empty domain because prior local state is unreadable.

## 8. Shared Session And Domain Access Lifecycle

### 8.1 Shared Authorization Dependency

Contacts depends on the shared app-data root-secret activation model defined by the framework.

Required rules:

- Contacts uses the framework-owned shared Keychain root-secret gate as the normative session gate
- Contacts depends on one Contacts domain DMK under that shared gate
- Contacts never provisions or deletes the shared root secret or derived wrapping root key directly
- Contacts never decides first-domain provisioning or last-domain cleanup itself
- Contacts authorization policy does not derive from private-key `AuthenticationMode`

### 8.2 Unlock Lifecycle

`AppSessionOrchestrator` is the only app-wide session owner.

`ProtectedDataSessionCoordinator` is the only owner of shared app-data root-secret retrieval.

Contacts access follows this order:

1. the app enters `AppSessionOrchestrator`
2. if app session is not active, `AppSessionOrchestrator` completes app-level privacy unlock first
3. the app-authenticated `LAContext` is passed to shared post-unlock protected-domain orchestration when available
4. `ProtectedDataSessionCoordinator` retrieves the shared root secret and derives the wrapping root key through the framework-owned path
5. `ProtectedDataPostUnlockCoordinator` opens or ensures committed registered protected domains, including Contacts
6. `ContactService` opens the Contacts domain snapshot and derived in-memory indexes
7. route-level Contacts UI consumes `ContactsAvailability` rather than calling plaintext load paths

Completing launch/resume authentication alone does not imply that Contacts is available unless root-secret retrieval, wrapping-root-key derivation, and Contacts domain open also succeeded.

During PR1-PR3 compatibility work before protected-domain cutover, this same route-level contract gates any legacy compatibility projection that `ContactService` exposes. Legacy compatibility reads are not a protected Contacts source of truth and do not replace the PR4 migration/readability/cutover boundary.

Ordinary Contacts browsing, search, tag/list management, and recipient selection reuse the active shared app-data session and do not trigger a Contacts-specific second prompt.

### 8.3 Relock And Cleanup

Contacts does not own relock policy, but it does own domain-local cleanup obligations.

On relock, Contacts must register a `ProtectedDataRelockParticipant` that clears or zeroizes:

- decrypted Contacts snapshot data in memory
- serialization scratch buffers that held plaintext snapshot bytes
- in-memory search indexes
- contacts-aware signer-recognition lookup state
- all `ContactService`-exposed runtime state, including any PR1-PR3 compatibility projection, manual-verification runtime map, and derived lookup/cache state

The framework owns:

- closing new protected-domain access
- zeroizing the derived wrapping root key and unwrapped domain DMKs
- discarding any session-local `LAContext` retained only for the unlock transaction
- latching `restartRequired` on unsafe relock failure

If the framework enters `restartRequired`, Contacts must treat that as `frameworkUnavailable` until restart and must not attempt an independent in-process recovery path.

### 8.4 Contact Export And Backup Boundary

Contacts package export/import is withdrawn from the active design because even public-key-only multi-contact packages externalize relationship and public-key possession information.

Required behavior:

- no `.cypherair-contacts` package format, package import preview, package commit, or multi-contact export is specified by this TDD
- ordinary public certificate import remains an existing public-key import path, not a Contacts package exchange feature
- PR6 certification-signature export/share remains a certification artifact action, not a Contacts backup or package exchange feature
- any future full Contacts backup or device-migration feature must be separately designed and must require encryption; plaintext or optional-encryption export of complete Contacts state is not allowed

## 9. Decrypt And Verify Integration

### 9.1 Decrypt

Decrypt is split into:

- core decryption
- signature packet detection
- certificate-backed signature verification when a suitable verification certificate is available
- contacts-aware signer recognition and trust/certification enrichment

Issuer/key-handle metadata from a signature packet is not a Contacts identity clue. Contacts enrichment uses only certificate-backed signer fingerprints and must not turn unverified signature metadata into a signer identity.

If Contacts verification context is unavailable because Contacts is locked, opening, recovering, or framework-unavailable:

- core plaintext decryption may complete
- signer recognition may remain unavailable
- signature verification must not be reported as completed unless a suitable verification certificate was actually available
- UI shows the most precise state available, such as Contacts context unavailable, signer certificate unavailable, or verification pending protected-data unlock
- there is no silent fallback to `unknown signer`

If the framework is unavailable:

- core decryption behavior remains governed by the decrypt subsystem
- Contacts enrichment does not bypass framework state
- the UI must distinguish framework unavailability from ordinary Contacts lock state

### 9.2 Verify

Independent verify requires full contacts-aware context to complete its intended behavior.

If Contacts verification context is unavailable and the verify route requires it:

- app-data unlock may be requested when it can make Contacts context available
- if unlock fails or is canceled, verify reports that required verification context is unavailable
- verify never reports a completed contacts-aware verification result by silently omitting Contacts-provided certificates

If the framework is unavailable:

- verify does not route through Contacts domain recovery
- the UI shows framework-level blocked state

### 9.3 Signer Recognition Sources

Signer recognition must consider:

- current preferred key
- additional active keys
- historical keys

This is required so that old signatures can still resolve to the same `ContactIdentity`.

## 10. Certification Integration Contract

Contacts uses the existing low-level certificate-signature service but owns the redesigned certification workflow, projection, and protected persistence.

Contacts-side requirements:

- each `ContactKeyRecord` stores certification projection used by Contacts surfaces
- each stored certification projection includes enough source reference, target selector, signer identity, and revision information for later revalidation
- valid imported or locally generated certification signature artifacts are saved as protected Contacts data
- contact detail exposes a compact trust/certification summary
- contact detail exposes the common `Certify This Contact` action without embedding the full advanced tool surface
- a redesigned certification details surface exposes saved history, exportable signature material, raw details, and secondary external signature import/verification actions
- import flow does not perform certification
- saved certification signature artifacts may be imported only through explicit certification signature preview/save flows that validate them before saving projection state
- unlock and certification artifact mutation flows may trigger revalidation so stale projected state can be corrected
- Contacts surfaces keep manual verification and certification visually separate

The redesigned workflow must cover the capabilities of the current three-mode page without preserving that UI model:

- direct-key signature verification
- User ID binding signature verification
- text/file import of external certification signatures
- generation of a certification over a contact User ID using one of the user's private keys
- export/share of generated certification signatures
- signer identity resolution
- target certificate selector validation
- certification-kind display

Contacts does not define:

- certification packet format
- signing flow internals
- certification cryptographic policy

Those belong to the certification feature itself.

## 11. Migration Design

### 11.1 Source

Legacy source:

- `.gpg` contact files
- `contact-metadata.json`

### 11.2 Migration Phases

Contacts security/storage migration occurs after the earlier shared-framework prerequisites are already satisfied, including protected app-data framework setup, post-unlock multi-domain hardening, `private-key-control`, `key metadata`, and completed non-Contacts protected-after-unlock work. Those prerequisites are complete, Contacts PR4 has implemented the protected `contacts` domain cutover for the flat compatibility snapshot, and Contacts PR5/6/8 behavior now runs over that protected domain. Future Contacts expansion still follows the Contacts-specific implementation plan.

The implemented PR4 cutover trigger is the first post-auth Contacts domain open with an authorized ProtectedData session. This may occur during launch/resume post-unlock orchestration. Migration must not be triggered merely by process launch or service initialization before app-data authorization.

Migration sequence:

1. confirm the shared protected app-data framework, file-protection baseline, and first low-risk domain are already present
2. read legacy files
3. build the canonical Contacts snapshot; the implemented PR4 path preserves the flat compatibility model, while later feature work expands the person-centered graph
4. create or write the Contacts domain through the shared framework create/write path
5. validate target Contacts domain readability through the normal post-auth open path
6. switch source of truth to the Contacts domain
7. move legacy plaintext into quarantine state
8. delete legacy plaintext only after the next successful Contacts domain open

Contacts migration does not directly provision the shared app-data root secret. It also does not infer first-domain or last-domain lifecycle from Contacts-local state.

### 11.3 Quarantine

Quarantine requirements:

- old plaintext is no longer treated as active source of truth
- old plaintext is not deleted immediately on first cutover success
- old plaintext remains available only as a short rollback safety window
- old plaintext is not loaded into normal search, recipient selection, or Contacts display paths during quarantine
- final deletion requires one later successful Contacts domain open confirmation

### 11.4 Interrupted Migration

If migration is interrupted:

- old storage remains authoritative until Contacts domain cutover is proven
- quarantine state must be distinguishable from active legacy state
- later recovery logic must be deterministic and idempotent
- any framework `pendingMutation` or Contacts domain generation cleanup resumes under the shared framework recovery rules rather than a Contacts-specific parallel mechanism

## 12. Contacts Backup And Exchange Boundary

The earlier plan for a first-class Contacts package exchange format is withdrawn. This TDD no longer defines a `.cypherair-contacts` package, Apple Archive-backed Contacts container, package manifest, package import preview, package commit, or multi-contact export.

Ordinary OpenPGP public certificate import remains available through the existing public-key import path. That path inspects external public key material and commits through normal Contacts mutations; it is not a Contacts package, backup, restore, or forwarding feature.

PR6 certification-signature export/share remains available for saved certification artifacts. That export is scoped to certification signature material and must not be treated as a Contacts backup or contact package.

Full Contacts backup or device migration remains deferred. If introduced later, it must be a separate mandatory encrypted backup design. Plaintext or optional-encryption export of complete Contacts state, including contact groupings, local labels, tags, notes, recipient lists, manual verification state, certification history, or protected-domain metadata, is not allowed by this TDD.

## 13. Service Architecture

The UI continues to depend on a single `ContactService` facade.

Planned Contacts-owned components:

- `ContactService`
- `ContactsDomainRepository`
- `ContactsMigrationCoordinator`
- `ContactsSearchIndex`
- `ContactsCertificationStore` or equivalent certification-record repository

Framework-owned dependencies consumed by Contacts:

- `AppSessionOrchestrator`
- `ProtectedDataSessionCoordinator`
- `ProtectedDomainKeyManager`
- `ProtectedDataRegistryStore`
- `ProtectedDomainRecoveryCoordinator`

Responsibilities:

- `ContactService`: UI-facing state, orchestration, availability mapping from framework state plus Contacts domain state, and user actions
- `ContactsDomainRepository`: canonical snapshot encode/decode, Contacts schema validation, translation between snapshot and runtime graphs, and delegation into the shared framework storage path
- `ContactsMigrationCoordinator`: legacy import, quarantine, and final cleanup flow
- `ContactsSearchIndex`: in-memory search and ranking over unlocked Contacts data plus relock-time cleanup participation
- `ContactsCertificationStore`: persistence and revalidation of certification projections and saved signature artifacts inside the Contacts protected domain

Minimum supporting internal types:

- `ContactsDomainSnapshot`
- `ContactsDomainSchemaVersion`
- `ContactsAvailability`
- `ContactCertificationRecord`

Vault-specific infrastructure types such as dedicated vault envelope headers, vault-key managers, or Contacts-owned recovery state machines are not the authoritative design for this round.

## 14. Validation Matrix

### 14.1 Identity And Merge

- strong candidate detection via normalized email exact match
- weak candidate handling via manual link only
- default import remains new contact
- merge preserves all key records
- merge preserves per-key verification/certification state

### 14.2 Multi-Key Behavior

- preferred key prompt appears when a second valid key becomes available
- existing preferred remains if user does nothing
- historical keys remain usable for signer recognition
- historical keys are excluded from encryption recipient resolution

### 14.3 Verification And Certification

- import flow handles manual verification only
- manual verification remains per-key
- certification projection remains per-key and may target specific User ID selectors
- contact detail exposes both layers distinctly
- Contact Detail shows a compact trust/certification summary and common `Certify This Contact` action
- certification details surface covers saved history, exportable signature artifacts, raw details, and secondary external signature import/verification
- the redesigned certification workflow covers direct-key verification, User ID binding verification, external signature import, user certification generation, generated-signature export/share, signer identity resolution, selector validation, and certification-kind display
- valid certification projection and saved signature artifacts persist as protected Contacts data

### 14.4 Shared Access And Locked State

- app authentication followed by post-unlock orchestration opens Contacts in normal app use
- locked Contacts domain remains an explicit boundary state for cancellation, relock, opening, recovery, or framework unavailability
- locked Contacts domain produces explicit `Contacts` locked/opening state when it is visible
- locked Contacts domain produces explicit `Encrypt` locked/opening recipient state when it is visible
- decrypt may complete plaintext while signer recognition or signature verification context stays unavailable
- decrypt and verify never claim completed signature verification without a suitable verification certificate
- verify reports required verification context unavailable when unlock is canceled or cannot provide Contacts context
- launch/resume post-unlock orchestration retrieves the shared root secret and activates the shared app-data session before Contacts opens
- launch/resume authentication alone is not treated as Contacts availability unless root-secret retrieval and Contacts open also completed
- ordinary Contacts use within an already active app-data session does not trigger redundant prompts
- if another protected domain already activated the shared session, opening Contacts does not prompt again
- framework-level blocked state is surfaced distinctly from Contacts domain recovery

### 14.5 Domain Integrity And Recovery

- unreadable Contacts wrapped-DMK state enters Contacts domain-scoped `recoveryNeeded`
- unreadable authoritative Contacts payload enters Contacts domain-scoped `recoveryNeeded`
- shared-resource or registry failure enters framework-level recovery and blocks Contacts
- startup recovery from framework-managed `pending / current / previous` state is deterministic
- unreadable Contacts state never silently resets to an empty dataset
- relock clears Contacts in-memory search, signer-recognition, and `ContactService` runtime / compatibility projection state through relock-participant cleanup
- `restartRequired` is treated as framework-level blocked state, not as Contacts data loss

### 14.6 Migration And Backup Boundary

- Contacts PR4 protected-domain security/storage cutover occurs after AppData Phase 1-7 prerequisites are complete; remaining person-centered feature work still follows the Contacts-specific implementation plan
- Contacts migration is triggered by post-auth protected-domain open, not by process launch or service initialization before app-data authorization
- target Contacts domain is validated before legacy source retirement
- quarantine storage is inactive for normal Contacts resolution
- final deletion happens only after next successful Contacts domain open
- interrupted migration recovers deterministically
- Contacts PR7 package exchange remains withdrawn and does not define package import/export behavior
- future complete Contacts backup or device migration is out of scope and must be mandatory encrypted if specified later

### 14.7 Search And Tags

- exact/prefix/substring ranking tiers work as specified
- tag normalization prevents common duplicates
- key ID and fingerprint exact matches rank correctly

## 15. Out Of Scope For This Document

This document does not define:

- packet-level OpenPGP certification cryptography
- a Contacts package exchange format or UI
- a complete Contacts backup, restore, or device-migration format
- shared protected app-data framework internals such as registry invariants, wrapped-DMK transactions, root-secret lifecycle, or framework recovery classification
- implementation details for unrelated canonical documents outside the Contacts initiative
