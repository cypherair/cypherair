# Contacts Technical Design Document (TDD)

> **Version:** Draft v1.1  
> **Status:** Draft future technical spec. This document does not describe current shipped Contacts implementation.  
> **Implementation note:** For this initiative, use this proposal document and its linked app-data / Contacts proposal companions as the primary implementation reference. Canonical current-state docs such as [SECURITY](SECURITY.md), [ARCHITECTURE](ARCHITECTURE.md), and [TESTING](TESTING.md) may temporarily lag and will be updated after implementation maturity.  
> **Purpose:** Technical design for implementing the Contacts enhancement initiative as a Contacts domain on the shared protected app-data framework.  
> **Audience:** Engineering, QA, and AI coding tools.  
> **Companion document:** [CONTACTS_PRD](CONTACTS_PRD.md)  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](archive/CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific technical direction.  
> **Primary framework references:** [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md) · [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md)  
> **Related documents:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Technical Scope

This document defines the implementation design for the Contacts enhancement initiative. It assumes the product direction in [CONTACTS_PRD](CONTACTS_PRD.md) is approved and fixed, and it assumes the shared protected app-data framework from the `APP_DATA_*` documents already exists before Contacts adoption begins.

This TDD covers:

- person-centered Contacts modeling
- Contacts domain payload schema and runtime model
- shared-framework integration for Contacts domain access
- search, tags, recipient lists, and merge behavior
- manual verification and certification integration
- migration, quarantine, and final legacy deletion
- Contacts domain export/import as a formal recovery path

This TDD does not redefine the shared protected app-data framework. The following remain owned by the `APP_DATA_*` documents:

- domain envelope rules
- wrapped-DMK persistence and transaction behavior
- `ProtectedDataRegistry` semantics
- shared root-secret activation and relock behavior
- framework-level recovery and `restartRequired`

This document also does not redesign the separate certification feature. It assumes certification capability exists before Contacts implementation begins and defines how Contacts consumes its results.

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
- explicit import-recoverable domain semantics
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
- `certificationState`
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

This state is provided by the certification subsystem, which is assumed to exist before Contacts implementation begins.

Contacts consumes certification state at the `ContactKeyRecord` level. Contacts does not define the packet-level certification mechanism in this document.

The minimum integration requirement is that Contacts can distinguish:

- certified
- not certified

The certification subsystem may expose richer technical states, but Contacts surfaces must at minimum support a user-facing certified/not-certified distinction.

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

Contacts must never present `frameworkUnavailable` as an empty dataset or as a Contacts import-recovery screen.

### 7.4 Domain Write And Recovery Responsibilities

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
3. after shared app-data session activation succeeds, the Contacts DMK may lazy-unlock and the framework may select an authoritative readable generation
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
3. `first real protected-domain access` means the first route in the current app session that actually needs protected-domain content, not process launch by itself
4. on first real Contacts access, if the shared app-data session is inactive, the orchestrator asks `ProtectedDataSessionCoordinator` to retrieve the shared root secret through an authenticated `LAContext`
5. if launch/resume immediately continues into a Contacts-dependent route, that same orchestrated flow may reuse the launch/resume `LAContext` for root-secret retrieval rather than surfacing a later second Contacts-specific prompt
6. after shared app-data session activation succeeds, the Contacts domain DMK may lazy-unlock through framework-owned key management
7. `ContactService` opens the Contacts domain snapshot and derived in-memory indexes

Completing launch/resume authentication alone does not imply that the shared app-data session is already active unless root-secret retrieval and wrapping-root-key derivation also succeeded.

Ordinary Contacts browsing, search, tag/list management, and recipient selection reuse the active shared app-data session and do not trigger a Contacts-specific second prompt.

### 8.3 Relock And Cleanup

Contacts does not own relock policy, but it does own domain-local cleanup obligations.

On relock, Contacts must register a `ProtectedDataRelockParticipant` that clears or zeroizes:

- decrypted Contacts snapshot data in memory
- serialization scratch buffers that held plaintext snapshot bytes
- in-memory search indexes
- contacts-aware signer-recognition lookup state

The framework owns:

- closing new protected-domain access
- zeroizing the derived wrapping root key and unwrapped domain DMKs
- discarding any session-local `LAContext` retained only for the unlock transaction
- latching `restartRequired` on unsafe relock failure

If the framework enters `restartRequired`, Contacts must treat that as `frameworkUnavailable` until restart and must not attempt an independent in-process recovery path.

### 8.4 Export Authentication Boundary

Contacts backup export is a high-risk externalization action.

Required behavior:

- export requires a currently available and unlocked Contacts domain
- export requires a fresh authentication immediately before snapshot generation
- export serializes Contacts business data, not framework artifacts
- import requires framework availability and an unlocked app session but does not require a routine second prompt beyond session unlock unless a later product decision adds one

## 9. Decrypt And Verify Integration

### 9.1 Decrypt

Decrypt is split into:

- core decryption
- contacts-aware verification enrichment

If the Contacts domain is locked:

- core plaintext decryption may complete
- signer recognition and contact-aware verification remain pending
- UI shows `Unlock Contacts to complete verification`
- there is no silent fallback to `unknown signer`

If the framework is unavailable:

- core decryption behavior remains governed by the decrypt subsystem
- Contacts enrichment does not bypass framework state
- the UI must distinguish framework unavailability from ordinary Contacts lock state

### 9.2 Verify

Independent verify requires full contacts-aware context to complete its intended behavior.

If the Contacts domain is locked:

- unlock is required before final verify completion
- if unlock fails or is canceled, verify stops

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

Contacts assumes a pre-existing certification feature and integrates with it.

Contacts-side requirements:

- each `ContactKeyRecord` stores a certification projection used by Contacts surfaces
- each stored certification projection includes enough source reference or revision information for later reconciliation
- contact detail exposes certification actions
- import flow does not perform certification
- unlock and import flows may trigger reconciliation against the certification subsystem so stale projected state can be corrected
- Contacts surfaces keep manual verification and certification visually separate

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

Contacts migration occurs only after the earlier AppData roadmap phases are already satisfied, including shared framework prerequisites, post-unlock multi-domain hardening, `private-key-control`, `key metadata`, and non-Contacts protected-after-unlock work.

The cutover trigger is the first Contacts-required protected-domain access after the Contacts protected-domain adoption point is reached. That access may occur during launch or resume if the initial route immediately needs Contacts data, but migration must not be triggered merely by process launch or service initialization.

Migration sequence:

1. confirm the shared protected app-data framework, file-protection baseline, and first low-risk domain are already present
2. read legacy files
3. build the new person-centered graph and canonical Contacts snapshot
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

## 12. Contacts Domain Export / Import

The Contacts subsystem must provide a first-class export/import path.

### 12.1 Export Package

Export produces a portable recovery artifact rather than a copy of raw local protected-domain files.

Required export envelope fields:

- export format version
- Argon2id parameters
- random nonce
- ciphertext
- AEAD authentication tag
- minimal metadata required to validate and open the export package

The encrypted export payload restores:

- contact identities
- key records
- tags
- recipient lists
- preferred-key selection
- manual verification state
- certification integration state as exposed to the Contacts subsystem

Export encryption requirements:

- require a user passphrase for every export
- derive the export encryption key with the app's canonical Argon2id backup profile
- encrypt the export payload with `AES.GCM`
- never export the shared app-data root secret, Contacts wrapped-DMK record, `ProtectedDataRegistry` state, source-device authorization state, or other framework-owned recovery artifacts

### 12.2 Export Flow

Export flow:

1. require a currently unlocked Contacts domain inside an available app-data session
2. require a fresh authentication immediately before export
3. serialize a canonical Contacts snapshot from unlocked runtime state
4. derive an export key from the user passphrase using Argon2id
5. encrypt the snapshot into the versioned export envelope
6. write a temporary export file for the system file exporter / Share Sheet
7. delete the temporary export file after completion or cancellation

The implementation must reuse the existing memory-safety posture for Argon2id-backed operations and refuse import-time Argon2id parameters that exceed the app's memory guard threshold.

### 12.3 Import Flow

Import flow:

1. open the portable recovery artifact
2. validate the encoded Argon2id parameters against the memory guard before key derivation
3. derive the export key from the user passphrase
4. decrypt and parse the exported Contacts snapshot
5. ask the shared framework to create or write the Contacts domain on the target installation
6. if the target installation has no protected domains yet, let the framework own any required first-domain provisioning
7. write the imported snapshot as fresh local Contacts domain state and validate post-auth readability

Import restores Contacts contents into a new or explicitly replaced Contacts domain on the target installation. The source device's local authorization material is never migrated.

## 13. Service Architecture

The UI continues to depend on a single `ContactService` facade.

Planned Contacts-owned components:

- `ContactService`
- `ContactsDomainRepository`
- `ContactsMigrationCoordinator`
- `ContactsSearchIndex`

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

Minimum supporting internal types:

- `ContactsDomainSnapshot`
- `ContactsDomainSchemaVersion`
- `ContactsAvailability`

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
- certification remains per-key
- contact detail exposes both layers distinctly

### 14.4 Shared Access And Locked State

- locked Contacts domain produces explicit `Contacts` locked state
- locked Contacts domain produces explicit `Encrypt` locked recipient state
- decrypt completes plaintext while verification stays pending
- verify requires unlock
- unlock cancel/failure results in hard stop for verify
- if launch/resume immediately enters Contacts-required protected access, the same orchestrated flow retrieves the shared root secret and activates the shared app-data session before Contacts opens
- launch/resume authentication alone is not treated as an already active app-data session unless root-secret retrieval also completed
- ordinary Contacts use within an already active app-data session does not trigger redundant prompts
- if another protected domain already activated the shared session, opening Contacts does not prompt again
- framework-level blocked state is surfaced distinctly from Contacts domain recovery
- export requires fresh authentication and cancellation produces no offline backup file

### 14.5 Domain Integrity And Recovery

- unreadable Contacts wrapped-DMK state enters Contacts domain-scoped `recoveryNeeded`
- unreadable authoritative Contacts payload enters Contacts domain-scoped `recoveryNeeded`
- shared-resource or registry failure enters framework-level recovery and blocks Contacts
- startup recovery from framework-managed `pending / current / previous` state is deterministic
- unreadable Contacts state never silently resets to an empty dataset
- relock clears Contacts in-memory search and signer-recognition state through relock-participant cleanup
- `restartRequired` is treated as framework-level blocked state, not as Contacts data loss

### 14.6 Migration And Recovery

- Contacts adoption occurs only after App Data Phase 1-3 prerequisites
- Contacts migration is triggered by first Contacts-required protected-domain access, not by process launch or service initialization alone
- target Contacts domain is validated before legacy source retirement
- quarantine storage is inactive for normal Contacts resolution
- final deletion happens only after next successful Contacts domain open
- interrupted migration recovers deterministically
- export/import restores Contacts state coherently
- import with wrong passphrase fails gracefully
- export/import never transports the shared root secret, wrapped-DMK record, registry state, or source-device authorization state
- if target-install first-domain provisioning is required during import, the framework owns it

### 14.7 Search And Tags

- exact/prefix/substring ranking tiers work as specified
- tag normalization prevents common duplicates
- key ID and fingerprint exact matches rank correctly

## 15. Out Of Scope For This Document

This document does not define:

- the internals of the certification feature
- the final localized UI copy for passphrase education and recovery messaging
- shared protected app-data framework internals such as registry invariants, wrapped-DMK transactions, root-secret lifecycle, or framework recovery classification
- implementation details for unrelated canonical documents outside the Contacts initiative
