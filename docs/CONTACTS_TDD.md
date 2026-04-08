# Contacts Technical Design Document (TDD)

> **Version:** Draft v1.0  
> **Purpose:** Technical design for implementing the Contacts enhancement initiative.  
> **Audience:** Engineering, QA, and AI coding tools.  
> **Companion document:** [CONTACTS_PRD](CONTACTS_PRD.md)  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](archive/CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific technical direction.  
> **Related document:** [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Technical Scope

This document defines the implementation design for the Contacts enhancement initiative. It assumes the product direction in [CONTACTS_PRD](CONTACTS_PRD.md) is approved and fixed.

This TDD covers:

- person-centered Contacts modeling
- multi-key contact support
- contacts vault architecture
- search, tags, recipient lists, and merge behavior
- manual verification and certification integration
- migration, quarantine, and final legacy deletion
- contacts vault export/import as a formal recovery path

This document does not redesign the separate certification feature. It assumes certification capability exists before Contacts implementation begins and defines how Contacts consumes its results.

## 2. Design Principles

The implementation must satisfy these principles:

- person-centered contact management
- offline-only operation
- no plaintext source of truth for the Contacts domain after migration
- session-authenticated contacts access
- deterministic behavior for multi-key contacts
- conservative identity-linking behavior
- explicit recovery path for user data
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

## 7. Contacts Vault Architecture

### 7.1 Storage Model

The Contacts domain source of truth is one encrypted, versioned contacts vault file stored under `Application Support`.

The vault contains:

- `ContactIdentity` records
- `ContactKeyRecord` records
- recipient lists
- normalized tag representations or equivalent
- vault metadata

### 7.2 Runtime Model

Runtime state is loaded from the vault after successful contacts-vault unlock.

The unlocked runtime state contains:

- contact graph
- key graph
- recipient list graph
- search index

### 7.3 Write Model

Write sequence:

1. mutate unlocked in-memory model
2. serialize a new vault payload
3. encrypt the payload
4. write to a temporary file
5. verify structural readability
6. atomically replace the current vault

## 8. Vault Key And Session Lifecycle

### 8.1 Vault Key

The contacts vault master key is Keychain-protected.

This document does not redefine the final certification feature or private-key access-control implementation. It does define the contacts-vault lifecycle:

- session-auth-gated
- not per-operation gated
- not bound to private-key loss semantics from `Special Security Mode`

### 8.2 Unlock Lifecycle

The vault unlocks after successful app launch or resume authentication.

The vault relocks when:

- app lock occurs
- session expires
- grace period expires
- app exits

Relock invalidates:

- decrypted vault contents in memory
- in-memory search indexes
- contacts-aware signer-recognition lookup state

### 8.3 Locked-State UX Contract

Locked vault state is explicit.

Required runtime/UI contract:

- `Contacts` shows a locked state, not an empty state
- `Encrypt` shows locked recipient state, not an empty recipient list
- actions that need unlocked Contacts data are blocked or placed into pending state according to product rules

## 9. Decrypt And Verify Integration

### 9.1 Decrypt

Decrypt is split into:

- core decryption
- contacts-aware verification enrichment

If the contacts vault is locked:

- core plaintext decryption may complete
- signer recognition and contact-aware verification remain pending
- UI shows `Unlock Contacts to complete verification`
- no silent fallback to `unknown signer`

### 9.2 Verify

Independent verify requires full contacts-aware context to complete its intended behavior.

If the contacts vault is locked:

- unlock is required before final verify completion
- if unlock fails or is canceled, verify stops

### 9.3 Signer Recognition Sources

Signer recognition must consider:

- current preferred key
- additional active keys
- historical keys

This is required so that old signatures can still resolve to the same `ContactIdentity`.

## 10. Certification Integration Contract

Contacts assumes a pre-existing certification feature and integrates with it.

Contacts-side requirements:

- each `ContactKeyRecord` stores certification state from the certification system
- contact detail exposes certification actions
- import flow does not perform certification
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

1. Read legacy files
2. Build new person-centered graph
3. Create encrypted vault
4. Validate vault readability
5. Switch source of truth to new vault
6. Move legacy plaintext into quarantine state
7. Delete legacy plaintext only after the next successful vault open

### 11.3 Quarantine

Quarantine requirements:

- old plaintext is no longer treated as active source of truth
- old plaintext is not deleted immediately on first cutover success
- old plaintext remains available only as a short rollback safety window
- final deletion requires one later successful vault-open confirmation

### 11.4 Interrupted Migration

If migration is interrupted:

- old storage remains authoritative until cutover is proven
- quarantine state must be distinguishable from active legacy state
- later recovery logic must be deterministic and idempotent

## 12. Contacts Vault Export / Import

The Contacts subsystem must provide a first-class export/import path.

Minimum technical direction:

- export produces a portable recovery artifact
- import restores vault contents into a new contacts vault on the target device or installation
- restored state must include:
  - contact identities
  - key records
  - tags
  - recipient lists
  - preferred-key selection
  - manual verification state
  - certification integration state as exposed to the Contacts subsystem

The exact packaging and passphrase/keying model remains an implementation detail, but export/import is not optional.

## 13. Service Architecture

The UI continues to depend on a single `ContactService` facade.

Planned subsystem components:

- `ContactService`
- `ContactsVaultStore`
- `ContactsVaultKeyManager`
- `ContactsMigrationCoordinator`
- `ContactsSearchIndex`

Responsibilities:

- `ContactService`: UI-facing state and orchestration
- `ContactsVaultStore`: encrypted vault read/write and atomic replacement
- `ContactsVaultKeyManager`: vault key access and session unlock/relock behavior
- `ContactsMigrationCoordinator`: legacy import, quarantine, and final cleanup flow
- `ContactsSearchIndex`: in-memory search and ranking over unlocked contacts data

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

### 14.4 Locked Vault

- locked vault produces explicit `Contacts` locked state
- locked vault produces explicit `Encrypt` locked state
- decrypt completes plaintext while verification stays pending
- verify requires unlock
- unlock cancel/failure results in hard stop for verify

### 14.5 Migration And Recovery

- cutover succeeds
- quarantine is created
- final deletion happens only after next successful vault open
- interrupted migration recovers deterministically
- export/import restores contacts state coherently

### 14.6 Search And Tags

- exact/prefix/substring ranking tiers work as specified
- tag normalization prevents common duplicates
- key ID and fingerprint exact matches rank correctly

## 15. Out Of Scope For This Document

This document does not define:

- the internals of the certification feature
- the final vault cryptographic container format
- passphrase UX for export/import
- implementation details for unrelated canonical documents outside the Contacts initiative
