# Contacts Technical Design Document (TDD)

> **Version:** Draft v1.0  
> **Status:** Draft future technical spec. This document does not describe current shipped Contacts implementation.
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
- contacts-vault cryptographic container and vault-key protection
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
- no plaintext derivative caches persisted outside the encrypted vault
- session-authenticated contacts access
- deterministic behavior for multi-key contacts
- conservative identity-linking behavior
- explicit recovery path for user data
- deterministic crash recovery with no silent reset to an empty vault
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

Primary on-disk artifacts:

- `contacts.vault` - current authoritative generation
- `contacts.vault.previous` - previous readable generation retained for rollback
- `contacts.vault.pending` - transient staging file during write or startup recovery

The vault payload contains:

- `ContactIdentity` records
- `ContactKeyRecord` records
- recipient lists
- normalized tag representations or equivalent
- certification projection state and reconciliation metadata
- vault metadata

No plaintext search index, tag cache, recipient-resolution cache, or signer-recognition cache may be persisted outside the encrypted vault payload.

### 7.2 Cryptographic Container

`contacts.vault` is stored as a versioned envelope.

Required envelope fields:

- vault format version
- vault-wrap version
- generation counter
- random 96-bit nonce
- ciphertext
- AEAD authentication tag
- minimal pre-decryption metadata required for deterministic recovery

Cryptographic requirements:

- encrypt the serialized vault payload with `AES.GCM` using `contactsVaultMasterKey`
- bind envelope metadata through AEAD associated data
- any header mismatch, AEAD tag failure, or associated-data mismatch is a hard failure
- unreadable ciphertext must not produce partial plaintext or partial runtime state

### 7.3 Runtime Model

Runtime state is loaded from the vault after successful contacts-vault unlock.

The unlocked runtime state contains:

- contact graph
- key graph
- recipient list graph
- search index
- contacts-aware signer-recognition lookup cache

`ContactService` exposes three runtime states:

- `locked`
- `unlocked`
- `recoveryNeeded`

`recoveryNeeded` is entered when no readable vault generation can be recovered or the local wrapped master key cannot be unwrapped.

### 7.4 Write And Recovery Model

`ContactsVaultStore` is a single-writer subsystem.

Write sequence:

1. mutate unlocked in-memory model
2. serialize a canonical vault snapshot
3. encrypt the payload into a new envelope using the next generation counter and a fresh random nonce
4. write the envelope to `contacts.vault.pending`
5. read back `contacts.vault.pending`, decrypt it, and parse it to verify structural readability before promotion
6. atomically promote the existing `contacts.vault` to `contacts.vault.previous`
7. atomically promote `contacts.vault.pending` to `contacts.vault`
8. remove stale pending artifacts only after successful promotion

Startup recovery sequence:

1. inspect `current`, `previous`, and `pending`
2. attempt to open each candidate using the local wrapped master key
3. keep only structurally valid, decryptable generations
4. select the highest readable generation as authoritative
5. select the next-highest readable generation, if any, as `previous`
6. if no readable generation exists or the local wrapped master key cannot be unwrapped, enter `recoveryNeeded`

The implementation must never silently create a new empty vault because a previous generation is unreadable.

## 8. Vault Key And Session Lifecycle

### 8.1 Vault Key

`contactsVaultMasterKey` is a random 256-bit symmetric key.

The master key is never stored in plaintext. It is wrapped using a dedicated Secure Enclave wrapping key and a contacts-specific wrapping context.

Required Keychain namespace:

- `com.cypherair.contacts.v1.vault-se-key`
- `com.cypherair.contacts.v1.vault-salt`
- `com.cypherair.contacts.v1.vault-sealed-master-key`
- `com.cypherair.contacts.v1.vault-metadata`

Required properties:

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for all vault-key Keychain items
- a contacts-specific wrap version distinct from private-key wrapping
- a contacts-specific HKDF info string such as `CypherAir-Contacts-Vault-Wrap-v1`
- device-bound local protection that does not attempt to survive device migration, backup restore, or Secure Enclave loss

This document does not redefine the final certification feature or private-key access-control implementation. It does define the contacts-vault lifecycle:

- session-auth-gated
- not per-operation gated
- not rewrapped when private-key authentication mode changes
- not bound to private-key loss semantics from `Special Security Mode`

### 8.2 Unlock Lifecycle

The vault unlocks after successful app launch or resume authentication.

`ContactsVaultKeyManager` unwraps `contactsVaultMasterKey` once per authenticated app session by reusing the authenticated context from the launch or resume authentication path. Ordinary Contacts browsing, search, tag/list management, and recipient selection reuse this in-memory session unlock and do not trigger an additional Contacts-specific prompt.

The vault relocks when:

- app lock occurs
- session expires
- grace period expires
- app exits

Relock invalidates:

- in-memory `contactsVaultMasterKey`
- decrypted vault contents in memory
- serialization scratch buffers that held plaintext vault bytes
- in-memory search indexes
- contacts-aware signer-recognition lookup state

All sensitive buffers listed above must be zeroized rather than merely dereferenced.

### 8.3 Export Authentication Boundary

Contacts backup export is treated as a high-risk externalization action.

Required behavior:

- export requires an already unlocked Contacts session
- export requires a fresh authentication immediately before snapshot generation
- import requires an unlocked app session but does not require a second fresh-auth prompt beyond session unlock

### 8.4 Locked-State And Recovery UX Contract

Locked and unrecoverable vault states are explicit.

Required runtime/UI contract:

- `Contacts` shows a locked state, not an empty state
- `Encrypt` shows locked recipient state, not an empty recipient list
- actions that need unlocked Contacts data are blocked or placed into pending state according to product rules
- `Contacts` shows a `recoveryNeeded` state when the local vault cannot be opened and no readable fallback generation exists
- `recoveryNeeded` offers import-based recovery guidance rather than silent reset

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
- old plaintext is not loaded into normal search, recipient selection, or Contacts display paths during quarantine
- final deletion requires one later successful vault-open confirmation

### 11.4 Interrupted Migration

If migration is interrupted:

- old storage remains authoritative until cutover is proven
- quarantine state must be distinguishable from active legacy state
- later recovery logic must be deterministic and idempotent

## 12. Contacts Vault Export / Import

The Contacts subsystem must provide a first-class export/import path.

### 12.1 Export Package

Export produces a portable recovery artifact rather than a copy of the raw local vault file.

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
- never export the local device-bound wrapped master key or any source-device Secure Enclave wrapping material

### 12.2 Export Flow

Export flow:

1. require a currently unlocked Contacts session
2. require a fresh authentication immediately before export
3. serialize a canonical contacts snapshot from unlocked runtime state
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
4. decrypt and parse the exported contacts snapshot
5. generate a brand-new local `contactsVaultMasterKey` on the target installation
6. wrap the new local master key with the target device's dedicated Secure Enclave wrapping key
7. write the imported snapshot as a fresh local vault generation

Import restores vault contents into a new contacts vault on the target device or installation. The source device's local wrapping material is never migrated.

## 13. Service Architecture

The UI continues to depend on a single `ContactService` facade.

Planned subsystem components:

- `ContactService`
- `ContactsVaultStore`
- `ContactsVaultKeyManager`
- `ContactsMigrationCoordinator`
- `ContactsSearchIndex`

Responsibilities:

- `ContactService`: UI-facing state, orchestration, and `locked` / `unlocked` / `recoveryNeeded` runtime state
- `ContactsVaultStore`: vault-envelope encode/decode, atomic generation promotion, and startup recovery
- `ContactsVaultKeyManager`: local vault-key creation, Secure Enclave wrapping, session unlock/relock behavior, export fresh-auth enforcement, and memory zeroization
- `ContactsMigrationCoordinator`: legacy import, quarantine, and final cleanup flow
- `ContactsSearchIndex`: in-memory search and ranking over unlocked contacts data

Minimum supporting internal types:

- `ContactsVaultEnvelopeHeader`
- `ContactsVaultGeneration`
- `ContactsVaultRecoveryState`

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
- ordinary Contacts use within an already authenticated app session does not trigger redundant prompts
- export requires fresh authentication and cancellation produces no offline backup file

### 14.5 Vault Integrity And Recovery

- incorrect AEAD tag hard-fails
- incorrect envelope header or associated data hard-fails
- local wrapped master-key unwrap failure enters `recoveryNeeded`
- startup recovery from `pending` / `current` / `previous` is deterministic
- unreadable vault never silently resets to an empty dataset
- relock zeroizes in-memory search and signer-recognition state

### 14.6 Migration And Recovery

- cutover succeeds
- quarantine is created
- quarantine storage is inactive for normal Contacts resolution
- final deletion happens only after next successful vault open
- interrupted migration recovers deterministically
- export/import restores contacts state coherently
- import with wrong passphrase fails gracefully

### 14.7 Search And Tags

- exact/prefix/substring ranking tiers work as specified
- tag normalization prevents common duplicates
- key ID and fingerprint exact matches rank correctly

## 15. Out Of Scope For This Document

This document does not define:

- the internals of the certification feature
- the final localized UI copy for passphrase education and recovery messaging
- implementation details for unrelated canonical documents outside the Contacts initiative
