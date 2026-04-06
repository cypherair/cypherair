# Contacts Product Requirements Document (PRD)

> **Version:** Draft v1.0  
> **Purpose:** Product requirements for the Contacts enhancement initiative.  
> **Audience:** Product, design, engineering, QA, and AI coding tools.  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific product direction.  
> **Companion document:** [CONTACTS_TDD](CONTACTS_TDD.md)  
> **Related document:** [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Product Intent

CypherAir's current Contacts capability is sufficient for a small number of imported public keys, but it is not yet structured for real-world relationship management, recurring recipient workflows, or social-graph-sensitive privacy requirements.

This document defines the product requirements for the next-generation Contacts capability. It exists so that later implementation work can rely on a complete, product-level specification without referring back to the older Contacts planning document.

The Contacts enhancement initiative covers four user-facing capability areas:

- Search
- Free-form tags
- Recipient lists
- Merge Contacts / multi-key contact management

The initiative also introduces a new privacy posture for Contacts storage:

- Contacts data is treated as social-graph-sensitive
- Contacts data is stored in a session-unlocked encrypted contacts vault
- Contacts vault recovery becomes an explicit product concern

## 2. Problem Statement

The current Contacts model has four major limitations:

1. Contacts and recipient selection are flat lists with no search.
2. There is no flexible organizational system for grouping contacts by context.
3. There is no reusable recipient-set model for repeated encryption workflows.
4. The current persistence model leaks too much about the user's local relationship graph.

Even though public keys are public artifacts, the set of keys retained on the device reveals who the user expects to communicate with. That makes Contacts a privacy-sensitive domain, not merely a convenience feature.

## 3. Goals And Non-Goals

### 3.1 Goals

The Contacts enhancement initiative must:

- make Contacts and Encrypt recipient selection searchable
- support free-form contact organization via tags
- support reusable recipient sets
- model contacts as people with one or more associated keys
- protect Contacts data using an encrypted, session-unlocked vault
- remain fully offline
- preserve a stable user-facing Contacts model despite a more advanced internal architecture
- provide an explicit recovery path for Contacts vault data

### 3.2 Non-Goals

This initiative does not include:

- network sync
- CloudKit
- system Contacts framework integration
- message format changes
- changes to private-key cryptography or Secure Enclave architecture
- redesign of the separate certification feature itself

This PRD assumes a future OpenPGP key certification capability will exist before Contacts implementation begins. Contacts integrates with that capability, but does not redefine its internal design in this document.

## 4. Core Product Model

### 4.1 ContactIdentity

A `ContactIdentity` represents a real-world person or relationship entry from the user's perspective. It is the stable entity the user manages.

Contact-level data belongs here:

- display-oriented relationship identity
- tags
- recipient list membership
- notes and future relationship metadata

### 4.2 ContactKeyRecord

A `ContactKeyRecord` represents one specific public key associated with a contact identity.

Key-level data belongs here:

- fingerprint
- key version and profile
- key algorithm metadata
- expiry / revocation state
- local manual verification state
- certification state provided by the certification feature

### 4.3 Key States

Within a single contact, keys are classified into three product states:

- **Preferred key**  
  The default key used when encrypting to this contact.

- **Additional active key**  
  A still-valid, still-encryptable key that belongs to the contact but is not the current preferred key.

- **Historical key**  
  A key retained for relationship continuity, signer recognition, or history mapping, but no longer used as a current encryption target.

Historical keys may include:

- replaced keys
- revoked keys
- expired keys
- keys intentionally retained for message history recognition

### 4.4 Verification Model

The Contacts feature uses a two-layer, per-key verification model.

#### Manual Verification

Manual verification is a local, user-asserted fingerprint-check state on each `ContactKeyRecord`.

It is currently represented by the existing product language:

- `Verify and Add`
- `Add as Unverified`
- later manual promotion from unverified to verified

This is not OpenPGP certification.

#### Certification

Certification is a separate, real OpenPGP key-certification capability that is expected to be introduced before Contacts implementation begins.

Contacts relies on that feature as a prerequisite and integrates its resulting state, but does not redefine its internal cryptographic design here.

#### Presentation Rule

Manual verification and certification must be presented as separate product signals. They must not be collapsed into one generic "verified" status.

## 5. Privacy, Security, And Recovery Position

### 5.1 Privacy Position

Contacts data is treated as social-graph-sensitive. This applies not only to tags and notes, but also to the possession of another person's public key.

### 5.2 Storage Position

The target persistence model is:

- one encrypted contacts vault file
- versioned
- stored under `Application Support`
- unlocked for the authenticated app session

The vault is the source of truth for Contacts data after migration completes.

### 5.3 Authentication Position

The Contacts vault follows app session authentication semantics:

- unlock after successful launch or resume authentication
- relock after app lock, session loss, or grace-period expiry

The Contacts vault does not mirror private-key per-operation gating and does not inherit the loss semantics of `Special Security Mode`.

### 5.4 Recovery Position

Contacts vault recovery is an explicit product responsibility.

The formal recovery direction for this initiative is:

- contacts vault export
- contacts vault import
- restoration of contact identities, keys, tags, recipient lists, preferred-key state, and verification metadata

System backup or device migration may still exist as environmental behavior, but they are not the sole product promise for Contacts recovery.

## 6. Search Requirements

### 6.1 Search Surfaces

Search must be available in:

- `Contacts`
- `Encrypt`

### 6.2 Search Inputs

Search must match against:

- contact display name
- contact email
- tag names
- full fingerprint
- short key ID

### 6.3 Search Result Ordering

The product must distinguish between:

- default list ordering
- search result ordering

#### Default Lists

Default lists use stable ordering:

`displayName -> email -> shortKeyId`

#### Search Results

Search results use tiered relevance:

1. exact match
2. prefix match
3. substring match

Stable ordering acts only as a tie-breaker inside a relevance tier.

Complex fuzzy search is not a first-version requirement.

## 7. Tag Requirements

### 7.1 Tag Semantics

Tags are free-form semantic labels applied at the `ContactIdentity` level.

Examples:

- work
- family
- legal
- audit
- temporary

### 7.2 Tag Management

Tags are primarily managed from Contacts surfaces.

Required user capabilities:

- add tags
- remove tags
- filter by tags
- see suggested existing tags when adding a tag

### 7.3 Tag Normalization

The first version must apply light normalization:

- trim surrounding whitespace
- collapse repeated internal spaces
- treat duplicates case-insensitively
- preserve the display casing of the first accepted form
- do not perform synonym merging

## 8. Recipient List Requirements

### 8.1 Recipient List Model

Recipient lists are reusable encryption recipient sets. They are not generic contact folders.

Recipient list membership binds to `ContactIdentity`, not directly to fingerprints.

### 8.2 Recipient List Behavior

Recipient lists must support:

- create
- rename
- delete
- add/remove contacts
- use in Encrypt

When a recipient list is used in Encrypt, each member resolves to that contact's preferred encryption key.

Historical keys are never used as recipient targets.

## 9. Candidate Matching, Import, And Merge

### 9.1 Candidate Matching Rules

The product distinguishes between strong and weak candidate matches.

#### Strong Candidate

A strong candidate exists when the imported key's normalized email exactly matches the normalized email of an existing contact.

Name is used only to improve user understanding of the prompt. Name alone never creates a candidate relationship.

#### Weak Candidate

A weak candidate exists when the imported key only shares weaker identity evidence, such as the same primary `userId` without a strong email match.

Weak candidates must never trigger automatic linking behavior.

### 9.2 Default Import Behavior

Import remains conservative by default.

When an imported key appears related to an existing contact:

- the default action is still to import it as a new contact
- the UI presents a prompt that it may be related to an existing contact
- the user can later merge contacts explicitly

The system must not auto-attach the key to an existing contact by default.

### 9.3 Import Confirmation Behavior

The import confirmation flow continues to own only **manual verification**, not certification.

During import, the user may:

- `Verify and Add`
- `Add as Unverified`

This continues to control only the per-key manual verification state.

Certification actions are not executed inside the import confirmation flow.

### 9.4 Merge Contacts

`Merge Contacts` is an in-scope product capability for this initiative.

Merge exists because the default import behavior is conservative and person-centered organization requires an explicit way to unify records later.

When two contacts are merged:

- their `ContactKeyRecord`s become part of one `ContactIdentity`
- tags are unified
- recipient list membership is unified
- verification and certification states remain attached to their individual keys

### 9.5 Preferred Key Prompt

When a contact gains another valid encryptable key:

- the app prompts the user that the preferred key may need review
- the user may switch preferred key immediately
- if the user does nothing, the current preferred key remains unchanged

The prompt is immediate, but the choice is not mandatory.

## 10. Decrypt And Verify Requirements

### 10.1 Decrypt With Locked Contacts Vault

Decrypt is split into:

- core content decryption
- contacts-aware signer recognition and verification enrichment

If the contacts vault is locked:

- content decryption may still complete
- the signature / signer-recognition area must enter an explicit pending state
- the UI must direct the user to unlock Contacts to complete verification
- the app must not silently degrade to `unknown signer`

### 10.2 Verify With Locked Contacts Vault

Independent Verify is different from Decrypt because its main value is verification itself.

If the contacts vault is locked and full contacts-aware verification requires contacts data:

- unlock is required before the verify result can complete
- if the user cancels or authentication fails, the verify flow does not continue

## 11. Contact Detail Requirements

The contact detail surface must support:

- viewing multiple keys under one contact
- seeing preferred vs additional vs historical keys
- manual verification actions
- certification actions
- preferred key management
- merge-related or post-merge cleanup actions as later detailed in TDD

Manual verification and certification must remain visibly distinct.

## 12. Migration Requirements

### 12.1 Migration Source

Migration source remains the legacy plaintext contacts storage:

- `.gpg` contact files
- `contact-metadata.json`

### 12.2 Migration Policy

Migration is automatic on first launch into the new Contacts architecture.

### 12.3 Quarantine And Deletion

After cutover succeeds:

- legacy plaintext data enters a quarantine state
- legacy plaintext is not kept as a permanent fallback
- final deletion happens only after the next successful opening of the new vault

This creates a safer rollback window than immediate deletion while still honoring the privacy goal of eliminating long-lived plaintext contacts storage.

## 13. Contacts Vault Export / Import

The Contacts initiative includes a formal export/import story for vault recovery.

The product must support:

- exporting contacts vault data into a portable recovery artifact
- importing that artifact later to restore Contacts state

The exact cryptographic packaging is a TDD concern, but product-level expectations are fixed:

- the export is user-driven
- the import restores Contacts state coherently
- recovery is not left as an implicit property of platform backup behavior alone

## 14. Authentication Mode Boundary

Contacts PRD must remain compatible with:

- `Standard`
- `High Security`
- `Special Security Mode`

Boundary rule:

- authentication modes define private-key access semantics
- the Contacts vault follows app session authentication semantics
- `Special Security Mode` does not redefine Contacts-vault recoverability or session unlock behavior

## 15. Acceptance Criteria

This initiative is product-complete only if all of the following are true:

- Contacts and Encrypt are searchable
- tags are usable and clean enough to stay manageable over time
- recipient lists are reusable and contact-identity-based
- users can merge contacts explicitly
- multi-key contacts are understandable in the UI
- preferred-key behavior is deterministic and user-controllable
- decrypt does not silently lose signer recognition when the vault is locked
- verify does not silently continue without full contacts-aware verification
- legacy plaintext storage is retired through quarantine and next-successful-open deletion
- contacts vault export/import exists in the product scope
- manual verification and certification are both represented clearly and separately

## 16. Product Scenarios

### Scenario A: Import A Possible Second Key

1. User imports a new key.
2. App detects an exact normalized email match with an existing contact.
3. App still imports the key as a new contact by default.
4. App informs the user that the new key may belong to an existing contact.
5. User can later merge the two contacts.

### Scenario B: Decrypt While Contacts Vault Is Locked

1. User decrypts a message successfully.
2. Plaintext is shown.
3. Contacts-aware signer recognition remains pending.
4. UI offers `Unlock Contacts to complete verification`.

### Scenario C: Verify While Contacts Vault Is Locked

1. User opens Verify.
2. Full contacts-aware verification requires Contacts data.
3. App asks the user to unlock Contacts.
4. If the user cancels, verification remains incomplete.

### Scenario D: Recover Contacts On A New Device

1. User exports Contacts vault recovery data.
2. User later imports it.
3. Contact identities, key records, tags, recipient lists, preferred-key state, and verification/certification integration state are restored coherently.

## 17. Out Of Scope For This Document

This document does not define:

- packet-level certification implementation
- the vault encryption wire format
- the exact export/import cryptographic packaging
- detailed service APIs
- persistence schema internals

Those topics belong in [CONTACTS_TDD](CONTACTS_TDD.md).
