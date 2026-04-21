# Contacts Product Requirements Document (PRD)

> **Version:** Draft v1.1  
> **Status:** Draft future product spec. This document does not describe current shipped Contacts behavior.  
> **Purpose:** Product requirements for the Contacts enhancement initiative as a Contacts domain built on the shared protected app-data framework.  
> **Audience:** Product, design, engineering, QA, and AI coding tools.  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](archive/CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific product direction.  
> **Companion document:** [CONTACTS_TDD](CONTACTS_TDD.md)  
> **Primary framework references:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)  
> **Related documents:** [APP_DATA_FRAMEWORK_SPEC](APP_DATA_FRAMEWORK_SPEC.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Product Intent

CypherAir's current Contacts capability is sufficient for a small number of imported public keys, but it is not yet structured for real-world relationship management, recurring recipient workflows, or social-graph-sensitive privacy requirements.

This document defines the product requirements for the next-generation Contacts capability. It describes the target Contacts experience after the shared protected app-data framework has already landed. In delivery order, Contacts adopts that framework in App Data Phase 4, after the reusable framework, file-protection baseline, and first low-risk domain have already been proven.

The Contacts enhancement initiative covers four user-facing capability areas:

- Search
- Free-form tags
- Recipient lists
- Merge Contacts / multi-key contact management

The initiative also defines the target privacy posture for Contacts:

- Contacts data is treated as social-graph-sensitive
- Contacts is implemented as a protected app-data domain, not as a second independent security architecture
- Contacts recovery remains an explicit product concern through importable offline recovery artifacts

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
- protect Contacts data as a shared-framework protected app-data domain
- reuse the shared app-data framework rather than invent a Contacts-specific vault base layer
- remain fully offline
- preserve a stable user-facing Contacts model despite a more advanced internal architecture
- provide an explicit import-based recovery path for Contacts data

### 3.2 Non-Goals

This initiative does not include:

- network sync
- CloudKit
- system Contacts framework integration
- message format changes
- changes to private-key cryptography or Secure Enclave architecture
- redesign of the shared protected app-data framework itself
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

- one logical Contacts protected domain inside the shared protected app-data framework
- encrypted Contacts payload generations stored under the framework's protected-domain storage rules
- one shared app-data authorization right as the normative session gate for protected app data
- one Contacts domain master key persisted only through the shared framework wrapped-DMK model
- no plaintext search indexes or derivative contact caches persisted outside the protected Contacts domain
- Contacts product data becomes the source of truth only after migration completes

Contacts does not own:

- the shared app-data right or secret
- registry authority
- wrapped-DMK lifecycle rules
- shared relock policy

User-facing copy may still use shorthand such as "Contacts vault," but the technical ownership model is a Contacts domain built on the shared app-data framework.

### 5.3 Authentication Position

The Contacts domain follows shared app-data session semantics:

- `AppSessionOrchestrator` owns the app-wide session boundary
- `ProtectedDataSessionCoordinator` owns shared app-data authorization under that boundary
- `first real Contacts access` means the first route in the current app session that actually needs to open Contacts protected-domain contents, not process launch by itself
- if launch/resume immediately continues into a Contacts-dependent route and the shared app-data session is inactive, that same orchestrated flow may authorize the shared right there
- completing launch/resume authentication alone does not imply that the shared app-data session is already active
- when that first Contacts access occurs inside launch/resume routing, the user-facing flow remains one understandable unlock step rather than a later second Contacts-specific prompt
- ordinary Contacts browsing, search, tag/list management, and recipient selection do not trigger a separate Contacts-specific routine prompt once the app-data session is active
- a second or third protected domain in the same active app-data session must not trigger another prompt merely because Contacts is opened later
- Contacts access relocks after app lock, session loss, grace-period expiry, or app exit
- exporting Contacts recovery data remains a high-risk externalization action and requires a fresh authentication immediately before export

Contacts does not mirror private-key per-operation gating and does not inherit the loss semantics of `Special Security Mode`. High-risk externalization actions such as export are treated separately from ordinary in-session use.

### 5.4 Recovery Position

Contacts domain recovery is an explicit product responsibility.

The formal recovery direction for this initiative is:

- Contacts remains an `import-recoverable` protected domain
- Contacts backup export and import restore contact identities, keys, tags, recipient lists, preferred-key state, and verification metadata
- portable recovery artifacts are protected by a user passphrase using a memory-hard KDF and authenticated encryption
- import restores Contacts state on a target installation while re-establishing fresh local protected-domain state there

Recovery ownership is layered:

- Contacts owns domain-scoped recovery behavior for unreadable Contacts payload or Contacts wrapped-DMK state
- the shared app-data framework owns framework-level recovery when registry or shared-resource state is unreadable, inconsistent, or unsafe
- framework-level recovery must not be misrepresented as Contacts-specific import recovery

### 5.5 Failure Position

Contacts failure states must remain explicit.

Required product behavior:

- a locked Contacts domain is presented as locked, not as an empty Contacts dataset
- unreadable Contacts domain state is presented as domain-scoped `recovery needed`
- shared-framework failure is presented as a framework-level unavailable or recovery-required state, not as a Contacts empty-state
- fail-closed relock failure that enters `restartRequired` blocks Contacts access until restart and is not misrepresented as Contacts data loss
- the app must not silently create a new empty Contacts domain or silently discard unreadable Contacts data

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

### 10.1 Decrypt With Contacts Domain Locked

Decrypt is split into:

- core content decryption
- contacts-aware signer recognition and verification enrichment

If the Contacts domain is locked because protected app-data access has not yet been authorized:

- content decryption may still complete
- the signature / signer-recognition area must enter an explicit pending state
- the UI must direct the user to unlock Contacts to complete verification
- the app must not silently degrade to `unknown signer`

### 10.2 Verify With Contacts Domain Locked

Independent Verify is different from Decrypt because its main value is verification itself.

If the Contacts domain is locked and full contacts-aware verification requires Contacts data:

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

### 12.2 Migration Order And Policy

Contacts migration belongs to App Data Phase 4.

Required preconditions:

- Phase 1 reusable protected app-data framework is already implemented
- Phase 2 file-protection baseline is already implemented
- Phase 3 first low-risk protected domain is already implemented

Contacts adoption and migration occur on the first Contacts-required protected-domain access into the new Contacts architecture. That access may happen during launch or resume if the initial route immediately needs Contacts data, and the same orchestrated unlock flow may activate the shared app-data session there.

Contacts migration must not be triggered merely because process launch or service initialization happened.

Contacts migration uses the shared framework create/write path. It does not define separate Contacts-specific rules for shared-right provisioning, first-domain creation, or last-domain cleanup.

### 12.3 Quarantine And Deletion

After cutover succeeds:

- legacy plaintext data enters a quarantine state
- legacy plaintext is not kept as a permanent fallback
- legacy plaintext is no longer loaded for search, recipient resolution, or routine Contacts display
- final deletion happens only after the next successful opening of the Contacts domain

This creates a safer rollback window than immediate deletion while still honoring the privacy goal of eliminating long-lived plaintext contacts storage.

## 13. Contacts Backup Export / Import

The Contacts initiative includes a formal export/import story for recovery.

The product must support:

- exporting a Contacts domain snapshot into a portable recovery artifact
- importing that artifact later to restore Contacts state

The exact cryptographic packaging is a TDD concern, but product-level expectations are fixed:

- the export is user-driven
- the export requires a fresh authentication immediately before backup generation
- the export requires a user passphrase and produces a passphrase-protected recovery artifact rather than raw local protected-domain files
- the export is delivered through the system file export/share flow so the user chooses where the offline backup is stored
- the export does not include the shared app-data secret, wrapped DMK records, registry state, or source-device authorization state
- the import restores Contacts state coherently
- the import re-establishes local protected-domain state on the target installation rather than transporting source-device authorization material
- recovery is not left as an implicit property of platform backup behavior alone

## 14. Authentication Mode Boundary

Contacts PRD must remain compatible with:

- `Standard`
- `High Security`
- `Special Security Mode`

Boundary rule:

- authentication modes define private-key access semantics
- protected app-data authorization policy is separate from private-key authentication mode
- the Contacts domain follows shared app-data session semantics
- authentication modes do not add a routine second prompt for ordinary Contacts use inside an already active app-data session
- the Contacts domain does not require mode-coupled rewrap when private-key authentication mode changes
- `Special Security Mode` does not redefine Contacts recoverability or shared app-data session behavior

## 15. Acceptance Criteria

This initiative is product-complete only if all of the following are true:

- Contacts and Encrypt are searchable
- tags are usable and clean enough to stay manageable over time
- recipient lists are reusable and contact-identity-based
- users can merge contacts explicitly
- multi-key contacts are understandable in the UI
- preferred-key behavior is deterministic and user-controllable
- if launch/resume immediately enters a Contacts-dependent protected route, the same orchestrated unlock flow may activate the shared app-data session without a later second Contacts-specific prompt
- entering Contacts or Encrypt during an already active protected app-data session does not trigger redundant Contacts-specific authentication prompts
- grace-period expiry or app lock relocks Contacts access explicitly
- decrypt does not silently lose signer recognition when the Contacts domain is locked
- verify does not silently continue without full contacts-aware verification
- legacy plaintext storage is retired through quarantine and next-successful-open deletion
- Contacts backup export/import exists in product scope
- Contacts backup export requires fresh authentication and produces a passphrase-protected recovery artifact
- passphrase-protected Contacts backup import restores state coherently on a new device or installation
- Contacts domain damage or unreadable Contacts wrapped-DMK state results in explicit Contacts `recovery needed` rather than an empty Contacts list
- framework-level protected-data failure is shown distinctly from Contacts domain recovery and is not misrepresented as a Contacts empty-state or Contacts import-only recovery path
- manual verification and certification are both represented clearly and separately

## 16. Product Scenarios

### Scenario A: Import A Possible Second Key

1. User imports a new key.
2. App detects an exact normalized email match with an existing contact.
3. App still imports the key as a new contact by default.
4. App informs the user that the new key may belong to an existing contact.
5. User can later merge the two contacts.

### Scenario B: Decrypt While Contacts Domain Is Locked

1. User decrypts a message successfully.
2. Plaintext is shown.
3. Contacts-aware signer recognition remains pending.
4. UI offers `Unlock Contacts to complete verification`.

### Scenario C: Verify While Contacts Domain Is Locked

1. User opens Verify.
2. Full contacts-aware verification requires Contacts data.
3. App asks the user to unlock Contacts.
4. If the user cancels, verification remains incomplete.

### Scenario D: Recover Contacts On A New Device

1. User exports Contacts recovery data.
2. User later imports it on a target installation.
3. Contact identities, key records, tags, recipient lists, preferred-key state, and verification/certification integration state are restored coherently.

### Scenario E: Launch Into Contacts-Protected Access

1. User cold-launches or resumes the app from a state that requires authentication.
2. The first route immediately needs Contacts protected-domain data.
3. `AppSessionOrchestrator` runs the user-visible unlock flow and hands off to shared app-data authorization for that first real Contacts access.
4. Contacts opens without a later second Contacts-specific prompt.
5. Later in the same active app-data session, opening recipient selection in `Encrypt` reuses that session.

### Scenario F: Use Contacts Within An Already Active App-Data Session

1. Earlier in the current app session, the user already completed shared app-data authorization by accessing a protected domain.
2. User opens `Contacts` and later opens recipient selection in `Encrypt`.
3. The app does not show another Contacts-specific authentication prompt.
4. If the grace period later expires, Contacts returns to an explicit locked state.

### Scenario G: Export Contacts Recovery Data

1. User opens the Contacts backup export action during an already active app-data session.
2. App requires a fresh authentication before generating the backup.
3. User enters a backup passphrase.
4. App produces a passphrase-protected portable recovery artifact and hands it to the system export flow so the user can choose where to save it.

### Scenario H: Contacts Domain Recovery Needed

1. App starts and the Contacts domain cannot be opened because the Contacts payload is damaged or the domain-specific wrapped-DMK state is unreadable.
2. `Contacts` does not appear empty.
3. The app presents an explicit Contacts `recovery needed` state.
4. The user is directed toward import-based recovery rather than silent reset.

### Scenario I: Protected App-Data Framework Recovery Blocks Contacts

1. App starts and the shared protected app-data framework cannot safely determine or use the shared authorization resource.
2. `Contacts` does not bypass that framework state independently.
3. The app presents a framework-level unavailable or recovery-required state.
4. The app does not mislabel that condition as a Contacts empty-state or a Contacts-specific import-only recovery path.

## 17. Out Of Scope For This Document

This document does not define:

- packet-level certification implementation
- shared protected app-data framework internals such as registry invariants, wrapped-DMK transactions, or relock state-machine mechanics
- the exact export/import cryptographic packaging
- detailed service APIs
- persistence schema internals

Those topics belong in [CONTACTS_TDD](CONTACTS_TDD.md) and the related `APP_DATA_*` framework documents.
