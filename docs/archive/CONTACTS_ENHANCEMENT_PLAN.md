# Contacts Enhancement Plan

> Archived historical planning document. Superseded by [`CONTACTS_PRD.md`](CONTACTS_PRD.md) and [`CONTACTS_TDD.md`](CONTACTS_TDD.md).

> Purpose: Master planning document for the next-generation Contacts capability in CypherAir.
> Audience: Product authors, technical design authors, human developers, and AI coding tools.
> Status: Planning baseline only. This document does not indicate that any described functionality has been implemented.
> Follow-on documents: Future Contacts-specific PRD and TDD documents must derive their scope and assumptions from this plan.

## 1. Purpose And Status

This document defines the agreed direction for enhancing the Contacts capability in CypherAir. It is the authoritative planning baseline for future contacts-related documentation work and is intended to be expanded later into:

- A product-focused document that formalizes user experience, prioritization, workflows, and acceptance criteria
- A technical design document that formalizes interfaces, persistence format, lifecycle rules, migration behavior, and validation detail

This document is intentionally positioned between a lightweight plan and a fully elaborated product or technical specification. It captures the decisions that should remain stable while later documents add more detail. It is not a progress report, implementation guide for completed work, or statement that the current application already behaves this way.

The scope of this planning effort is limited to documentation. The existence of this document must not be interpreted as permission to modify product code, storage, or security behavior until a separate implementation step is explicitly requested.

## 2. Current State Assessment

### 2.1 Current Contacts Model

The current Contacts capability is built as a flat list of imported OpenPGP public keys. A contact is derived primarily from key material and key metadata rather than from a rich application-managed relationship model. The application currently supports:

- Public key import from paste, file, QR photo, and URL-based QR exchange flows
- Duplicate detection based on fingerprint
- Key replacement detection when the same User ID appears with a different fingerprint
- A binary verification state that indicates whether the user has verified the fingerprint out of band
- Recipient selection for encryption by choosing from the full contact list
- Signer recognition by matching message signatures against imported public keys

The current persistence model stores contact certificates as individual `.gpg` files and stores lightweight local metadata in a companion JSON file:

- `Documents/contacts/*.gpg`
- `Documents/contacts/contact-metadata.json`

This approach is simple and functional for a small number of contacts, but it reflects an MVP storage model rather than a long-term information architecture.

### 2.2 Current UX Limitations

The current UX has meaningful scaling and organization gaps.

In `Contacts`:

- The list is flat and unstructured
- There is no search
- There are no labels or categories
- There is no way to define reusable subsets of contacts
- The list becomes harder to scan as contact count grows

In `Encrypt`:

- Recipient selection is also a flat presentation of contacts
- There is no search or filtering support
- There is no way to quickly select a common working set of recipients
- The cognitive load increases as soon as the user has more than a small handful of contacts

### 2.3 Why The Current Model Is Insufficient

The current model is insufficient because Contacts has evolved from a simple public-key repository into a user-facing organizational surface. Once the user begins to manage real people, multiple contexts, and recurring recipient sets, a flat list stops being enough.

Three pressures are already visible:

1. **Retrieval pressure**: users need to find a contact quickly in both Contacts and Encrypt.
2. **Organization pressure**: users need a way to describe and filter contacts across multiple dimensions such as work, family, audit, testing, or temporary collaboration.
3. **Workflow pressure**: users need reusable recipient sets for repeated encryption tasks.

At the same time, the current persistence model exposes too much about the user's relationship graph. Even though public keys are public artifacts, the set of keys that a user chooses to retain locally can reveal a meaningful social graph.

## 3. Goals And Non-Goals

### 3.1 Goals

The Contacts enhancement effort has five primary goals:

1. Make contacts searchable in the places where retrieval matters most.
2. Introduce free-form, multi-dimensional tags for flexible organization.
3. Introduce recipient lists for repeated encryption workflows.
4. Strengthen the privacy posture of contact storage to better protect relationship metadata and social-graph inference.
5. Preserve a stable UI-facing boundary through a single `ContactService` facade even as the internal implementation becomes more structured.

### 3.2 Non-Goals

This effort does not include the following:

- No network sync of contacts, labels, lists, or vault state
- No CloudKit integration
- No use of the system Contacts framework or traditional address-book folders
- No change to the existing private-key protection architecture
- No new permissions
- No change to encryption profile behavior, message format selection, or decryption authenticity guarantees
- No immediate product code implementation as part of this document-writing round

### 3.3 Design Constraints

The Contacts enhancement direction must continue to respect CypherAir's core product constraints:

- Fully offline operation
- Minimal permissions
- Stable import confirmation and fingerprint verification reminders
- No logging of sensitive contact-derived relationship information
- Compatibility with the current import and encryption workflow model

## 4. Product Direction

The enhancement direction is intentionally phased so that future implementation can deliver value incrementally while preserving a coherent long-term model.

| Phase | Capability | Primary User Problem | Primary Surfaces |
|------|------------|----------------------|------------------|
| 1 | Search | "I cannot quickly find the right contact." | `Contacts`, `Encrypt` |
| 2 | Tags | "I need to organize contacts across multiple contexts." | `Contacts`, `Contact Detail`, `Encrypt` filtering |
| 3 | Recipient Lists | "I repeatedly encrypt to the same group of people." | Managed in `Contacts`, used in `Encrypt` |

### 4.1 Phase 1: Search

Search is the first capability because it solves the most immediate scaling problem with the least conceptual overhead.

Search must be available in:

- `Contacts`
- `Encrypt`

Search behavior must be defined as follows:

- Case-insensitive matching
- Real-time local filtering
- Search fields include:
  - display name
  - email
  - full fingerprint
  - short key ID
  - tag names once tags exist
- Result ordering must remain stable and deterministic

The baseline ordering rule is:

`displayName -> email -> shortKeyId`

This ordering rule applies both to default listings and to filtered search results unless a later PRD explicitly defines a different ranking model.

### 4.2 Phase 2: Tags

Tags are defined as free-form semantic labels rather than fixed categories. A single contact may belong to multiple conceptual groupings at the same time.

Examples of intended tag usage include:

- work
- family
- audit
- legal
- testing
- temporary
- verified in person

Tags are not the same thing as recipient lists. A tag answers the question "what kind of contact is this?" A recipient list answers the question "who do I often encrypt to together?"

Tag behavior must be defined as follows:

- Tags are user-defined and free-form
- The UI may suggest existing tags to reduce duplication
- A contact may have multiple tags
- Tags are primarily managed from Contacts surfaces
- `Contact Detail` is the editing surface for an individual contact's tags
- Contacts lists must support tag-based filtering
- Encrypt may later expose light tag-based filtering, but tag management remains centered in Contacts

### 4.3 Phase 3: Recipient Lists

Recipient lists are reusable recipient sets for repeated encryption tasks. They are intentionally distinct from tags and are not meant to function as generic contact folders.

Typical use cases include:

- Regular communication with a fixed work team
- Sharing the same encrypted report with a recurring audit group
- Reusing a small family recipient set
- Repeating a testing or review distribution list

Recipient list behavior must be defined as follows:

- Recipient lists are created, edited, renamed, and deleted from Contacts management surfaces
- Encrypt consumes recipient lists for quick recipient selection
- Encrypt does not become the primary management surface for list maintenance
- Recipient lists are sets, not ordered lists
- Duplicate members are not allowed
- Applying a recipient list in Encrypt never bypasses existing recipient validity rules

The minimum conceptual fields for a recipient list are:

- Stable identifier
- User-editable name
- De-duplicated member fingerprint set

## 5. Security And Privacy Model

### 5.1 Threat Model Assumption

This plan assumes that the Contacts domain contains privacy-sensitive information even when the underlying key material is public.

The sensitive information is not limited to notes or tags. The very fact that a user possesses another person's public key can reveal:

- relationship existence
- organizational affiliation
- project membership
- social proximity
- communication frequency or grouping patterns

This means the Contacts dataset should be treated as a social-graph-bearing asset rather than as a collection of harmless public files.

### 5.2 Why Public Keys Still Need Protection In Context

A contact certificate may be public in isolation, but local retention changes its meaning. A device that stores a curated set of public keys is storing evidence of who the user expects to communicate with, which can be sensitive even when each individual certificate is not secret.

The current storage model exposes this information more than desired:

- individual file existence reveals contact count
- certificate filenames can reveal stable identity-linked fingerprints
- companion metadata reveals user-defined organization
- flat storage makes relationship reconstruction easier if the sandbox contents are obtained

For this reason, the Contacts enhancement effort treats the complete contacts dataset as privacy-sensitive.

### 5.3 Target Protection Model

The target protection model is a **session-unlocked encrypted contacts vault**.

This means:

- Contacts data is stored encrypted at rest
- The vault is unlocked after the app completes its existing launch or resume authentication flow
- The vault remains available during the authenticated session
- The vault is relocked when the app exits, locks, or exceeds the configured grace period

This model intentionally balances privacy and usability:

- stronger privacy than plain app-managed structured storage
- better usability than prompting for biometrics every time the user opens Contacts or Encrypt
- better fit for social-graph-sensitive data than partial protection of only labels or metadata

This model is explicitly tied to the app's authenticated session rather than to per-view or per-operation access. The vault is not assumed to be synchronously available as plaintext at cold launch before authentication has succeeded. Instead, vault availability follows the app's launch and resume authentication lifecycle.

### 5.4 Explicitly Rejected Alternatives

The following approaches are intentionally not the target architecture:

#### `SwiftData` As Contacts Source Of Truth

`SwiftData` is not the target source of truth for Contacts because this effort prioritizes privacy of the entire contacts dataset, not only convenience of app-managed structure. A plaintext or lightly protected structured store is not a strong fit for data that may reveal social-graph information even through filenames, counts, or queryable metadata.

#### Per-Operation Secure Enclave Gating

Private-key operations justify per-operation gating because they protect secret signing and decryption material. Contacts access has a very different usage pattern. Requiring a private-key-style biometric gate for every contacts or recipient-selection action would create excessive friction and would not match the intended user experience of browsing, searching, filtering, and selecting contacts during a single authenticated session.

### 5.5 Key Protection Direction

The vault's master key is expected to be protected by Keychain. The session-unlocked model allows the app to reuse existing app authentication rather than introducing a second persistent prompts layer for normal Contacts use.

At the planning level, the required semantics are:

- the vault master key is Keychain-protected
- the vault follows session-auth-gated behavior tied to app launch and resume authentication
- the vault does not adopt the private-key model of per-operation gating
- the vault is not intended to inherit private-key loss semantics after biometric enrollment changes

This means the contacts vault should be treated as part of the app's authenticated working session, not as a second copy of the private-key protection model.

This document does not define the final cryptographic container format in implementation detail. That is a future TDD concern. It does define the required security posture:

- encrypted at rest
- session-scoped unlock
- no plaintext contacts source of truth on disk
- no reopening of the storage direction in future documents unless explicitly re-approved

Future TDD work must still define the concrete Keychain policy details, including accessibility class, `ThisDeviceOnly` behavior, and the exact relationship between vault-key accessibility, `requireAuthOnLaunch`, and grace-period relocking. However, those later details must remain inside the direction established here: the contacts vault is session-auth-gated and does not follow the private-key survivability semantics of authentication modes.

### 5.6 Relationship To Authentication Modes

The contacts vault design must remain compatible with a future world in which the app exposes three authentication modes:

- `Standard`
- `High Security`
- `Special Security Mode`

The contacts vault does not redefine those modes and does not change their private-key behavior. Instead, the planning assumption is:

- authentication modes continue to govern private-key access semantics
- the contacts vault continues to follow app session authentication semantics
- `Special Security Mode` may strengthen private-key access guarantees, but it does not change the contacts vault into a biometric-enrollment-bound asset that becomes unrecoverable after enrollment reset

This boundary is important. The contacts vault protects social-graph-sensitive relationship data, but it is still intended to unlock and relock with the app's authenticated session rather than mirror the recoverability profile of private keys.

## 6. Storage And Data Model Direction

### 6.1 Target Storage Model

The target persistence model is a **single versioned encrypted contacts vault file** stored under `Application Support`.

This target model replaces the current architecture of:

- `Documents/contacts/*.gpg`
- `Documents/contacts/contact-metadata.json`

The new vault becomes the sole source of truth for the Contacts domain.

### 6.2 Vault Contents

The vault must contain all data needed to fully reconstruct Contacts behavior at runtime, including:

- raw public key material
- verification state
- free-form tags
- recipient lists
- future-compatible fields such as:
  - notes
  - creation timestamps
  - update timestamps
  - future local organization metadata

At the planning level, the vault should be understood as a versioned container over a logical model composed of:

- contact entries
- organization metadata
- recipient list definitions
- vault metadata needed for evolution and migration

### 6.3 Write Model

To avoid partial-state bugs and multi-file consistency hazards, the write model is fixed as:

1. Load and unlock vault into runtime memory
2. Apply the in-memory mutation
3. Serialize a new vault payload
4. Encrypt the new payload
5. Write to a temporary file
6. Verify the newly written file is readable and structurally valid
7. Atomically replace the current vault

This model is chosen to minimize torn-state behavior and to create a clear recovery boundary.

### 6.4 Why Single-File Vault Was Chosen

Single-file encrypted storage was chosen over multi-file encrypted storage for four reasons:

1. **Stronger privacy**: one opaque vault leaks less about the contact graph than many per-contact files.
2. **Simpler consistency**: one atomic replacement path is easier to reason about than a payload-and-index graph.
3. **Easier migration**: the old storage model can be imported into one new container and cut over conservatively.
4. **Lower implementation risk**: fewer opportunities for orphaned files, stale indexes, or partially updated membership relationships.

This does mean every logical mutation rewrites the vault. That trade-off is acceptable because Contacts is expected to be read-heavy, write-light, and moderate in scale.

### 6.5 Versioning Expectations

The vault must be versioned from the start. This document does not prescribe a final wire format, but it requires:

- explicit vault versioning
- forward planning for schema evolution
- future support for non-destructive migration between vault revisions

Later technical design work must treat versioning as a first-class requirement, not as an afterthought.

### 6.6 Legacy Storage Retirement

The encrypted vault becomes the sole source of truth only after migration has fully succeeded. Until then, the legacy plaintext storage remains authoritative.

After a successful migration and validated cutover:

- the legacy `.gpg` files must be retired
- the legacy `contact-metadata.json` file must be retired
- legacy plaintext storage must be deleted in the same migration completion path that commits the new vault as authoritative

This creates two simultaneous rules:

- before success: legacy data must not be deleted
- after success: legacy plaintext data must not remain on disk as a long-term fallback source

The purpose of this rule is to align migration behavior with the stated privacy goal that no plaintext contacts source of truth remains on disk after the vault architecture is in effect.

## 7. Service And Runtime Architecture

### 7.1 UI-Facing Boundary

The UI must continue to consume a single Contacts-facing service boundary:

- `ContactsView`
- `ContactDetailView`
- `EncryptView`

This boundary remains `ContactService`.

The intent is to preserve a stable mental and structural model for the presentation layer while making the internal Contacts architecture more modular and maintainable.

### 7.2 `ContactService` As Facade

`ContactService` remains the `@Observable` facade exposed to views. Its responsibilities at the planning level are:

- exposing contacts state to UI
- exposing search and filtered results
- exposing contact-level operations
- exposing tag operations
- exposing recipient list operations
- coordinating unlock-dependent behavior
- coordinating migration and index refresh behavior

`ContactService` should not continue to grow as a monolithic implementation class. It remains the entry point, but not the whole subsystem.

### 7.3 Internal Components

The internal Contacts runtime is divided into four planned components.

| Component | Responsibility |
|----------|----------------|
| `ContactsVaultStore` | Encrypted vault read/write, temporary file write, structural validation, atomic replacement, and snapshot/recovery support |
| `ContactsVaultKeyManager` | Vault key access, Keychain interaction, session unlock, relock, and key lifecycle coordination |
| `ContactsMigrationCoordinator` | Import from legacy `.gpg + JSON` storage, conservative cutover, and migration fallback behavior |
| `ContactsSearchIndex` | In-memory search, filtering, and stable ordering over the unlocked contacts runtime state |

### 7.4 Locked-State Runtime Behavior

The contacts vault must have an explicit locked runtime state. When the vault is locked, the app must not pretend that the user simply has zero contacts.

Required planning-level behavior:

- `Contacts` shows an explicit locked state rather than an empty contacts list
- `Encrypt` shows an explicit locked recipient state rather than an empty recipient list
- the user is given an unlock or retry path
- selection and management actions that depend on unlocked contacts data remain unavailable until unlock succeeds

This avoids two implementation failures:

1. treating a security lock as if it were an empty dataset
2. forcing future implementation to choose between silent failure and accidental plaintext preload

### 7.5 Authentication Timing And Vault Availability

Current app behavior performs contact loading during startup and performs re-authentication later through the privacy-screen resume flow. The future contacts vault design must bridge those two timing models explicitly.

The planning requirement is:

- the contacts vault is not assumed to preload into an unlocked plaintext runtime state during cold startup
- successful launch authentication or resume authentication enables vault unlock
- grace-period expiry, app lock, or session loss must relock the vault and invalidate any unlocked search/index state

Later technical design work must decide the exact mechanics, but it must preserve the product semantics above and the explicit locked-state behavior described here.

### 7.6 Contacts-Dependent Decrypt And Verify Behavior

Some decrypt and verify flows do not merely display contacts data. They actively depend on contacts data for:

- verification key collection
- signer-contact lookup
- signer identity resolution

For those flows, a locked contacts vault is a blocking condition rather than a soft degradation state.

Required planning-level behavior:

- contacts-aware `Decrypt` requires the contacts vault to be unlocked before the operation proceeds
- contacts-aware `Verify` paths follow the same rule for consistency
- if unlock is required and the user cancels or authentication fails, the operation does not continue
- the app must not silently continue and downgrade signer recognition to `unknown signer`
- the app must not treat a locked contacts vault as if contacts verification inputs were simply absent

This preserves the meaning of signer identity recognition as a supported feature rather than turning it into an opportunistic best-effort behavior under lock conditions.

### 7.7 Deliberately Deferred Service Splits

Tags and recipient lists are intentionally not promoted to their own top-level services at this stage. The planning assumption is that they remain coordinated inside the Contacts subsystem through `ContactService` and the runtime vault model.

This keeps the presentation layer stable and avoids prematurely fragmenting the Contacts domain into too many narrowly scoped facades before implementation pressure proves the need.

## 8. Migration Strategy

### 8.1 Migration Source

The migration source is the existing legacy Contacts storage:

- old `.gpg` contact files
- old `contact-metadata.json`

### 8.2 Migration Policy

Migration is defined as:

- first-launch automatic migration
- conservative cutover
- no destructive deletion before successful completion

The old storage remains authoritative until the new vault is successfully built, validated, and committed.

### 8.3 Expected Migration Outcomes

Three planning-level outcomes are expected:

#### Full Migration Success

- legacy contact files are read
- legacy metadata is interpreted
- a valid encrypted vault is built
- the app switches to the new vault as source of truth
- the legacy plaintext `.gpg + JSON` storage is deleted immediately after validated cutover succeeds

#### Migration Failure With Fallback

- vault construction or validation fails
- old storage remains authoritative
- no destructive delete occurs
- user-visible handling can be defined later, but data safety wins over cutover progress

#### Interrupted Migration

- partial work may exist in temporary artifacts
- the old storage still remains authoritative until full success is proven
- future TDD work must define how interrupted migration cleanup is performed safely

### 8.4 Contact Key Rotation Behavior

Key replacement is already a meaningful contact lifecycle event and remains so in the new model.

The current system detects a likely key-update situation when the same `userId` appears with a different fingerprint. In the future model, that heuristic remains only a **candidate detection signal**. It is not, by itself, the authoritative proof that two keys belong to the same person.

The authoritative condition for migrating local organization data is explicit user confirmation that the newly detected key should replace the existing contact.

When the user confirms replacement of an existing contact key with a new fingerprint:

- tag relationships migrate automatically to the replacement fingerprint
- recipient list membership migrates automatically to the replacement fingerprint

This preserves the user's organization model and avoids turning routine key replacement into a loss of contact structure, while reducing the risk that automatic metadata migration is triggered by a heuristic match alone.

## 9. Testing And Validation Scope

This section defines the validation baseline that later technical design work must formalize further. It is intentionally structured by behavior rather than as a single flat checklist.

### 9.1 Search Validation

Search validation must cover:

- empty vault behavior
- single-contact and multi-contact behavior
- case-insensitive matching
- matching by display name
- matching by email
- matching by full fingerprint
- matching by short key ID
- matching by tag name once tags exist
- stable result ordering under both full lists and filtered lists

### 9.2 Tag Validation

Tag validation must cover:

- creating tags
- preventing or reconciling duplicates according to later TDD rules
- assigning multiple tags to a single contact
- removing tags
- persistence across restart
- filtering contacts by tag
- tag preservation during confirmed contact key replacement

### 9.3 Recipient List Validation

Recipient list validation must cover:

- creating a list
- renaming a list
- enforcing member de-duplication
- removing members
- persistence across restart
- using a list in Encrypt
- failure handling when list members are no longer encryptable, no longer present, or otherwise invalid

### 9.4 Vault Security Validation

Vault validation must cover:

- successful session unlock
- relock on app lock or app exit
- relock after grace period expiration
- explicit locked-state behavior in `Contacts`
- explicit locked-state behavior in `Encrypt`
- no empty-list masquerade when the vault is locked
- locked-vault `Decrypt` behavior when contacts-aware verification requires unlock
- locked-vault `Verify` behavior when contacts-aware identity resolution requires unlock
- cancellation or failed unlock resulting in a hard stop rather than degraded signer recognition
- clearing in-memory unlock state when access should no longer be allowed
- failure behavior for invalid vault material
- failure behavior for wrong key usage
- failure behavior for corrupted encrypted payloads
- compatibility with future authentication-mode expansion, including the requirement that `Special Security Mode` does not change the vault into a private-key-style loss-on-biometric-reset asset

### 9.5 Migration Validation

Migration validation must cover:

- import from legacy contact files
- import from legacy JSON metadata
- successful creation of a new vault from legacy data
- immediate legacy plaintext deletion after successful validated cutover
- interrupted migration behavior
- fallback behavior when migration does not fully succeed
- cutover behavior only after successful validation
- candidate detection for key replacement without immediate metadata migration
- metadata migration only after explicit replacement confirmation

### 9.6 Regression Validation

The new Contacts model must not regress the existing baseline behavior around:

- public key import
- duplicate detection
- key replacement confirmation
- contact deletion
- encryption recipient selection
- signer identity recognition during verification
- decrypt and verify flows requiring contacts unlock rather than silently degrading under locked-vault conditions

Later TDD work must turn this section into a concrete test matrix, but future documentation must preserve this validation scope as the baseline requirement.

## 10. Future Documentation Expansion

This document is designed to branch into two later document types.

### 10.1 Future PRD Expansion

A future Contacts-focused PRD should expand:

- user stories
- workflow definitions
- surface-by-surface UX behavior
- prioritization and release framing
- acceptance criteria and success measures

The PRD should elaborate user-facing behavior, not redefine storage or security architecture.

### 10.2 Future TDD Expansion

A future Contacts-focused TDD should expand:

- vault container model
- runtime interfaces
- unlock and relock lifecycle
- key access behavior
- migration mechanics
- failure and recovery rules
- detailed validation and test matrix

The TDD should elaborate implementation detail, not reopen the product or privacy direction already established here.

### 10.3 Change Discipline For Follow-On Documents

Future documents should refine and operationalize this plan. They should not reopen the following decisions unless explicitly re-approved:

- search + free-form tags + recipient lists as the capability direction
- social-graph-sensitive treatment of Contacts data
- session-unlocked encrypted contacts vault as the target protection model
- single encrypted vault file as the target storage form
- Keychain-protected vault key
- session-auth-only vault semantics even in a future world with `Special Security Mode`
- `ContactService` as a facade over internal runtime components
- first-launch automatic migration with conservative fallback

## 11. Planning Assumptions

This plan relies on the following defaults:

- Contacts relationship data is privacy-sensitive enough to justify encrypted storage
- `SwiftData` is not the target source of truth for the Contacts domain
- The single-file vault trade-off is acceptable for a read-heavy, write-light feature area
- The UI should not become dependent on multiple separate Contacts-facing services
- Future PRD and TDD documents are expected to deepen this plan, not replace it

## 12. Summary Of Decisions

For future document authors, the durable planning decisions established here are:

- Contacts enhancement is phased as Search, then Tags, then Recipient Lists
- Tags are free-form semantic labels
- Recipient lists are reusable encryption recipient sets, not generic contact folders
- Contacts data is treated as social-graph-sensitive
- The target architecture is a session-unlocked encrypted contacts vault
- The vault is a single encrypted, versioned file under `Application Support`
- The vault key is Keychain-protected
- The vault follows app session authentication semantics and explicit locked-state UX
- `ContactService` remains the UI-facing facade
- Internal Contacts runtime responsibilities are split across vault storage, vault key management, migration, and search indexing
- Migration from legacy storage is automatic on first launch, uses conservative fallback before success, and deletes legacy plaintext storage immediately after successful cutover

This document is the master planning artifact for future Contacts documentation. It should be read as the baseline from which later Contacts PRD and TDD work will be expanded.
