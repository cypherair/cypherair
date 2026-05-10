# Contacts Product Requirements Document (PRD)

> **Version:** Draft v1.3
> **Status:** Current product requirements for implemented Contacts PR5/6/8 behavior plus deferred backup/package boundaries.
> **Purpose:** Product requirements for the Contacts enhancement initiative as a Contacts domain built on the shared protected app-data framework.  
> **Audience:** Product, design, engineering, QA, and AI coding tools.  
> **Supersedes:** [CONTACTS_ENHANCEMENT_PLAN](archive/CONTACTS_ENHANCEMENT_PLAN.md) for Contacts-specific product direction.  
> **Companion document:** [CONTACTS_TDD](CONTACTS_TDD.md)  
> **Primary framework references:** [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TDD](TDD.md)
> **Related documents:** [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) · [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md) · [TESTING](TESTING.md) · [SPECIAL_SECURITY_MODE](SPECIAL_SECURITY_MODE.md)

## 1. Product Intent

CypherAir's Contacts capability now runs over the protected Contacts domain and includes person-centered key management, certification integration, search, tags, and recipient lists. This document records the product requirements for that capability and the remaining product boundaries around package exchange and future backup design.

The shared ProtectedData framework, Phase 1-7 non-Contacts domains, Contacts PR4 protected-domain security/storage cutover, and Contacts PR5/6/8 capability stack have landed. Implementation history and future expansion gates are owned by [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md), surface coverage is owned by [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md), and persisted-state classification is owned by [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md).

The Contacts enhancement initiative covers four user-facing capability areas:

- Search
- Free-form tags
- Recipient lists
- Merge Contacts / multi-key contact management

The initiative also defines the target privacy posture for Contacts:

- Contacts data is treated as social-graph-sensitive
- Contacts is implemented as a protected app-data domain, not as a second independent security architecture
- Contacts package exchange is withdrawn from this initiative because multi-contact export can externalize the user's social graph
- complete Contacts backup or device migration is deferred to a separate mandatory encrypted design

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
- preserve existing ordinary public certificate import behavior without introducing a Contacts package exchange feature

### 3.2 Non-Goals

This initiative does not include:

- network sync
- CloudKit
- system Contacts framework integration
- message format changes
- changes to private-key cryptography or Secure Enclave architecture
- redesign of the shared protected app-data framework itself
- whole-domain Contacts backup, whole-domain Contacts restore, or empty-install Contacts domain restore
- Contacts package export/import or public-key forwarding as a Contacts feature
- plaintext or optionally encrypted export of complete local Contacts state

The app already has low-level OpenPGP certificate-signature generation and verification workflows. This initiative redesigns how Contacts owns, persists, and presents certification state, while leaving packet-level OpenPGP certification cryptography to the existing crypto/service layer.

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
- Contacts-owned certification projection and any saved certification signature artifacts for this key

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

Certification is real OpenPGP key certification, not a UI synonym for local manual verification.

Contacts must own the user-facing trust/certification model around the existing certificate-signature service:

- direct-key signature verification
- User ID binding signature verification
- external certification signature text/file import
- user-initiated certification of a contact User ID with one of the user's private keys
- export/share of generated certification signatures
- signer identity resolution
- target certificate selector validation
- certification-kind presentation

These capabilities must not remain exposed as a raw three-mode technical tool. The target experience is contact-centered: Contact Detail shows a compact trust/certification summary and a common `Certify This Contact` action, while a redesigned certification details surface owns saved history, exportable signature material, raw details, and secondary import/verify actions.

#### Presentation Rule

Manual verification and certification must be presented as separate product signals. They must not be collapsed into one generic "verified" status.

## 5. Privacy, Security, And Failure Position

### 5.1 Privacy Position

Contacts data is treated as social-graph-sensitive. This applies not only to tags and notes, but also to the possession of another person's public key.

### 5.2 Storage Position

The target persistence model is:

- one logical Contacts protected domain inside the shared protected app-data framework
- encrypted Contacts payload generations stored under the framework's protected-domain storage rules
- one shared Keychain-protected app-data root-secret gate as the normative session gate for protected app data
- one Contacts domain master key persisted only through the shared framework wrapped-DMK model
- no plaintext search indexes or derivative contact caches persisted outside the protected Contacts domain
- Contacts product data becomes the source of truth only after migration completes

Contacts does not own:

- the shared app-data root secret or derived wrapping root key
- registry authority
- wrapped-DMK lifecycle rules
- shared relock policy

User-facing copy may still use shorthand such as "Contacts vault," but the technical ownership model is a Contacts domain built on the shared app-data framework.

### 5.3 Authentication Position

The Contacts domain follows shared app-data session semantics:

- `AppSessionOrchestrator` owns the app-wide session boundary
- `ProtectedDataSessionCoordinator` owns shared app-data root-secret retrieval under that boundary
- after app privacy authentication succeeds, Contacts is opened through the same post-authentication / post-unlock protected-domain orchestration used by other protected app-data domains
- if the shared app-data session is inactive, the authenticated `LAContext` from app authentication may be reused for shared root-secret retrieval rather than surfacing a Contacts-specific prompt
- completing launch/resume authentication alone is not enough unless shared root-secret retrieval, wrapping-root-key derivation, and Contacts domain open also succeed
- routine launch/resume into the app should leave Contacts available after the shared protected app-data domains open successfully
- ordinary Contacts browsing, search, tag/list management, and recipient selection do not trigger a separate Contacts-specific routine prompt once the app-data session is active
- a second or third protected domain in the same active app-data session must not trigger another prompt merely because Contacts is opened later
- Contacts access relocks after app lock, session loss, grace-period expiry, or app exit

Contacts does not mirror private-key per-operation gating and does not inherit the loss semantics of `Special Security Mode`. Future high-risk externalization actions such as complete Contacts backup must be designed separately and must not be treated as ordinary in-session use.

### 5.4 Domain Failure And Backup Boundary

Contacts domain failure remains explicit, but this initiative does not define a portable whole-domain backup or restore feature.

The formal direction for this initiative is:

- Contacts package exchange is not an active product requirement
- ordinary public certificate import remains an existing public-key import path, not a Contacts backup or exchange package
- future complete Contacts backup or device migration must be a separate mandatory encrypted design
- plaintext or optionally encrypted export of complete Contacts social-graph state is not allowed
- unreadable Contacts domain state is surfaced as domain-scoped `recovery needed`, not silently replaced by backup restore or an empty domain

Failure ownership is layered:

- Contacts owns domain-scoped failure presentation for unreadable Contacts payload or Contacts wrapped-DMK state
- the shared app-data framework owns framework-level recovery when registry or shared-resource state is unreadable, inconsistent, or unsafe
- framework-level recovery must not be misrepresented as Contacts backup restore or Contacts empty state

### 5.5 Failure Position

Contacts failure states must remain explicit.

Required product behavior:

- a locked Contacts domain is presented as locked, not as an empty Contacts dataset
- unreadable Contacts domain state is presented as domain-scoped `recovery needed`
- shared-framework failure is presented as a framework-level unavailable or recovery-required state, not as a Contacts empty-state
- fail-closed relock failure that enters `restartRequired` blocks Contacts access until restart and is not misrepresented as Contacts data loss
- the app must not silently create a new empty Contacts domain or silently discard unreadable Contacts data
- ordinary authenticated app use should normally open Contacts automatically; a locked Contacts state is a boundary condition such as authentication cancellation, relock, domain recovery, or framework unavailability

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

### 10.1 Decrypt When Contacts Verification Context Is Unavailable

Decrypt is split into:

- core content decryption
- signature packet detection
- certificate-backed signature verification using available certificates
- contacts-aware signer recognition and trust/certification enrichment

Issuer/key-handle metadata from a signature packet is not used as a user identity clue. The app only resolves signer identity from a suitable verification certificate and must not present unverified signature metadata as a signer.

If Contacts verification context is unavailable because Contacts is locked, recovering, or framework-unavailable:

- content decryption may still complete
- the signature area must state exactly what is known and what is missing
- the app must not claim that cryptographic signature verification completed unless a suitable verification certificate was actually available
- the UI may direct the user to complete app-data authorization when that can make Contacts verification context available
- the app must not silently degrade to `unknown signer`

### 10.2 Verify When Contacts Verification Context Is Unavailable

Independent Verify is different from Decrypt because its main value is verification itself.

If full verification requires Contacts data and Contacts verification context is unavailable:

- the verify result must remain incomplete rather than silently falling back to a generic unknown-signer state
- if app-data authorization is available, the app may ask the user to unlock protected app data
- if the user cancels or authentication fails, verify reports that required verification context is unavailable

## 11. Contact Detail Requirements

The contact detail surface must support:

- viewing multiple keys under one contact
- seeing preferred vs additional vs historical keys
- manual verification actions
- a compact trust/certification summary
- a common `Certify This Contact` action
- a route to certification details for saved history, exportable certification signature material, raw details, and secondary external signature import/verification
- preferred key management
- merge-related or post-merge cleanup actions as later detailed in TDD

Manual verification and certification must remain visibly distinct.

## 12. Migration Requirements

### 12.1 Migration Source

The legacy migration source is the old plaintext contacts storage:

- `.gpg` contact files
- `contact-metadata.json`

### 12.2 Migration Order And Policy

Contacts migration belongs to the Contacts Protected Domain phase, currently Phase 8.

Shared-framework prerequisites are complete:

- Phase 1 reusable protected app-data framework is implemented
- Phase 2 file-protection baseline is implemented for ProtectedData storage
- Phase 3 first low-risk protected domain has completed its narrow `protected-settings` / `clipboardNotice` scope
- Phase 4 post-unlock multi-domain orchestration and framework hardening is complete, including second-real-domain coverage and pending-create continuation hardening
- Phase 5 `private-key-control` domain is implemented
- Phase 6 `key-metadata` domain is implemented
- Phase 7 non-Contacts protected-after-unlock domains and required local file/static-protection cleanup are implemented

No remaining AppData gate blocks Contacts PR1-PR8. Implementation history and future expansion gates are tracked in [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md).

Contacts adoption and migration occur after app authentication through the shared post-unlock protected-domain orchestration. The same authenticated `LAContext` may be reused for root-secret retrieval and Contacts domain open, so normal app entry does not create a separate Contacts prompt.

Contacts migration must not be triggered merely because process launch or service initialization happened before app-data authorization.

Contacts migration uses the shared framework create/write path. It does not define separate Contacts-specific rules for root-secret provisioning, first-domain creation, or last-domain cleanup.

### 12.3 Quarantine And Deletion

After cutover succeeds:

- legacy plaintext data enters a quarantine state
- legacy plaintext is not kept as a permanent fallback
- legacy plaintext is no longer loaded for search, recipient resolution, or routine Contacts display
- final deletion happens only after the next successful opening of the Contacts domain

This creates a safer rollback window than immediate deletion while still honoring the privacy goal of eliminating long-lived plaintext contacts storage.

## 13. Contacts Backup And Public Certificate Import Boundary

The Contacts initiative no longer includes a formal Contacts package export/import story.

The product boundary is:

- ordinary OpenPGP public certificate material continues to use the existing public-key import path
- importing public certificate material is not a Contacts package, backup, restore, or forwarding feature
- PR6 certification-signature export/share remains scoped to certification artifacts, not Contacts backup
- complete Contacts backup, restore, or device migration is deferred to a separate product/design effort

Future complete Contacts backup must meet these product constraints before it can enter scope:

- backup must be a separate mandatory encrypted format
- plaintext or optionally encrypted export of complete Contacts state is not allowed
- backup must not be presented as Contacts domain recovery, framework recovery, or empty-install bootstrap unless that behavior is explicitly designed later
- backup design must account for social-graph-sensitive data such as local labels, tags, notes, recipient lists, manual verification state, certification history, and retained public-key groupings

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
- app authentication and post-unlock protected-domain orchestration normally open Contacts without a later second Contacts-specific prompt
- entering Contacts or Encrypt during an already active protected app-data session does not trigger redundant Contacts-specific authentication prompts
- grace-period expiry or app lock relocks Contacts access explicitly
- decrypt and verify report missing Contacts verification context accurately and never claim completed signature verification without a suitable verification certificate
- verify does not silently continue without required verification context
- legacy plaintext storage is retired through quarantine and next-successful-open deletion
- Contacts domain damage or unreadable Contacts wrapped-DMK state results in explicit Contacts `recovery needed` rather than an empty Contacts list
- framework-level protected-data failure is shown distinctly from Contacts domain recovery and is not misrepresented as a Contacts empty-state or backup restore path
- manual verification and certification are both represented clearly and separately
- certification workflows cover the existing direct-key verification, User ID binding verification, external signature import, user certification generation, generated-signature export/share, signer identity resolution, selector validation, and certification-kind display capabilities without retaining the old three-mode technical UI

## 16. Product Scenarios

### Scenario A: Import A Possible Second Key

1. User imports a new key.
2. App detects an exact normalized email match with an existing contact.
3. App still imports the key as a new contact by default.
4. App informs the user that the new key may belong to an existing contact.
5. User can later merge the two contacts.

### Scenario B: Decrypt When Contacts Verification Context Is Unavailable

1. User decrypts a message successfully.
2. Plaintext is shown.
3. The signature area states that Contacts verification context or a signer certificate is unavailable.
4. The UI does not claim signature verification completed until a suitable verification certificate is available.

### Scenario C: Verify When Contacts Verification Context Is Unavailable

1. User opens Verify.
2. Full contacts-aware verification requires Contacts data.
3. App asks the user to unlock protected app data if that can make Contacts context available.
4. If the user cancels, verification reports required context unavailable.

### Scenario D: Launch Into Protected Contacts Availability

1. User cold-launches or resumes the app from a state that requires authentication.
2. `AppSessionOrchestrator` runs the user-visible unlock flow.
3. The authenticated `LAContext` is reused by shared post-unlock orchestration to retrieve the root secret and open registered protected domains, including Contacts.
4. Later in the same active app-data session, opening Contacts or recipient selection in `Encrypt` reuses that session.

### Scenario E: Use Contacts Within An Already Active App-Data Session

1. Earlier in the current app session, the user already activated the shared app-data session by accessing a protected domain.
2. User opens `Contacts` and later opens recipient selection in `Encrypt`.
3. The app does not show another Contacts-specific authentication prompt.
4. If the grace period later expires, Contacts returns to an explicit locked state.

### Scenario F: Certify A Contact

1. User opens Contact Detail and sees a compact trust/certification summary.
2. User chooses `Certify This Contact`.
3. App asks the user to choose a signing key, target User ID, and certification kind.
4. App generates and saves a certification record and signature artifact in the protected Contacts domain.
5. User may export/share the generated certification signature.

### Scenario G: Manage Certification Details

1. User opens a contact's certification details.
2. App shows saved certification history, exportable signature material, and raw technical details.
3. User may use a secondary action to import or verify an external certification signature.
4. Imported valid certification material is saved as protected Contacts data.

### Scenario H: Contacts Domain Recovery Needed

1. App starts and the Contacts domain cannot be opened because the Contacts payload is damaged or the domain-specific wrapped-DMK state is unreadable.
2. `Contacts` does not appear empty.
3. The app presents an explicit Contacts `recovery needed` state.
4. The app does not silently reset Contacts or present backup restore as framework/domain recovery.

### Scenario I: Protected App-Data Framework Recovery Blocks Contacts

1. App starts and the shared protected app-data framework cannot safely determine or use the shared root-secret resource.
2. `Contacts` does not bypass that framework state independently.
3. The app presents a framework-level unavailable or recovery-required state.
4. The app does not mislabel that condition as a Contacts empty-state or a backup restore path.

## 17. Out Of Scope For This Document

This document does not define:

- packet-level certification implementation
- shared ProtectedData framework internals such as registry invariants, wrapped-DMK transactions, or relock state-machine mechanics
- Contacts package exchange
- complete Contacts backup, restore, or device-migration format
- detailed service APIs
- persistence schema internals

Technical details that remain in scope belong in [CONTACTS_TDD](CONTACTS_TDD.md) and the current shared-framework references listed at the top of this document. Withdrawn package exchange and deferred backup design require a new product decision before they can re-enter the active spec set.
