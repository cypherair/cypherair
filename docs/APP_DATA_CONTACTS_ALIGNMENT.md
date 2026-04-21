# App Data / Contacts Alignment

> **Version:** Draft v1.0  
> **Status:** Draft temporary alignment proposal. This document does not describe current shipped behavior.  
> **Purpose:** Record the temporary divergence between the current app-data protection proposal and the older Contacts proposal docs, and define how that divergence is resolved until the Contacts docs are updated.  
> **Audience:** Engineering, security review, QA, and AI coding tools.  
> **Companion documents:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)  
> **Related documents:** [CONTACTS_PRD](CONTACTS_PRD.md) · [CONTACTS_TDD](CONTACTS_TDD.md)

## 1. Why This Document Exists

The app-data protection proposal has evolved faster than the still-unrevised Contacts proposal docs.

At the moment:

- `APP_DATA_PROTECTION_PLAN.md` and `APP_DATA_PROTECTION_TDD.md` define the intended future shared protected-data framework
- `CONTACTS_PRD.md` and `CONTACTS_TDD.md` still describe an older Contacts-specific vault protection model

This document exists only to prevent that temporary divergence from becoming ambiguous implementation guidance.

It is a temporary bridge document and must be archived after the Contacts docs are rewritten.

## 2. Temporary Precedence Rule

For future protected-data planning work only:

- `APP_DATA_PROTECTION_PLAN.md`
- `APP_DATA_PROTECTION_TDD.md`
- this alignment document

outrank conflicting older Contacts-vault implementation assumptions in `CONTACTS_PRD.md` and `CONTACTS_TDD.md`.

This precedence rule does **not** make the Contacts docs current or obsolete by itself. It only defines how to interpret the temporary mismatch until the next documentation round updates the Contacts docs directly.

## 3. Current Conflict Inventory

The following conflicts currently exist between the app-data proposal and the Contacts proposal docs.

### 3.1 Vault-Key Protection Model

Current Contacts docs still say:

- the local contacts-vault master key is protected by a dedicated Secure Enclave wrapping scheme
- the Contacts vault key has a dedicated Keychain namespace with `vault-se-key`, `vault-salt`, and `vault-sealed-master-key`

Current app-data docs now say:

- app-data domains use one shared `LAPersistedRight` as the primary authorization gate in v1
- app-data uses one shared app-data secret plus per-domain DMKs in the canonical v1 model
- custom Secure Enclave wrapping is no longer promised as the primary v1 app-data design

### 3.2 Unlock Lifecycle Authority

Current Contacts docs still say:

- `ContactsVaultKeyManager` unwraps the master key once per authenticated app session by reusing launch/resume authentication context

Current app-data docs now say:

- `ProtectedDataSessionCoordinator` owns shared app-data right authorization timing
- `LAPersistedRight.authorize(...)` is the single normative app-data authorization boundary
- the shared app-data secret is not released before `LAPersistedRight` authorization succeeds
- one successful app-data authorization covers all app-data domains in the current session
- startup is split into pre-auth bootstrap and post-auth unlock phases

### 3.3 Recovery Contract Ownership

Current Contacts docs define:

- Contacts-specific `recoveryNeeded`
- import-based recovery guidance
- Contacts-specific vault key failure language

Current app-data docs now define:

- a shared protected-data recovery taxonomy
- `import-recoverable`, `resettable-with-confirmation`, and `blocking` domain contracts
- shared protected-domain recovery coordination
- a shared app-data gate plus per-domain DMK recovery ladder

### 3.4 Service-Architecture Ownership

Current Contacts docs still describe Contacts-specific ownership of:

- vault-key lifecycle
- unlock and relock behavior
- startup recovery semantics

Current app-data docs now define those responsibilities as shared protected-data framework concerns, with Contacts intended to become a domain-specific consumer.

### 3.5 Multi-Domain Gate And Session Model

Current Contacts docs still imply a Contacts-specific vault session.

Current app-data docs now say:

- one shared app-data right gates all app-data domains
- per-domain DMKs are lazy-unwrapped on first access
- app-data session lifetime follows the shared grace-window model

## 4. How To Read The Conflict For Now

Until the Contacts docs are updated:

- keep all Contacts product behavior assumptions that do **not** conflict with the app-data framework
- treat Contacts-specific storage, vault-key, unlock, and recovery implementation details as stale where they contradict the newer app-data proposal

In practice, the newer app-data proposal should be treated as the future architectural source of truth for:

- protected-domain authorization boundary
- startup authentication split
- shared recovery taxonomy
- first-party protected-domain ownership boundaries

## 5. Contacts Sections That Must Be Rewritten Next Round

The next documentation round must revise these areas in the Contacts docs:

### In `CONTACTS_PRD.md`

- storage model
- vault-key protection language
- authentication position
- recovery position
- failure position where it depends on older vault-key assumptions

### In `CONTACTS_TDD.md`

- vault key and session lifecycle
- unlock lifecycle
- startup recovery model where it assumes Contacts-specific key-unlock ownership
- service architecture ownership
- validation matrix entries that assume the older Contacts-specific vault-key model

## 6. Exit Criteria For Archiving This Document

Archive this document once all of the following are true:

- `CONTACTS_PRD.md` is updated to align with the shared app-data framework
- `CONTACTS_TDD.md` is updated to align with the shared app-data framework
- cross-links are repaired so active docs no longer point to stale conflicting assumptions
- no active-doc conflicts remain on protected-data architecture

When those conditions are met:

- move this document to `docs/archive/`
- add an archive banner
- reference the updated Contacts docs as the successor source of guidance

## 7. Guardrail

This document must not become a permanent third architecture source.

If the Contacts docs remain unrevised for too long, the correct action is to update the Contacts docs, not to keep expanding this bridge document indefinitely.
