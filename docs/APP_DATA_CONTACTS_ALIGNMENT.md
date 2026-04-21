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

- app-data uses one shared `LAPersistedRight` as the primary authorization gate in v1
- app-data uses one shared app-data secret plus per-domain wrapped DMKs in the canonical v1 model
- custom Secure Enclave wrapping is no longer promised as the primary v1 app-data design

### 3.2 Session Ownership And Unlock Authority

Current Contacts docs still say:

- `ContactsVaultKeyManager` unwraps the master key once per authenticated app session by reusing launch/resume authentication context
- Contacts effectively owns its own vault session boundary

Current app-data docs now say:

- `AppSessionOrchestrator` is the app-wide session owner
- `ProtectedDataSessionCoordinator` is the app-data subsystem coordinator under that owner
- `LAPersistedRight.authorize(...)` remains the single normative app-data authorization boundary
- the shared app-data secret is not released before shared-right authorization succeeds
- Contacts is expected to live under `AppSessionOrchestrator` -> `ProtectedDataSessionCoordinator` -> Contacts domain

### 3.3 Shared Gate And Multi-Domain Session Model

Current Contacts docs still imply a Contacts-specific vault session and Contacts-specific relock ownership.

Current app-data docs now say:

- one shared app-data right gates all protected domains
- per-domain DMKs are lazy-unwrapped on first access
- one successful app-data authorization covers all protected domains in the active app-data session
- a second or third protected domain does not trigger another prompt in that same session

### 3.4 Lifecycle Authority And Recovery Ownership

Current Contacts docs still imply that Contacts-vault files and vault-key state are sufficient to determine Contacts lifecycle and recovery.

Current app-data docs now say:

- `ProtectedDataRegistry` is the sole authority for committed domain membership and shared-resource lifecycle
- filesystem artifacts are recovery evidence, not the normal authority
- framework-level recovery and domain-scoped recovery are separate layers
- Contacts is a domain-specific consumer with its own recovery contract, not the owner of framework session or lifecycle authority

### 3.5 Recovery Contract Ownership

Current Contacts docs define:

- Contacts-specific `recoveryNeeded`
- import-based recovery guidance
- Contacts-specific vault-key failure language

Current app-data docs now define:

- a shared protected-data recovery taxonomy
- `frameworkRecoveryNeeded` for shared-resource failure
- domain-scoped `recoveryNeeded` for wrapped-DMK or payload failure
- `import-recoverable`, `resettable-with-confirmation`, and `blocking` domain contracts

## 4. How To Read The Conflict For Now

Until the Contacts docs are updated:

- keep all Contacts product behavior assumptions that do **not** conflict with the app-data framework
- treat Contacts-specific storage, vault-key, session, lifecycle, and recovery implementation details as stale where they contradict the newer app-data proposal

In practice, the newer app-data proposal should be treated as the future architectural source of truth for:

- protected-domain authorization boundary
- shared session ownership
- registry authority
- startup authentication split
- shared recovery taxonomy
- first-party protected-domain ownership boundaries

The following Contacts assumptions remain compatible unless a later rewrite explicitly changes them:

- Contacts may still use one encrypted Contacts payload as its domain storage choice
- Contacts remains `import-recoverable`
- no plaintext derivative caches or indexes may persist outside the protected Contacts domain

## 5. Contacts Sections That Must Be Rewritten Next Round

The next documentation round must revise these areas in the Contacts docs:

### In `CONTACTS_PRD.md`

- storage model where it assumes Contacts-specific vault-key protection
- authentication position where it assumes a Contacts-owned session boundary
- recovery position where it assumes Contacts-owned lifecycle authority
- failure position where it assumes Contacts-vault artifacts are sufficient to classify all recovery state

### In `CONTACTS_TDD.md`

- vault key and session lifecycle
- unlock lifecycle
- startup recovery model where it assumes Contacts-specific key-unlock ownership
- service architecture ownership
- lifecycle authority where it assumes no shared registry
- validation matrix entries that assume the older Contacts-specific vault-key and session model

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
