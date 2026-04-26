# Contacts Protected Domain Surface Inventory

> **Version:** Draft v0.1
> **Status:** Draft implementation-prep checklist. This document does not describe current shipped behavior.
> **Purpose:** Enumerate all Contacts-required access and mutation surfaces that must be accounted for during Contacts protected-domain implementation.
> **Audience:** Engineering, QA, and AI coding tools.
> **Companion document:** [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
> **Primary design references:** [CONTACTS_TDD](CONTACTS_TDD.md) · [APP_DATA_PROTECTION_TDD](APP_DATA_PROTECTION_TDD.md)

## 1. Scope And Usage

This document is the execution checklist for Contacts protected-domain adoption.

It exists because current Contacts access is distributed across:

- app routes
- import coordinators
- view models
- service-layer recipient resolution
- verification enrichment helpers
- certificate-signature workflows

Every later implementation PR should use this document to answer:

- which surfaces it owns
- whether each surface is a domain read, mutation, recovery action, or optional Contacts enrichment
- what the locked-state behavior must be
- whether framework gating is required

## 2. Classification Rules

Each row in the inventory uses the following concepts.

### 2.1 Surface Type

- `read` — needs Contacts domain content for ordinary user-visible behavior
- `mutation` — changes Contacts domain content
- `recovery` — imports, exports, migration, reconciliation, or cleanup flows
- `enrichment` — optional Contacts-aware enhancement around otherwise meaningful non-Contacts work

### 2.2 Target Unlock Requirement

- `yes` — the target design requires an unlocked Contacts domain
- `conditional` — the surface can partially operate without Contacts, but Contacts-aware behavior requires unlock
- `no` — the surface should not require Contacts domain unlock

This column only describes whether the Contacts domain itself must already be unlocked. It does not describe whether app-session unlock or shared framework gate participation is still required.

### 2.3 Framework Gate

- `yes` — surface must pass through shared protected-data session rules
- `conditional` — only the Contacts-dependent branch is gated
- `bootstrap-only` — may inspect only early-readable framework metadata, never Contacts payload content

In the target design, the shared protected-data session is activated by reading the Keychain-protected app-data root secret through an authenticated `LAContext`. A `yes` framework gate does not mean Contacts payloads may be opened during pre-auth startup; it means the surface must wait until the shared root-secret gate and any required Contacts domain unlock have succeeded.

### 2.4 Locked-State Target Behavior

Locked-state behavior is frozen at the inventory level so later PRs do not reinterpret it ad hoc.

Allowed outcomes:

- explicit Contacts locked state
- explicit framework unavailable state
- recovery-needed state
- core result completed with Contacts enrichment pending
- pre-commit inspection allowed, commit blocked until unlock

## 3. Access Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Pre-auth startup bootstrap | `AppStartupCoordinator.performPreAuthBootstrap(...)` | read | no | bootstrap-only | Must not open Contacts domain payload; may only use registry/bootstrap metadata | PR4 | Current code still loads Contacts during pre-auth startup and must stop doing so |
| Contacts root list | `ContactsView` + `ContactService.loadContacts()` | read | yes | yes | Show explicit Contacts locked / recovery-needed / framework-unavailable state instead of empty list | PR4 | Current `.task`-based load bypasses future gate |
| Contact detail lookup | `ContactDetailView` + `contactService.contact(forFingerprint:)` | read | yes | yes | Route blocked or explicit locked-state presentation; never nil-as-not-found because domain is locked | PR4 | Current view treats missing contact and unavailable domain too similarly |
| Encrypt recipient browsing | `EncryptView` / `EncryptScreenModel.encryptableContacts` | read | yes | yes | Show explicit Contacts locked recipient state with unlock CTA | PR4 | Current recipient list assumes startup-loaded Contacts |
| Encrypt recipient resolution | `EncryptionService` recipient fingerprint -> public key lookup | read | yes | yes | Encryption cannot proceed until Contacts domain is available | PR4, PR8 | Later PR8 changes resolution to contact-identity/preferred-key semantics |
| Decrypt Contacts enrichment | `DecryptionService` signer lookup / identity resolution | enrichment | conditional | conditional | Plaintext and core verification complete; Contacts enrichment remains pending | PR3, PR4 | Core verification and Contacts enrichment are intentionally split |
| Password-message Contacts enrichment | `PasswordMessageService.decryptMessage(...)` signer lookup / identity resolution | enrichment | conditional | conditional | Core password decrypt completes; Contacts enrichment remains pending when locked | PR3, PR4 | Mirrors ordinary decrypt semantics for signed SKESK flows |
| Verify route Contacts-aware verification | `Verify` route via `SigningService` verify helpers | enrichment | conditional | conditional | Route requires unlock before presenting its intended final contacts-aware result | PR3, PR4 | Service contract still splits core verification from Contacts enrichment |
| Certificate-signature target contact access | `ContactCertificateSignaturesScreenModel.contact` | read | yes | yes | Route blocked or explicit Contacts locked state | PR4 | Target certificate remains Contacts-owned state |
| Certificate-signature verification-time candidate signer read | `CertificateSignatureService` candidate signer certificate loading via `contactService.contacts` | read | yes | yes | Verification cannot consume Contacts-backed candidate signer certificates until the Contacts domain is available | PR4 | Current service passes Contacts certificates into the engine as `candidateSigners`; this is verification input, not just UI enrichment |
| Certificate-signature signer identity and projection enrichment | `CertificateSignatureService` signer identity resolution and certification projection through Contacts | enrichment | conditional | conditional | Contacts enrichment blocked until unlock; framework unavailable stays distinct | PR4, PR5 | PR4 gates route access and separates raw verification from enrichment; PR5 lands projection/reconciliation support |

## 4. Mutation Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Add Contact import inspection | `AddContactScreenModel`, `PublicKeyImportLoader`, URL/QR/file inspection | mutation | no | no | Allow key inspection and preview without Contacts unlock | PR4 | Inspection of candidate public key bytes is not itself a Contacts domain write |
| Add Contact import commit | `ContactImportWorkflow.importContact(...)` | mutation | yes | yes | Pre-commit preview may remain visible, but commit requires Contacts unlock | PR4 | Current workflow writes directly through `ContactService.addContact(...)` |
| URL-based contact import commit | `IncomingURLImportCoordinator.handleIncomingURL(...)` -> import confirmation success path | mutation | yes | yes | URL parsing may happen before unlock; final import commit requires Contacts unlock | PR4 | Current coordinator reaches import workflow directly |
| Confirm key replacement / same-user update | `ContactImportWorkflow.confirmReplacement(...)` | mutation | yes | yes | Block replacement until Contacts unlock | PR4, PR8 | Later PR8 changes replacement semantics under person-centered model |
| Delete contact | `ContactsView` delete, `ContactDetailView` destructive action, `ContactService.removeContact(...)` | mutation | yes | yes | Show explicit locked or framework-unavailable state; never best-effort delete while locked | PR4 | Current deletes hit plaintext storage directly |
| Manual verification promotion | `ContactDetailView` -> `ContactService.setVerificationState(...)` | mutation | yes | yes | Unlock required before mutation; no shadow write path | PR4 | Manual verification remains distinct from certification |
| Merge contacts | future Contacts management surfaces | mutation | yes | yes | Unlock required; explicit merge workflow only | PR8 | Not yet implemented in current code |
| Preferred key management | future Contacts detail or merge follow-up surfaces | mutation | yes | yes | Unlock required; must preserve deterministic preferred/additional/historical rules | PR8 | Depends on person-centered model |
| Tag management | future Contacts detail / filter management | mutation | yes | yes | Unlock required | PR9 | Tags belong to `ContactIdentity` layer |
| Recipient-list management | future Contacts list/detail management surfaces | mutation | yes | yes | Unlock required | PR9 | Lists bind to `ContactIdentity`, not fingerprints |

## 5. Recovery, Migration, And Maintenance Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Contacts recovery export | future Contacts recovery action | recovery | yes | yes | Requires unlocked Contacts plus fresh authentication immediately before export | PR6 | Export serializes Contacts business data, not framework artifacts |
| Contacts recovery import | future Contacts recovery import action | recovery | no | yes | Requires framework availability, app-session unlock, and root-secret availability; no routine second Contacts prompt beyond defined policy | PR6 | Covers replace-domain import and does not require a previously unlocked Contacts domain |
| Empty-install restore | recovery import on installation with no protected domains | recovery | no | yes | Framework owns first-domain provisioning; Contacts does not special-case lifecycle | PR6 | Must bridge from empty steady-state / no protected domain present and does not require a pre-existing unlocked Contacts domain |
| Certification projection reconciliation on unlock | Contacts unlock flow + reconciliation helper | recovery | yes | yes | Runs after unlock as needed; failures must not be misrepresented as empty Contacts state | PR5 | Separate from raw crypto verification |
| Certification projection reconciliation on import | recovery import finalization | recovery | yes | yes | Rebuild projected state deterministically after import | PR5, PR6 | Import and reconciliation responsibilities meet here |
| Legacy plaintext migration read | migration coordinator reading `.gpg` files and `contact-metadata.json` | recovery | conditional | yes | Old source remains authoritative until target readability is proven | PR7 | Reads legacy plaintext without treating it as the final source after cutover |
| Quarantine management | migration coordinator quarantine paths | recovery | yes | yes | Quarantine is inactive for normal Contacts display and resolution | PR7 | No ordinary route may read quarantine as active source |
| Final legacy deletion | post-cutover cleanup after later successful Contacts domain open | recovery | yes | yes | Delete only after later successful open confirmation | PR7 | Avoids destructive deletion on first cutover success |

## 6. Surfaces Explicitly Not Treated As Contacts Domain Access

These repository behaviors remain important, but they are not ordinary Contacts domain access surfaces in the target design:

| Surface | Reason |
|---------|--------|
| Pre-auth registry bootstrap | May inspect only framework-readable metadata, never Contacts payload content or the root-secret Keychain item |
| Public-key inspection before import commit | Examines incoming key bytes, not existing Contacts domain state |
| Core decrypt and core signature verification | Remains meaningful without Contacts, though Contacts enrichment may be pending or blocked |

## 7. Inventory Acceptance Criteria

This inventory is only complete if later implementers can use it to answer all of the following without rediscovering repository state manually:

- which current entrypoints directly touch Contacts behavior
- which surfaces are reads vs mutations vs recovery actions vs optional enrichment
- which surfaces can partially operate while Contacts is locked
- which surfaces must wait for Contacts unlock before commit
- which PR will own each surface during later implementation

Future implementation PRs should update this document whenever:

- a surface changes owner
- a new Contacts-dependent route is introduced
- a locked-state behavior becomes more specific
- a row moves from current-state inventory to implemented coverage notes
