# Contacts Protected Domain Surface Inventory

> **Version:** Draft v0.5
> **Status:** Draft implementation-prep checklist, updated with the Contacts PR7 package-exchange withdrawal.
> **Purpose:** Enumerate all Contacts-required access and mutation surfaces that must be accounted for during Contacts protected-domain implementation.
> **Audience:** Engineering, QA, and AI coding tools.
> **Companion document:** [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
> **Primary design references:** [CONTACTS_TDD](CONTACTS_TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TDD](TDD.md)

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
- whether each surface is a domain read, mutation, maintenance action, or optional Contacts enrichment
- what the locked-state behavior must be
- whether framework gating is required

## 2. Classification Rules

Each row in the inventory uses the following concepts.

### 2.1 Surface Type

- `read` — needs Contacts domain content for ordinary user-visible behavior
- `mutation` — changes Contacts domain content
- `maintenance` — migration, quarantine, reset, cleanup, reconciliation, or sandbox boundary flows
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
- explicit Contacts opening state
- explicit framework unavailable state
- recovery-needed state
- plaintext delivered with signature verification context unavailable
- pre-commit inspection allowed, commit blocked until unlock

## 3. Access Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Pre-auth startup bootstrap | `AppStartupCoordinator.performPreAuthBootstrap(...)` | read | no | bootstrap-only | Must not open Contacts domain payload; may only use registry/bootstrap metadata | Contacts PR3 | PR3 covered: startup records `startup.contacts.load.deferred` and performs no legacy Contacts read pre-auth |
| Contacts root list | `ContactsView` + `ContactService.contactsAvailability` / `availableContactIdentities` | read | yes | yes | Show explicit Contacts locked / recovery-needed / framework-unavailable state instead of empty list | Contacts PR3, Contacts PR5 | PR3 covered availability gating; PR5 covered identity rows with key count and preferred-key status |
| Contact detail lookup | `ContactDetailView` + `contactService.availableContactIdentity(forContactID:)` | read | yes | yes | Route blocked or explicit locked-state presentation; never nil-as-not-found because domain is locked | Contacts PR3, Contacts PR5 | PR3 covered unavailable state; PR5 covered contact-ID route and preferred/additional/historical key sections |
| Encrypt recipient browsing | `EncryptView` / `EncryptScreenModel.encryptableContacts` | read | yes | yes | Show explicit Contacts locked recipient state with unlock CTA | Contacts PR3, Contacts PR5 | PR3 covered availability gating; PR5 covered identity selection with contact IDs |
| Encrypt recipient resolution | `EncryptionService` recipient contact ID -> gated preferred-key lookup | read | yes | yes | Encryption cannot proceed until Contacts domain is available; selected contacts without one preferred encryptable key fail closed | Contacts PR3, Contacts PR5 | PR5 covered contact-ID resolution through `publicKeysForRecipientContactIDs`; fingerprint overloads remain compatibility seams |
| Decrypt Contacts enrichment | `DecryptionService` signer lookup / identity resolution | enrichment | conditional | conditional | Plaintext may complete; signature verification reports missing Contacts context or signer certificate accurately | Contacts PR2, Contacts PR3 | PR3 covered: enrichment reads use gated verification context and report Contacts context unavailable while locked |
| Password-message Contacts enrichment | `PasswordMessageService.decryptMessage(...)` signer lookup / identity resolution | enrichment | conditional | conditional | Password decrypt may complete; signed-message verification reports missing Contacts context or signer certificate accurately | Contacts PR2, Contacts PR3 | PR3 covered: mirrors ordinary decrypt semantics for signed SKESK flows |
| Verify route Contacts-aware verification | `Verify` route via `SigningService` verify helpers | enrichment | conditional | conditional | Route requires required verification context before presenting final contacts-aware result | Contacts PR2, Contacts PR3 | PR3 covered at service level: gated verification context distinguishes missing context from invalid signatures |
| Certificate-signature target contact access | legacy `ContactCertificateSignaturesScreenModel.contact`; `ContactCertificationDetailsScreenModel` | read | yes | yes | Route blocked or explicit Contacts opening / locked state | Contacts PR3, Contacts PR6 | PR3 covered availability-aware lookup; PR6 added contact-centered details lookup by contact ID/key ID |
| Certificate-signature verification-time candidate signer read | `CertificateSignatureService` gated candidate signer certificate loading | read | yes | yes | Verification cannot consume Contacts-backed candidate signer certificates until the Contacts domain is available | Contacts PR3 | PR3 covered: service throws Contacts unavailable instead of reading Contacts-backed `candidateSigners` while locked |
| Certification summary read | Contact Detail trust/certification summary and key summary rows | read | yes | yes | Show opening / locked / recovery-needed state rather than stale certification summary | Contacts PR6 | PR6 covered: summaries read protected projection state and keep manual verification separate |
| Certification details read | `ContactCertificationDetailsView` / `ContactCertificationDetailsScreenModel` | read | yes | yes | Show opening / locked / recovery-needed state rather than empty history | Contacts PR6 | PR6 covered: contact-centered route shows saved history and details |
| Certificate-signature signer identity and projection enrichment | `CertificateSignatureService` signer identity resolution and certification projection through Contacts | enrichment | conditional | conditional | Contacts enrichment blocked until available; framework unavailable stays distinct | Contacts PR2, Contacts PR3, Contacts PR6 | PR6 covered: validation helpers return persistable metadata; Contacts persists projection/artifacts after explicit save |

## 4. Mutation Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Add Contact import inspection | `AddContactScreenModel`, `PublicKeyImportLoader`, URL/QR/file inspection | mutation | no | no | Allow key inspection and preview without Contacts unlock | Contacts PR3 | Inspection of candidate public key bytes is not itself a Contacts domain write |
| Add Contact import commit | `ContactImportWorkflow.importContact(...)` | mutation | yes | yes | Pre-commit preview may remain visible, but commit requires Contacts unlock | Contacts PR3 | PR3 covered: commit reaches gated `ContactService.addContact(...)`; inspection remains ungated |
| URL-based contact import commit | `IncomingURLImportCoordinator.handleIncomingURL(...)` -> import confirmation success path | mutation | yes | yes | URL parsing may happen before unlock; final import commit requires Contacts unlock | Contacts PR3 | PR3 covered through shared import workflow gating |
| Confirm key replacement / same-user update | `ContactImportWorkflow.confirmReplacement(...)`; protected import candidate matching | mutation | yes | yes | Block replacement until Contacts unlock; same-user different-fingerprint imports create separate identities with candidate matches | Contacts PR3, Contacts PR5 | PR3 covered through gated replacement confirmation; PR5 covered protected-domain same-fingerprint in-place update and no automatic same-user replacement |
| Delete contact | `ContactsView` delete, `ContactDetailView` destructive action, `ContactService.removeContactIdentity(...)` / compatibility `removeContact(...)` | mutation | yes | yes | Show explicit locked or framework-unavailable state; never best-effort delete while locked | Contacts PR3, Contacts PR5 | PR3 covered gated mutation API; PR5 covered identity-level removal while preserving key-level compatibility removal |
| Manual verification promotion | `ContactDetailView` key row -> `ContactService.setVerificationState(...)` | mutation | yes | yes | Unlock required before mutation; no shadow write path | Contacts PR3, Contacts PR5 | PR3 covered gated mutation API; PR5 keeps manual verification per key record |
| Certify this contact | Contact Detail primary action to `ContactCertificationDetailsView` | mutation | yes | yes | Requires Contacts availability and private-key access according to existing signing rules | Contacts PR6 | PR6 covered: generates a User ID certification, verifies it, saves the valid artifact, and exposes explicit export |
| Save imported certification signature | certification details secondary import action | mutation | yes | yes | Preview may inspect external signature first; commit requires Contacts availability | Contacts PR6 | PR6 covered: text/file import previews and verifies before showing `Save Signature` |
| Merge contacts | `ContactDetailView` merge entry + `ContactService.mergeContact(sourceContactId:into:)` | mutation | yes | yes | Unlock required; explicit merge workflow only | Contacts PR5 | PR5 covered: current/detail identity survives, source keys move, tags and recipient-list memberships union |
| Preferred key management | `ContactDetailView` key rows + `ContactService.setPreferredKey(...)` / `setKeyUsageState(...)` | mutation | yes | yes | Unlock required; must preserve deterministic preferred/additional/historical rules | Contacts PR5 | PR5 covered: preferred/additional must be encryptable, historical excluded from recipient resolution but retained for signer recognition |
| Tag management | future Contacts detail / filter management | mutation | yes | yes | Unlock required | Contacts PR8 | Tags belong to `ContactIdentity` layer |
| Recipient-list management | future Contacts list/detail management surfaces | mutation | yes | yes | Unlock required | Contacts PR8 | Lists bind to `ContactIdentity`, not fingerprints |

## 5. Migration, Certification, And Maintenance Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Certification projection revalidation on unlock | Contacts unlock flow + revalidation helper | maintenance | yes | yes | Runs after open as needed; failures must not be misrepresented as empty Contacts state | Contacts PR6 | PR6 covered: projections are recomputed after protected Contacts open and through reusable `ContactService` hooks |
| Legacy plaintext migration read | migration coordinator reading `.gpg` files and `contact-metadata.json` | maintenance | conditional | yes | Old source remains authoritative until target readability is proven | Contacts PR4 | Reads legacy plaintext without treating it as the final source after cutover |
| Quarantine management | migration coordinator quarantine paths | maintenance | yes | yes | Quarantine is inactive for normal Contacts display and resolution | Contacts PR4 | No ordinary route may read quarantine as active source |
| Final legacy deletion | post-cutover cleanup after later successful Contacts domain open | maintenance | yes | yes | Delete only after later successful open confirmation | Contacts PR4 | Avoids destructive deletion on first cutover success |
| Local data reset | `LocalDataResetService.resetAllLocalData(...)` | maintenance | no | yes | Delete legacy Contacts and protected Contacts artifacts, and clear `ContactService` runtime state | Contacts PR4 | Current reset already deletes legacy contacts directory and clears in-memory Contacts state |
| Tutorial / test sandbox Contacts stores | `TutorialSandboxContainer`, UI test preload helpers | maintenance | no | no | Remain isolated from real protected Contacts migration | Contacts PR4 | Sandbox contacts are test/tutorial data, not production protected-domain state |

## 6. Surfaces Explicitly Not Treated As Contacts Domain Access

These repository behaviors remain important, but they are not ordinary Contacts domain access surfaces in the target design:

| Surface | Reason |
|---------|--------|
| Pre-auth registry bootstrap | May inspect only framework-readable metadata, never Contacts payload content or the root-secret Keychain item |
| Public-key inspection before import commit | Examines incoming key bytes, not existing Contacts domain state |
| Plaintext decrypt and signature packet detection | May remain meaningful without Contacts, but signature verification and signer identity must not be reported complete without a suitable verification certificate |

## 7. Inventory Acceptance Criteria

This inventory is only complete if later implementers can use it to answer all of the following without rediscovering repository state manually:

- which current entrypoints directly touch Contacts behavior
- which surfaces are reads vs mutations vs maintenance actions vs optional enrichment
- which surfaces can partially operate while Contacts is opening, locked, or unavailable
- which surfaces must wait for Contacts unlock before commit
- which PR will own each surface during later implementation

Future implementation PRs should update this document whenever:

- a surface changes owner
- a new Contacts-dependent route is introduced
- a locked-state behavior becomes more specific
- a row moves from current-state inventory to implemented coverage notes

## 8. Contacts PR3-PR4 Coverage Notes

Contacts PR3 covers the lifecycle and access-gating rows without changing the source of truth:

- pre-auth startup defers legacy Contacts loading and records `startup.contacts.load.deferred`
- app post-auth wiring maps `ProtectedDataPostUnlockOutcome + ProtectedDataSessionCoordinator.frameworkState` into a dedicated Contacts post-auth gate result
- eligible post-auth gates open the legacy compatibility source; ineligible gates clear runtime state and expose `.locked`, `.frameworkUnavailable`, or `.restartRequired`
- `ContactService` exposes availability-aware reads, lookups, recipient resolution, and mutations; production code no longer uses raw legacy load or direct runtime Contacts storage
- Contacts list, detail, Encrypt recipient selection, import commit, delete, manual verification, certificate-signature route entry, and certificate-signature candidate signer reads are blocked when Contacts is unavailable
- Decrypt, password decrypt, and Verify-style service flows preserve plaintext or parse results where appropriate while reporting Contacts context unavailable for Contacts-backed verification/enrichment
- legacy compatibility load is atomic and fail-closed: any load, validation, projection, or metadata-save failure clears contacts, verification states, and compatibility projection before setting `.recoveryNeeded`

Contacts PR4 then moves the flat compatibility snapshot into the protected `contacts` domain, migrates and quarantines legacy plaintext, prevents ordinary reads from falling back to legacy or quarantine after cutover, deletes quarantine only after a later successful protected-domain open, and preserves Contacts runtime/projection cleanup on relock and reset.

Contacts PR5 then moves ordinary Contacts UI and Encrypt behavior to person-centered `ContactIdentity` semantics, adds explicit merge and preferred/additional/historical key management, and keeps flat `Contact` rows as compatibility projection only.

Contacts PR6 adds protected persistence for valid certification artifacts, recomputes per-key OpenPGP certification projection from saved records, exports saved canonical signature bytes as armor on demand, revalidates projection after protected Contacts open, and replaces the ordinary fingerprint-first Certificate Signatures entry with a contact-centered certification details route. Contact Detail now shows manual fingerprint verification and OpenPGP certification as separate signals, `Certify This Contact` saves a validated generated User ID certification only after the user runs that action, and external `.asc` / `.sig` import remains preview-first until `Save Signature` is explicitly chosen.

Contacts PR7 package exchange is withdrawn and has no active inventory rows. Remaining follow-on work still includes search, tags, recipient-list UI, and organization workflows. Any future complete Contacts backup or device migration must be designed separately as a mandatory encrypted feature before it receives inventory coverage.
