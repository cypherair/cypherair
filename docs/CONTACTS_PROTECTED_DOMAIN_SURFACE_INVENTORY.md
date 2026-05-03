# Contacts Protected Domain Surface Inventory

> **Version:** Draft v0.1
> **Status:** Draft implementation-prep checklist. This document does not describe current shipped behavior.
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
- whether each surface is a domain read, mutation, package action, maintenance action, or optional Contacts enrichment
- what the locked-state behavior must be
- whether framework gating is required

## 2. Classification Rules

Each row in the inventory uses the following concepts.

### 2.1 Surface Type

- `read` — needs Contacts domain content for ordinary user-visible behavior
- `mutation` — changes Contacts domain content
- `package` — selected-contact `.cypherair-contacts` package export/import preview/commit
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
| Pre-auth startup bootstrap | `AppStartupCoordinator.performPreAuthBootstrap(...)` | read | no | bootstrap-only | Must not open Contacts domain payload; may only use registry/bootstrap metadata | Contacts PR3 | Current code still loads Contacts during pre-auth startup and must stop doing so |
| Contacts root list | `ContactsView` + `ContactService.loadContacts()` | read | yes | yes | Show explicit Contacts locked / recovery-needed / framework-unavailable state instead of empty list | Contacts PR3 | Current `.task`-based load bypasses future gate |
| Contact detail lookup | `ContactDetailView` + `contactService.contact(forFingerprint:)` | read | yes | yes | Route blocked or explicit locked-state presentation; never nil-as-not-found because domain is locked | Contacts PR3 | Current view treats missing contact and unavailable domain too similarly |
| Encrypt recipient browsing | `EncryptView` / `EncryptScreenModel.encryptableContacts` | read | yes | yes | Show explicit Contacts locked recipient state with unlock CTA | Contacts PR3 | Current recipient list assumes startup-loaded Contacts |
| Encrypt recipient resolution | `EncryptionService` recipient fingerprint -> public key lookup | read | yes | yes | Encryption cannot proceed until Contacts domain is available | Contacts PR3, Contacts PR5 | Later Contacts PR5 changes resolution to contact-identity/preferred-key semantics |
| Decrypt Contacts enrichment | `DecryptionService` signer lookup / identity resolution | enrichment | conditional | conditional | Plaintext may complete; signature verification reports missing Contacts context or signer certificate accurately | Contacts PR2, Contacts PR3 | Verification accuracy and Contacts enrichment are intentionally split |
| Password-message Contacts enrichment | `PasswordMessageService.decryptMessage(...)` signer lookup / identity resolution | enrichment | conditional | conditional | Password decrypt may complete; signed-message verification reports missing Contacts context or signer certificate accurately | Contacts PR2, Contacts PR3 | Mirrors ordinary decrypt semantics for signed SKESK flows |
| Verify route Contacts-aware verification | `Verify` route via `SigningService` verify helpers | enrichment | conditional | conditional | Route requires required verification context before presenting final contacts-aware result | Contacts PR2, Contacts PR3 | Service contract distinguishes missing context from invalid signatures |
| Certificate-signature target contact access | current `ContactCertificateSignaturesScreenModel.contact`; future certification details flow | read | yes | yes | Route blocked or explicit Contacts opening / locked state | Contacts PR3, Contacts PR6 | Target certificate remains Contacts-owned state |
| Certificate-signature verification-time candidate signer read | `CertificateSignatureService` candidate signer certificate loading via `contactService.contacts` | read | yes | yes | Verification cannot consume Contacts-backed candidate signer certificates until the Contacts domain is available | Contacts PR3 | Current service passes Contacts certificates into the engine as `candidateSigners`; this is verification input, not just UI enrichment |
| Certification summary read | future Contact Detail trust/certification summary | read | yes | yes | Show opening / locked / recovery-needed state rather than stale certification summary | Contacts PR6 | Summary reads protected projection state |
| Certification details read | redesigned certification details surface | read | yes | yes | Show opening / locked / recovery-needed state rather than empty history | Contacts PR6 | Replaces the current three-mode technical page with saved history and details |
| Certificate-signature signer identity and projection enrichment | `CertificateSignatureService` signer identity resolution and certification projection through Contacts | enrichment | conditional | conditional | Contacts enrichment blocked until available; framework unavailable stays distinct | Contacts PR2, Contacts PR3, Contacts PR6 | Contacts PR6 lands projection/artifact persistence and redesigned UX |

## 4. Mutation Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Add Contact import inspection | `AddContactScreenModel`, `PublicKeyImportLoader`, URL/QR/file inspection | mutation | no | no | Allow key inspection and preview without Contacts unlock | Contacts PR3 | Inspection of candidate public key bytes is not itself a Contacts domain write |
| Add Contact import commit | `ContactImportWorkflow.importContact(...)` | mutation | yes | yes | Pre-commit preview may remain visible, but commit requires Contacts unlock | Contacts PR3 | Current workflow writes directly through `ContactService.addContact(...)` |
| URL-based contact import commit | `IncomingURLImportCoordinator.handleIncomingURL(...)` -> import confirmation success path | mutation | yes | yes | URL parsing may happen before unlock; final import commit requires Contacts unlock | Contacts PR3 | Current coordinator reaches import workflow directly |
| Confirm key replacement / same-user update | `ContactImportWorkflow.confirmReplacement(...)` | mutation | yes | yes | Block replacement until Contacts unlock | Contacts PR3, Contacts PR5 | Later Contacts PR5 changes replacement semantics under person-centered model |
| Delete contact | `ContactsView` delete, `ContactDetailView` destructive action, `ContactService.removeContact(...)` | mutation | yes | yes | Show explicit locked or framework-unavailable state; never best-effort delete while locked | Contacts PR3 | Current deletes hit plaintext storage directly |
| Manual verification promotion | `ContactDetailView` -> `ContactService.setVerificationState(...)` | mutation | yes | yes | Unlock required before mutation; no shadow write path | Contacts PR3 | Manual verification remains distinct from certification |
| Certify this contact | future Contact Detail primary certification action | mutation | yes | yes | Requires Contacts availability and private-key access according to existing signing rules | Contacts PR6 | Generates and saves certification projection plus signature artifact |
| Save imported certification signature | redesigned certification details secondary import action | mutation | yes | yes | Preview may inspect external signature first; commit requires Contacts availability | Contacts PR6 | Covers current text/file external signature verification capability |
| Merge contacts | future Contacts management surfaces | mutation | yes | yes | Unlock required; explicit merge workflow only | Contacts PR5 | Not yet implemented in current code |
| Preferred key management | future Contacts detail or merge follow-up surfaces | mutation | yes | yes | Unlock required; must preserve deterministic preferred/additional/historical rules | Contacts PR5 | Depends on person-centered model |
| Tag management | future Contacts detail / filter management | mutation | yes | yes | Unlock required | Contacts PR8 | Tags belong to `ContactIdentity` layer |
| Recipient-list management | future Contacts list/detail management surfaces | mutation | yes | yes | Unlock required | Contacts PR8 | Lists bind to `ContactIdentity`, not fingerprints |

## 5. Package, Migration, Certification, And Maintenance Surfaces

| Surface | Current entrypoints | Type | Target unlock requirement | Framework gate | Locked-state target behavior | Planned PR | Notes |
|---------|---------------------|------|---------------------------|----------------|------------------------------|------------|-------|
| Contact Detail single-contact export | future Contact Detail export action | package | yes | yes | Requires unlocked Contacts plus fresh authentication immediately before export | Contacts PR7 | Exports one contact into `.cypherair-contacts`; public-derived labels are default, local relationship/custom labels require explicit default-off selection |
| Contacts list multi-select export | future Contacts list selection mode | package | yes | yes | Requires unlocked Contacts plus fresh authentication immediately before export | Contacts PR7 | Exports one or more selected contacts into one package; local relationship/custom labels require explicit default-off selection |
| Contact package import preview | future package import route / file importer | package | no | conditional | Parse and preview without Contacts mutation; framework gate is required only for later commit | Contacts PR7 | Reject malformed packages before preview; imported labels are untrusted preview hints |
| Contact package import commit | future package import confirmation | package | yes | yes | Commit blocked until Contacts domain is available | Contacts PR7 | Creates/updates contacts through protected-domain write path; never whole-domain restore |
| Certification projection revalidation on unlock | Contacts unlock flow + revalidation helper | maintenance | yes | yes | Runs after open as needed; failures must not be misrepresented as empty Contacts state | Contacts PR6 | Separate from raw crypto verification |
| Certification projection revalidation on package import | package import commit finalization | maintenance | yes | yes | Rebuild projected state deterministically after commit | Contacts PR6, Contacts PR7 | Import and certification responsibilities meet here |
| Legacy plaintext migration read | migration coordinator reading `.gpg` files and `contact-metadata.json` | maintenance | conditional | yes | Old source remains authoritative until target readability is proven | Contacts PR4 | Reads legacy plaintext without treating it as the final source after cutover |
| Quarantine management | migration coordinator quarantine paths | maintenance | yes | yes | Quarantine is inactive for normal Contacts display and resolution | Contacts PR4 | No ordinary route may read quarantine as active source |
| Final legacy deletion | post-cutover cleanup after later successful Contacts domain open | maintenance | yes | yes | Delete only after later successful open confirmation | Contacts PR4 | Avoids destructive deletion on first cutover success |
| Local data reset | `LocalDataResetService.resetAllLocalData(...)` | maintenance | no | yes | Delete legacy Contacts, protected Contacts artifacts, package temporary artifacts, and clear `ContactService` runtime state | Contacts PR4, Contacts PR7 | Current reset already deletes legacy contacts directory and clears in-memory Contacts state |
| Tutorial / test sandbox Contacts stores | `TutorialSandboxContainer`, UI test preload helpers | maintenance | no | no | Remain isolated from real protected Contacts migration and package exchange | Contacts PR4 | Sandbox contacts are test/tutorial data, not production protected-domain state |
| Package temporary artifact cleanup | `AppTemporaryArtifactStore` / future package export temp files | maintenance | no | no | Temporary package files are cleaned after completion, cancellation, startup cleanup, and reset | Contacts PR7 | Mirrors existing protected export handoff expectations |

## 6. Surfaces Explicitly Not Treated As Contacts Domain Access

These repository behaviors remain important, but they are not ordinary Contacts domain access surfaces in the target design:

| Surface | Reason |
|---------|--------|
| Pre-auth registry bootstrap | May inspect only framework-readable metadata, never Contacts payload content or the root-secret Keychain item |
| Public-key inspection before import commit | Examines incoming key bytes, not existing Contacts domain state |
| Plaintext decrypt and low-level claimed/observed signer evidence extraction | May remain meaningful without Contacts, but signature verification must not be reported complete without a suitable verification certificate |

## 7. Inventory Acceptance Criteria

This inventory is only complete if later implementers can use it to answer all of the following without rediscovering repository state manually:

- which current entrypoints directly touch Contacts behavior
- which surfaces are reads vs mutations vs package actions vs maintenance actions vs optional enrichment
- which surfaces can partially operate while Contacts is opening, locked, or unavailable
- which surfaces must wait for Contacts unlock before commit
- which PR will own each surface during later implementation

Future implementation PRs should update this document whenever:

- a surface changes owner
- a new Contacts-dependent route is introduced
- a locked-state behavior becomes more specific
- a row moves from current-state inventory to implemented coverage notes
