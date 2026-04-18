# Rust / FFI App-Surface Adoption Plan

> Status: Active product-scoped plan for adopting newly integrated Rust / FFI capability families at the SwiftUI app surface.
> Purpose: Define the app routes, screen-model ownership, workflow shape, export UX, validation, and review posture for selected Rust / FFI capabilities that are already integrated at the Swift service boundary.
> Audience: Human developers, reviewers, designers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_PLAN](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [RUST_FFI_SERVICE_INTEGRATION_BASELINE](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> Plan posture: This document fixes the intended app-surface design for the next UI adoption round. It is a documentation baseline and implementation guide for future work, not a statement that the current UI already behaves this way.

## 1. Role And Scope

This document is the product-scoped follow-on plan to [RUST_FFI_SERVICE_INTEGRATION_PLAN.md](RUST_FFI_SERVICE_INTEGRATION_PLAN.md).

Use the service-integration documents for:

- which Rust / FFI families already exist
- which Swift services own them today
- which service-boundary decisions are already frozen
- which semantic and security constraints were fixed before app adoption

Use this document for:

- which existing app surfaces will adopt those service capabilities
- which new routes and new screens will be introduced
- which existing screen models remain in place and how they change
- how export-oriented workflows should behave at the UI boundary
- which behaviors remain intentionally deferred
- what validation and human review must accompany later implementation

This document intentionally fixes app-surface decisions only.

- It does not redefine Rust / FFI wire shapes, parser semantics, selector semantics, or cryptographic rules that are already fixed in the service and reference documents.
- It does not replace [SECURITY.md](SECURITY.md) or [TESTING.md](TESTING.md).
- It does not authorize unrelated UI cleanup, route refactoring, or service rewrites.
- It does not change the current rule that views and view models must consume Swift services rather than call `PgpEngine` directly.

Current planning posture is `service-complete / app-adoption-next`.

- The relevant downstream service families landed first.
- Existing UI still uses legacy summary-oriented behavior on the currently shipped paths.
- This document defines the next adoption step at the app boundary without reopening the completed service-layer rollout.

## 2. Current State Snapshot

### 2.1 Recently Landed Service Families

Between April 16, 2026 and April 17, 2026, the current repository landed the shared selector-discovery prerequisite plus the four service families that matter for the next app-adoption round.

Shared prerequisite:

- selector discovery support and selector-bearing Swift metadata for subkeys and User IDs

Relevant service families:

- `CertificateSignatureService`
- additive detailed-result APIs in `SigningService`
- additive selective-revocation APIs in `KeyManagementService`
- additive detailed-result APIs in `DecryptionService`

The current rollout baseline is therefore no longer "missing service ownership." It is now "service ownership exists, app ownership is mostly still absent."

### 2.2 Current App-Surface Baseline

The current UI baseline remains mostly legacy-summary driven.

- `VerifyView` and `VerifyScreenModel` still present one folded verification result even though `SigningService` now exposes detailed verification results.
- `DecryptView` and `DecryptScreenModel` still present one folded signature result even though `DecryptionService` now exposes detailed decrypt verification results.
- `KeyDetailView` exposes key-level revocation export only and has no UI path for selective subkey or User ID revocation.
- `ContactDetailView` exposes no certificate-signature tooling and no route into certificate-signature workflows.
- No current route exists for a key-scoped selective-revocation screen.
- No current route exists for a contact-scoped certificate-signatures tool screen.
- `PasswordMessageService` exists in the dependency container, but there is still no app route, no screen-model owner, and no UI-boundary plaintext/export contract for it.

### 2.3 Adoption Target For This Round

This app-adoption round targets the following:

- adopt detailed signature results in `Verify`
- adopt detailed signature results in `Decrypt`
- introduce a selective-revocation workflow from `KeyDetail`
- introduce a certificate-signatures workflow from `ContactDetail`

This round does not target `PasswordMessageService`.

## 3. Fixed Product Decisions

### 3.1 Round Scope

In scope:

- `Verify` detailed-result adoption
- `Decrypt` detailed-result adoption
- selective revocation from existing key-management surfaces
- certificate-signature workflows from existing contact-management surfaces
- additive route, view, and screen-model work needed to support those flows

Out of scope:

- `PasswordMessageService` UI
- a new top-level tab or top-level tool category
- a global certificate-signature utility detached from contacts
- integrating certificate-signature tools into `AddContactView` or the contact-import confirmation flow
- automatic application of generated certification signatures back into target certificates
- automatic changes to `Contact.isVerified` based on certificate-signature verification results
- any persisted selective-revocation artifact store beyond the already-existing key-level revocation field
- any trust or web-of-trust policy semantics

### 3.2 UI Adoption Philosophy

This round keeps the current presentation model recognizable.

- The current top-level app structure stays intact.
- `Verify` and `Decrypt` keep their current primary task shapes and current top summary result presentation.
- New advanced flows are reached from existing detail pages rather than from new top-level navigation surfaces.
- Detailed information becomes additive and collapsible; it does not replace the current summary-first presentation.

### 3.3 Service-Boundary Rules At The UI Layer

The UI adoption work must preserve the current architectural boundary.

- Views and screen models do not call `PgpEngine`.
- Armored-input normalization and armored-export wrapping belong in service helpers, not in views.
- Any new UI-oriented service helpers must be additive. They must not replace or weaken the existing raw-byte service APIs.
- Selector-bearing choices shown in UI must come from `selectionCatalog(...)` discovery support. They must not be reconstructed from display strings, lossy labels, or inferred ordering.
- Any selector validation that can happen before authentication must still happen before authentication.
- `DecryptionService` UI adoption must not alter the current Phase 1 / Phase 2 boundary.

## 4. UI Ownership And Routes

### 4.1 `Verify`

`VerifyView` remains the existing route and the existing app entry point for message-signature verification.

Ownership decisions fixed here:

- keep `VerifyView` as the page
- keep `VerifyScreenModel` as the workflow owner
- do not add a new route for detailed verification
- migrate the screen model's internal verification state from legacy-only results to `DetailedSignatureVerification`
- keep the page's first visible result card driven by `legacyVerification`
- add a reusable, collapsible detailed-signature section below the existing summary result when `signatures` is not empty

This round intentionally treats detailed verification as deeper visibility into the current workflow, not as a different tool.

### 4.2 `Decrypt`

`DecryptView` remains the existing route and the existing app entry point for message decryption.

Ownership decisions fixed here:

- keep `DecryptView` as the page
- keep `DecryptScreenModel` as the workflow owner
- do not add a new route for detailed decrypt verification
- migrate the screen model's internal signature state from legacy-only results to `DetailedSignatureVerification`
- keep the page's first visible signature summary driven by `legacyVerification`
- add a reusable, collapsible detailed-signature section below the current summary result when `signatures` is not empty
- keep `DecryptView.Configuration.onDecrypted` on its current `(Data, SignatureVerification)` contract by deriving the callback payload from the detailed result's legacy bridge

This preserves current external app contracts while letting the page itself show richer information.

### 4.3 `KeyDetail` To Selective Revocation

Selective revocation becomes an advanced key-management route reached from `KeyDetail`.

Route decision fixed here:

- add `AppRoute.selectiveRevocation(fingerprint: String)`

Ownership decisions fixed here:

- add a navigation entry in `KeyDetailView`
- keep `KeyDetailScreenModel` responsible only for launching the route, not for owning the selective-revocation workflow state
- introduce `SelectiveRevocationView`
- introduce `SelectiveRevocationScreenModel`

The new page is key-scoped:

- it is entered with one key fingerprint
- it loads selector-bearing metadata from `KeyManagementService.selectionCatalog(fingerprint:)`
- it handles export-only workflows for subkey and User ID revocation

This is intentionally a separate advanced page rather than inline expansion inside `KeyDetailView`.

### 4.4 `ContactDetail` To Certificate Signatures

Certificate-signature workflows become an advanced contact-scoped tool page reached from `ContactDetail`.

Route decision fixed here:

- add `AppRoute.certificateSignatures(fingerprint: String)`

Ownership decisions fixed here:

- add a navigation entry in `ContactDetailView`
- keep `ContactDetailView` as the launcher only
- introduce `CertificateSignaturesView`
- introduce `CertificateSignaturesScreenModel`

The new page is contact-scoped:

- it resolves the target certificate from the selected contact's `publicKeyData`
- it does not ask the user to browse arbitrary target certificates
- it does not modify the add-contact flow

### 4.5 New Shared UI Components

This round may introduce shared presentation helpers where reuse is clear, but only for the workflows in scope.

Shared ownership decisions fixed here:

- the detailed per-signature display used by `Verify` and `Decrypt` should be implemented as one reusable app-layer component rather than duplicated page-specific markup
- certificate-signature result presentation should use certificate-signature-specific UI rather than reusing message-signature cards unchanged
- any new shared UI helpers remain presentation-only and do not absorb service or workflow logic

## 5. Workflow Specs

### 5.1 `Verify` Detailed Results

`Verify` adopts detailed-result service APIs without changing its top-level user task.

Workflow decisions fixed here:

- cleartext verification switches to `SigningService.verifyCleartextDetailed(...)`
- detached verification switches to `SigningService.verifyDetachedStreamingDetailed(...)`
- the screen model stores the full `DetailedSignatureVerification`
- the existing summary section uses `legacyVerification`
- the new detailed section appears only when `signatures` is not empty
- the detailed list preserves parser order exactly as supplied by the service
- repeated signers remain separate entries
- unknown signers remain separate entries and do not receive invented fingerprints
- the current import, progress, cancellation, and error-presentation patterns remain unchanged

The detailed UI is additive:

- users still get the current one-line summary first
- users can expand into per-signature detail when needed
- no current route, importer, or file-selection UX is replaced

### 5.2 `Decrypt` Detailed Results

`Decrypt` adopts detailed-result service APIs without changing its two-phase structure.

Workflow decisions fixed here:

- text decryption keeps the current Phase 1 recipient parse step unchanged
- file decryption keeps the current Phase 1 recipient parse step unchanged
- text decrypt switches its Phase 2 call to `DecryptionService.decryptDetailed(...)`
- file decrypt switches its Phase 2 call to `DecryptionService.decryptFileStreamingDetailed(...)`
- the screen model stores the full `DetailedSignatureVerification`
- the existing signature summary section uses `legacyVerification`
- the new detailed section appears only when `signatures` is not empty
- the screen model continues to zeroize plaintext buffers after callback delivery on current text paths
- the file path keeps current streaming progress, cancellation, temp-file cleanup, and export behavior unchanged

This round does not reinterpret the security model.

- Phase 1 still performs recipient matching without authentication.
- Phase 2 still performs authenticated private-key access and decrypt.
- The detailed result is a richer report about the same authenticated decrypt path, not a second decrypt mode.

### 5.3 Selective Revocation

Selective revocation is an export-oriented advanced workflow from `KeyDetail`.

Workflow decisions fixed here:

- entering the page loads selector-bearing metadata from `KeyManagementService.selectionCatalog(fingerprint:)`
- page load uses public certificate data only and must not trigger authentication
- the page shows subkey and User ID choices derived from the selector catalog
- the page does not fabricate selector values and does not accept manual selector entry
- subkey and User ID revocation remain separate user actions
- actual export calls `exportSubkeyRevocationCertificate(...)` or `exportUserIdRevocationCertificate(...)`
- only the export action may trigger device authentication
- exported output goes through the existing file-export pattern
- the flow remains export-on-demand only and must not persist a new revocation artifact in app state

This page is intentionally not a general key-maintenance editor.

- it does not modify key metadata
- it does not apply revocations back into the stored certificate
- it does not replace the existing key-level revocation export action

### 5.4 Certificate Signatures

Certificate-signature workflows are grouped into one contact-scoped tool page.

The page supports exactly three modes:

1. direct-key signature verification
2. User ID binding signature verification
3. User ID certification export

Workflow decisions fixed here:

- the page resolves its target certificate from the selected contact
- direct-key verification accepts pasted or file-imported signature input
- User ID binding verification accepts pasted or file-imported signature input
- User ID-driven modes load `CertificateSignatureService.selectionCatalog(targetCert:)`
- User ID-driven modes require the user to choose from the discovered `userIds` list
- certification generation requires the user to choose one of the user's own keys as signer
- certification generation requires the user to choose one `CertificationKind`
- certification export produces an ASCII-armored signature export through an additive service helper layered on top of the existing raw-byte API

The page does not do any of the following:

- it does not mutate the contact's stored certificate
- it does not mutate the contact's verification state
- it does not claim policy validity or trust semantics beyond the crypto-only result returned by the service
- it does not generalize into a global certificate browser

### 5.5 Additive Certificate-Signature Service Conveniences

The current service surface is almost sufficient for UI adoption, but one additive convenience layer is intentionally part of the app-surface plan.

Service-helper decisions fixed here:

- certificate-signature verification paths should accept armored or binary signature input through a service-owned normalization helper instead of pushing dearmor logic into the UI
- certification export should use a service-owned armored-export helper layered on top of `generateUserIdCertification(...)`
- the existing raw-byte certificate-signature methods remain valid and unchanged
- these helpers may be implemented as new public methods or as public workflow wrappers backed by internal helpers, but they must remain additive

## 6. Validation And Review

### 6.1 Required Validation

Later implementation work derived from this document must preserve current service coverage and add app-layer coverage.

Minimum required validation:

- existing relevant service tests remain passing
- new screen-model tests cover detailed-result mapping and legacy-summary bridging in `Verify`
- new screen-model tests cover detailed-result mapping and legacy-summary bridging in `Decrypt`
- new screen-model tests cover selector loading and export gating for selective revocation
- new screen-model tests cover selector loading, signer selection, and export gating for certificate-signature workflows
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- at minimum one macOS UI smoke pass that exercises the new routes and their page launch path through `CypherAir-MacUITests`

### 6.2 Human Review Requirements

The following implementation work remains security- or secrecy-sensitive and requires focused human review under [SECURITY.md](SECURITY.md) and [CODE_REVIEW.md](CODE_REVIEW.md).

- any `DecryptionService` adoption work that touches the detailed decrypt path
- any app-facing work that changes how selective revocation reaches authenticated secret-key access
- any app-facing work that changes how certification generation reaches authenticated secret-key access
- any change that risks moving selector validation to after authentication instead of before it

Review posture fixed here:

- richer UI does not justify weakening pre-auth validation
- richer UI does not justify bypassing the service boundary
- export-oriented workflows remain subject to the same zero-network and no-secret-logging rules as the rest of the app

## 7. Recommended Implementation Sequence

This document is the implementation precondition for later UI work. It should be consumed in three follow-on phases.

1. Verify / Decrypt detailed UI
2. Selective Revocation UI
3. Certificate Signatures UI

Each phase should remain additive and reviewable on its own.

## 8. Deferred Items

The following items stay explicitly deferred after this document lands.

- `PasswordMessageService` UI
- adding certificate-signature workflows to `AddContactView`
- adding certificate-signature workflows to import confirmation
- automatic application of generated certification signatures to stored certificates
- automatic contact-verification-state mutation from certificate-signature results
- persistent storage for selective subkey or User ID revocations
- a global certificate-signatures route detached from `ContactDetail`
- broader trust, certification-policy, or web-of-trust semantics
- unrelated route or screen-model refactors outside the workflows in scope
