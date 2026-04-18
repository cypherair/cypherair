# Rust / FFI App-Surface Adoption Plan

> Status: Active product-scoped plan for the remaining app-surface adoption work on shipped Rust / FFI service families.
> Purpose: Define the next UI-owned workflow to add on top of the current Rust / FFI service baseline without re-planning work that is already landed in the app.
> Audience: Human developers, reviewers, designers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_BASELINE](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_SERVICE_INTEGRATION_PLAN](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)
> Plan posture: This document covers remaining app-surface adoption work only. It is not a statement that every Rust / FFI capability family still lacks UI ownership.

## 1. Role And Scope

This document now assumes the following app-surface work is already shipped:

- detailed verify results in `VerifyView` / `VerifyScreenModel`
- detailed decrypt results in `DecryptView` / `DecryptScreenModel`
- key-scoped selective revocation launched from `KeyDetailView`

This document does not re-plan those shipped paths.

## 2. Current Shipped Baseline

### 2.1 Verify And Decrypt

- `VerifyScreenModel` already calls `SigningService.verifyCleartextDetailed(...)` and `verifyDetachedStreamingDetailed(...)`.
- `DecryptScreenModel` already calls `DecryptionService.decryptDetailed(...)` and `decryptFileStreamingDetailed(...)`.
- Both routes render `DetailedSignatureSectionView` while preserving the current legacy summary-first presentation through the detailed result's legacy bridge.

### 2.2 Selective Revocation

- `KeyDetailView` already launches `AppRoute.selectiveRevocation(fingerprint:)`.
- `SelectiveRevocationView` and `SelectiveRevocationScreenModel` own selector discovery, export orchestration, and export-controller integration for subkey and User ID revocation.
- `MacUISmokeTests` already cover the main key-detail launch path.
- Tutorial surfaces explicitly block this route instead of relying on missing navigation support.

### 2.3 Remaining Gaps

- `ContactDetailView` still exposes no certificate-signature tooling.
- `PasswordMessageService` still has no app route, no screen-model owner, and no user-facing plaintext/export contract.

## 3. Adoption Target For The Next Round

The next app-adoption round should target one family only:

- introduce a contact-scoped certificate-signature workflow from `ContactDetailView`

This round does not target:

- a new top-level tab or global certificate-signature utility
- password-message UI
- changes to the shipped verify/decrypt detailed-result UI
- changes to the shipped selective-revocation flow

## 4. Fixed Product Decisions

### 4.1 Entry Point And Ownership

- `ContactDetailView` remains the launcher.
- The workflow should live behind a dedicated route and dedicated screen model rather than being inlined into the contact-detail page body.
- Views and screen models must continue to call `CertificateSignatureService`, not `PgpEngine`.

### 4.2 Workflow Scope

The contact-scoped workflow may expose:

- direct-key signature verification against the contact certificate
- User ID binding verification against a selected User ID on the contact certificate
- User ID certification generation using one of the user's own keys

The workflow should not:

- automatically insert generated certification signatures back into a stored certificate
- automatically change `Contact.isVerified`
- introduce trust or web-of-trust policy semantics
- infer selectors from display text instead of using service-provided selector-bearing metadata

### 4.3 Security And Boundary Rules

- Selector discovery and selector validation must stay pre-auth and service-owned.
- Certification generation remains secret-sensitive because it unwraps the user's own secret certificate through `KeyManagementService`.
- The UI should treat generated certification output as exported artifact bytes, not as an in-place contact mutation.

## 5. Validation Expectations

- Add screen-model tests for route ownership, selector-loading state, export flow, and failure presentation.
- Add at least one macOS UI smoke path for launching the new contact-scoped route.
- Preserve the current tutorial and main-app route blocklist semantics if the new route is reachable from tutorial-owned surfaces.

## 6. Deferred Work

- `PasswordMessageService` app exposure stays deferred pending a separate product-scoped plan.
- Any richer certificate-management or trust workflow beyond the scoped contact-detail tool remains deferred.
