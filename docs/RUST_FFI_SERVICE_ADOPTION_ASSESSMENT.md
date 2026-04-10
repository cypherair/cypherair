# Rust / FFI Service Adoption Assessment

> Purpose: Assess how the five recently added Rust / FFI capability families are wired into the Swift services layer, app entry points, and test stack.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [RUST_SEQUOIA_INTEGRATION_TODO](RUST_SEQUOIA_INTEGRATION_TODO.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md)

## 1. Scope And Classification

This assessment follows the same five-layer review path for each family:

1. reference-document expectation
2. Rust wrapper and UniFFI export
3. Swift service adoption
4. direct app entry points under `Sources/App/`
5. Rust, FFI, and service-test coverage

This document is intentionally narrower than a cryptography audit:

- it does not re-audit Sequoia semantics that are already covered by Rust and FFI tests
- it focuses on whether service-layer adoption is complete, partial, absent, or intentionally deferred
- it treats a family as "adopted" only when production services consume the family semantics, not merely when Rust or FFI exports exist

Classification labels used below:

- `Production-adopted`: production services consume the family and expose its intended semantics
- `Production-adopted with contract gap`: production services consume the family, but an important service-layer invariant is still not enforced end-to-end
- `Service ready, app dormant`: production services exist and are tested, but no direct app entry point currently uses them
- `FFI only`: Rust and UniFFI exports exist, but there is no production service owner
- `Partial internal service use`: a production service calls into the family, but only for a subset of the family or only to recover legacy behavior
- `Documented deferred`: the current lack of service adoption matches the reference documents and is not treated as a surprise omission

## 2. Current-State Matrix

| Family | Document expectation | Current service owner | Current app entry | Current classification | Test coverage | Key gap | Suggested action |
|---|---|---|---|---|---|---|---|
| Certificate Merge / Update | Implemented in `ContactService` for same-fingerprint public updates | `ContactService` | `ContactImportWorkflow`, `AddContactView`, URL import flow in `CypherAirApp` | Production-adopted | Rust + FFI + service tests | No current service-layer gap after the contact-import public-only gate landed | Keep validating the stable contact-import public-only token and service-layer persistence guard |
| Revocation Construction | Key-level Swift adoption approved; subkey and User ID builders deferred until selector discovery exists | `KeyManagementService` for key-level only | `KeyDetailView` revocation export | Key-level production-adopted; selective builders documented deferred | Rust + FFI + key-level service tests | No current gap on the approved key-level path; selective builders have no service owner by design | Keep subkey/User ID builders deferred until selector discovery helpers and a downstream owner exist |
| Password / SKESK Symmetric Messages | Dedicated `PasswordMessageService` approved; UI exposure deferred | `PasswordMessageService` | No direct app call site found under `Sources/App/` beyond `AppContainer` construction | Service ready, app dormant | Rust + FFI + service tests | No user-facing workflow currently consumes the service | Keep deferred unless product wants a UI; when activating it, define plaintext zeroization and UX behavior explicitly |
| Certification And Binding Verification | Service adoption deferred by default | None | None | FFI only; documented deferred | Rust + FFI tests | No service owner, no app path | Keep deferred until a dedicated certificate-management or trust workflow exists |
| Richer Signature Results | Service adoption deferred; parallel detailed APIs exist for later consumers | `SigningService` uses one detailed file-verify path; no `DecryptionService` owner | `VerifyView` streaming detached verify only | Partial internal service use; externally still legacy | Rust + FFI tests, plus indirect service coverage of legacy fields only | Detailed semantics are discarded at the service boundary and are not service-tested as a family | Either adopt the family explicitly with dedicated service result types and tests, or revert the one detailed call site to the legacy API for clarity |

## 3. Family Findings

### 3.1 Certificate Merge / Update

**Expected service stance**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) Section 3.1 and [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) Section 2.1 both expect bounded same-fingerprint public-certificate update absorption in the Swift contacts flow.
- [`SEQUOIA_CAPABILITY_AUDIT.md`](SEQUOIA_CAPABILITY_AUDIT.md) records this family as implemented end-to-end.

**Current implementation evidence**

- Rust / FFI export: [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) exports `merge_public_certificate_update`.
- Production service owner: [`Sources/Services/ContactService.swift`](../Sources/Services/ContactService.swift) calls `engine.mergePublicCertificateUpdate(...)` on the same-fingerprint path and preserves `.duplicate` vs `.updated` semantics.
- App entry points: [`Sources/App/Contacts/Import/ContactImportWorkflow.swift`](../Sources/App/Contacts/Import/ContactImportWorkflow.swift), [`Sources/App/Contacts/AddContactView.swift`](../Sources/App/Contacts/AddContactView.swift), and the URL-import flow in [`Sources/App/CypherAirApp.swift`](../Sources/App/CypherAirApp.swift).
- Tests:
  - Rust: [`pgp-mobile/tests/certificate_merge_tests.rs`](../pgp-mobile/tests/certificate_merge_tests.rs)
  - FFI: [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - Service: [`Tests/ServiceTests/ContactServiceTests.swift`](../Tests/ServiceTests/ContactServiceTests.swift)

**What is aligned**

- Same-fingerprint duplicate / no-op behavior is preserved.
- Same-fingerprint update absorption covers expiry refresh, revocation updates, primary User ID changes, and new encryption subkeys.
- The app-level import workflow still keeps same-UID different-fingerprint replacement as a separate confirmation flow.

**Current service-layer guard**

- Contact import now uses a dedicated public-certificate validation helper before both UI inspection and service persistence.
- Rust / FFI exposes a public-certificate validator that rejects `cert.is_tsk()` with `InvalidKeyData` and a stable machine token for this contact-import violation.
- The Swift contact-import helper maps that token to an explicit contact-import public-certificate error instead of relying on a human-readable reason string.
- [`Sources/Services/ContactService.swift`](../Sources/Services/ContactService.swift) re-validates contact-replacement bytes inside `confirmKeyUpdate(...)` and rebuilds the authoritative `Contact` from the validated bytes, so file names, in-memory state, and verification metadata no longer trust caller-supplied contact objects.

**Assessment**

- Classification: `Production-adopted`
- The earlier contact-import public-only contract gap is now closed.

### 3.2 Revocation Construction

**Expected service stance**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) Section 3.2 and [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) Section 2.2 explicitly approve only key-level production adoption.
- Subkey and User ID revocation builders are intentionally deferred until selector discovery helpers exist.

**Current implementation evidence**

- Rust / FFI exports: [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) exports `generate_key_revocation`, `generate_subkey_revocation`, and `generate_user_id_revocation`.
- Production service owner for the approved path: [`Sources/Services/KeyManagementService.swift`](../Sources/Services/KeyManagementService.swift)
  - generation/import-time key-level revocation availability
  - lazy backfill for legacy imported keys
  - armored revocation export
- App entry point: [`Sources/App/Keys/KeyDetailView.swift`](../Sources/App/Keys/KeyDetailView.swift) uses `exportRevocationCertificate(...)`.
- Tests:
  - Rust: [`pgp-mobile/tests/revocation_construction_tests.rs`](../pgp-mobile/tests/revocation_construction_tests.rs)
  - FFI: [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - Service: [`Tests/ServiceTests/KeyManagementServiceTests.swift`](../Tests/ServiceTests/KeyManagementServiceTests.swift)

**What is aligned**

- Key-level revocation generation is fully wired into the approved import/export flows.
- Imported-key availability parity and lazy backfill behavior are covered by service tests.
- Sensitive secret-certificate handling in `KeyManagementService` follows the documented unwrap / zeroize pattern.

**What remains deferred**

- Subkey-specific and User ID-specific revocation builders are exported and tested, but they have no production service owner.
- That is consistent with the reference documents because selector discovery is still missing on the Swift side.

**Assessment**

- Classification: `Key-level production-adopted; selective builders documented deferred`
- No immediate service-layer mismatch was found on the approved key-level path.

### 3.3 Password / SKESK Symmetric Messages

**Expected service stance**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) Section 3.3 and [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) Section 2.3 both allow and expect a dedicated Swift service wrapper while leaving product UI exposure deferred.

**Current implementation evidence**

- Rust / FFI exports: [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) exports additive password encrypt/decrypt methods and dedicated password result enums/records.
- Production service owner: [`Sources/Services/PasswordMessageService.swift`](../Sources/Services/PasswordMessageService.swift)
- App wiring: [`Sources/App/AppContainer.swift`](../Sources/App/AppContainer.swift) constructs the service.
- App entry points: current source review of `Sources/App/` found no direct call sites beyond `AppContainer` construction.
- Tests:
  - Rust: [`pgp-mobile/tests/password_message_tests.rs`](../pgp-mobile/tests/password_message_tests.rs)
  - FFI: [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - Service: [`Tests/ServiceTests/PasswordMessageServiceTests.swift`](../Tests/ServiceTests/PasswordMessageServiceTests.swift)

**What is aligned**

- The service keeps password-message flows separate from recipient-key decrypt flows.
- `noSkesk`, `passwordRejected`, and successful decrypt results are preserved as service-level outcomes.
- Fatal auth/integrity failures and unsupported algorithms still map through `CypherAirError.from(...)` rather than being collapsed into family-local statuses.

**Current limitation**

- The service is production-ready and tested, but the app does not currently expose a user workflow for it.
- Because there is no view/controller path yet, the caller-side plaintext zeroization contract has not been finalized at the UI boundary in the same way as the recipient-key decrypt flow.

**Assessment**

- Classification: `Service ready, app dormant`
- This is a product-exposure gap, not a Rust / FFI coverage gap.

### 3.4 Certification And Binding Verification

**Expected service stance**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) Section 3.4 and [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) Section 2.4 both say service adoption is deferred by default.

**Current implementation evidence**

- Rust / FFI exports: [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) exports direct-key verification, User ID binding verification, and User ID certification generation.
- There is no production service wrapper under [`Sources/Services/`](../Sources/Services/).
- No direct app entry point under [`Sources/App/`](../Sources/App/).
- Tests:
  - Rust: [`pgp-mobile/tests/certification_binding_tests.rs`](../pgp-mobile/tests/certification_binding_tests.rs)
  - FFI: [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)

**Assessment**

- Classification: `FFI only; documented deferred`
- This is not a surprise omission. The repo already treats Rust completeness as the goal for this family and does not yet define a downstream service owner.

### 3.5 Richer Signature Results

**Expected service stance**

- [`RUST_FFI_IMPLEMENTATION_REFERENCE.md`](RUST_FFI_IMPLEMENTATION_REFERENCE.md) Section 3.5 and [`RUST_SEQUOIA_INTEGRATION_TODO.md`](RUST_SEQUOIA_INTEGRATION_TODO.md) Section 2.5 both record the detailed result family as additive and deferred for production service adoption.

**Current implementation evidence**

- Rust / FFI exports: [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs) exports `verify_*_detailed`, `decrypt_detailed`, and file detailed APIs.
- Production service use is narrow:
  - [`Sources/Services/SigningService.swift`](../Sources/Services/SigningService.swift) `verifyDetachedStreaming(...)` calls `engine.verifyDetachedFileDetailed(...)`
  - it immediately folds the result back to `SignatureVerification` using only `legacyStatus` and `legacySignerFingerprint`
- No corresponding detailed service owner exists in [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift) for `decrypt_detailed` or `decrypt_file_detailed`.
- App entry point: [`Sources/App/Sign/VerifyView.swift`](../Sources/App/Sign/VerifyView.swift) uses the streaming detached verify path only.
- Tests:
  - Rust: [`pgp-mobile/tests/detailed_signature_tests.rs`](../pgp-mobile/tests/detailed_signature_tests.rs)
  - FFI: [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../Tests/FFIIntegrationTests/FFIIntegrationTests.swift)
  - Service: [`Tests/ServiceTests/StreamingServiceTests.swift`](../Tests/ServiceTests/StreamingServiceTests.swift) exercises success/failure/cancellation for the streaming verify path, but does not assert detailed family semantics such as signature-array preservation, parser order, repeated signers, or unknown-signer entries

**What is aligned**

- The additive detailed APIs exist and preserve legacy folded fields.
- The one current service call site does not break legacy UI behavior.

**Key service-layer gap**

- The family's distinctive semantics never cross the service boundary.
- Current production behavior is still a single folded status, even on the one path that already depends on the detailed API.
- The one partial call site creates ambiguity:
  - maintainers may read the code as "detailed family adopted"
  - users still receive only legacy semantics
  - service tests do not protect the family-level detailed result contract

**Assessment**

- Classification: `Partial internal service use; externally still legacy`
- This is now the primary remaining service-layer finding across the five families.

## 4. Prioritized Follow-Ups

### P1

1. Decide whether richer signature results are truly deferred or should become a first-class service feature.
   - Affected family: Richer Signature Results
   - Why it matters: `SigningService` currently depends on a detailed API but discards the detailed semantics immediately, and service tests only protect the legacy folded result.
   - Decision boundary:
     - if the family stays deferred, switch the narrow call site back to the legacy file-verify API so the code reflects actual product semantics
     - if the family becomes active, define explicit service-layer result types for detailed verify/decrypt paths and add service tests for parser order, repeated signers, unknown signers, and legacy-compat fields
   - Sensitive-boundary note: any future detailed decrypt adoption in [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift) requires human review under [`SECURITY.md`](SECURITY.md)

### P2

1. Keep the password-message family app-dormant unless product scope changes.
   - Affected family: Password / SKESK Symmetric Messages
   - Current state already matches the docs: the service is implemented and tested, but there is no app workflow yet.
   - If product scope expands, define:
     - caller-side plaintext zeroization rules
     - UI/error handling for `noSkesk`, `passwordRejected`, auth/integrity failure, and optional signing

2. Keep selective revocation builders deferred until selector discovery exists.
   - Affected family: Revocation Construction
   - Current state matches the docs: key-level adoption is complete, subkey/User ID builders remain FFI-only by design.

3. Keep certificate-signature verification deferred until a dedicated owner exists.
   - Affected family: Certification And Binding Verification
   - Current state matches the docs: Rust and FFI completeness is delivered, but there is no production service or UI workflow yet.
   - When this family becomes active, add a dedicated service rather than folding it into current message-verification services.

## 5. Final Classification Summary

- Certificate Merge / Update: `Production-adopted`
- Revocation Construction: `Key-level production-adopted; selective builders documented deferred`
- Password / SKESK Symmetric Messages: `Service ready, app dormant`
- Certification And Binding Verification: `FFI only; documented deferred`
- Richer Signature Results: `Partial internal service use; externally still legacy`

This classification removes the current gray areas:

- every family now has an explicit service-owner status
- every FFI export family has a direct downstream classification
- every deferred family is distinguished from a service gap
- the remaining meaningful service-layer issue is the P1 partial-adoption clarity problem around richer signature results
