# Rust / FFI Service Integration Plan

> Status: Active rollout document for completing and deepening Swift service adoption of the current Rust / FFI capability families.
> Purpose: Define the next implementation work needed to complete or deepen Swift service adoption for the five Rust / FFI capability families.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_BASELINE](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_SERVICE_INTEGRATION_PLAN_ASSESSMENT](RUST_FFI_SERVICE_INTEGRATION_PLAN_ASSESSMENT.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT](archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

## 1. Role And Scope

This document is the rollout companion to [RUST_FFI_SERVICE_INTEGRATION_BASELINE.md](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md).

Use the baseline document for:

- current Rust / FFI surface
- current Swift service ownership
- current app consumers
- current coverage and current gaps

Use this document for:

- what to build next
- which service should own each family
- which interface changes are needed
- what order the work should land in
- what validation should accompany it

## 2. Rollout Summary

The current rollout work is:

1. Add selector discovery and selector-bearing Swift models.
2. Extend `KeyManagementService` for selective revocation.
3. Introduce `CertificateSignatureService`.
4. Add detailed result variants to `SigningService` and `DecryptionService`.
5. Add the app consumer for `PasswordMessageService`.

Certificate Merge / Update stays out of the rollout queue because it already serves as the completed reference baseline.

## 3. Planned Service Integration Workstreams

### 3.1 Add Selector Discovery And Selector-Bearing Swift Models

This is the shared prerequisite workstream for selective revocation and certificate-signature service adoption.

- Introduce a bounded selector-bearing metadata surface instead of expanding `PGPKeyIdentity` with ad hoc fields.
- The new surface should make subkey and User ID selection discoverable through validated metadata, not raw caller guesses.
- The selector-bearing surface must be specific enough for:
  - subkey revocation selection
  - User ID revocation selection
  - User ID binding verification
  - User ID certification generation
- If existing Rust exports do not expose enough selector data for Swift to build this model safely, the missing discovery surface should be added deliberately rather than inferred from display-only fields.

### 3.2 Extend `KeyManagementService` For Selective Revocation

After selector discovery exists, selective revocation should become a bounded `KeyManagementService` responsibility.

- Keep current key-level revocation behavior unchanged.
- Add additive service APIs for:
  - subkey revocation generation
  - User ID revocation generation
- Accept validated selectors from the new selector-bearing model instead of raw strings or bytes from views.
- Preserve the current export and storage expectations around revocation bytes and armored export.
- Connect the service APIs to `KeyDetail` or a later key-management UI only after the service contract is stable.

### 3.3 Introduce `CertificateSignatureService`

This family should land as a new service rather than piggybacking on message services.

- Proposed service name: `CertificateSignatureService`
- Proposed owned operations:
  - `verifyDirectKeySignature(...)`
  - `verifyUserIdBindingSignature(...)`
  - `generateUserIdCertification(...)`
- Proposed owned result model:
  - certificate-signature-specific result types
  - no reuse of message `SignatureVerification`
- The service should consume selector-bearing metadata rather than raw UI-selected bytes where possible.

### 3.4 Add Parallel Detailed Result APIs In `SigningService` And `DecryptionService`

This workstream deepens service adoption without breaking current app behavior.

- Keep current legacy service methods and result types unchanged for existing consumers.
- Add additive detailed-result methods in `SigningService`.
- Add additive detailed-result methods in `DecryptionService`.
- Expose Swift detailed result types that preserve:
  - per-signature arrays
  - parser order
  - repeated signers
  - unknown signer entries
  - legacy compatibility fields
- Treat `DecryptionService` detailed adoption as security-sensitive work because the current Phase 1 / Phase 2 boundary must remain intact.

### 3.5 Add A Dedicated App Consumer For `PasswordMessageService`

This workstream is about app ownership, not a service rewrite.

- Add a dedicated route, view, and screen-model ownership for password-message encrypt/decrypt.
- Keep this workflow separate from the existing recipient-key two-phase decrypt flow.
- Document and implement UI-boundary ownership for plaintext zeroization.
- Define explicit UI handling for:
  - `noSkesk`
  - `passwordRejected`
  - fatal auth/integrity failure
  - optional signature reporting on successful decrypt

## 4. Target Service / Interface Changes

### 4.1 `KeyManagementService`

- Add selective revocation service boundaries after selector discovery exists.
- Require validated selectors from a selector-bearing Swift model instead of raw caller-provided selector bytes.
- Keep current key-level revocation behavior unchanged.

### 4.2 Selector-Bearing Swift Metadata

- Add a new selector-bearing metadata type or equivalent bounded discovery surface.
- Do not overload `PGPKeyIdentity` with UI-driven selector details.
- Make this metadata reusable across selective revocation and certificate-signature workflows.

### 4.3 `CertificateSignatureService`

- Introduce a dedicated service for:
  - direct-key signature verification
  - User ID binding verification
  - User ID certification generation
- Use certificate-signature-specific result types instead of message verification types.

### 4.4 `SigningService`

- Add detailed verify variants parallel to the current legacy methods.
- Return new detailed signature result types.
- Preserve legacy folded fields only as a compatibility bridge inside the new detailed result model.

### 4.5 `DecryptionService`

- Add detailed decrypt variants parallel to the current legacy methods.
- Keep the current Phase 1 / Phase 2 boundary intact.
- Return new detailed decrypt result types without weakening existing auth/failure guarantees.

### 4.6 `PasswordMessageService`

- Keep the current service API unless implementation work reveals a concrete gap.
- Focus the next phase on app entry ownership, screen-model ownership, and UI-boundary plaintext handling rather than service refactoring.

## 5. Validation Expectations

The documentation split is complete when:

- the repository has two active docs:
  - `RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`
  - `RUST_FFI_SERVICE_INTEGRATION_PLAN.md`
- the archived assessment is clearly marked as historical
- active docs distinguish current state from rollout work
- active-doc links distinguish:
  - current state → `BASELINE`
  - rollout / next work → `PLAN`

Future implementation work described here should validate at the following level.

### 5.1 Revocation Construction

- existing key-level behavior remains unchanged
- selector discovery covers subkey and User ID selection
- negative coverage exists for selector miss, public-only input, and unusable-secret input
- service-level persistence/export behavior is tested after selector-based revocation creation

### 5.2 Password / SKESK Symmetric Messages

- app entry points do not blur password decrypt with recipient-key decrypt
- plaintext zeroization ownership is documented and tested at the UI boundary
- `noSkesk`, `passwordRejected`, and auth/integrity failure UX mapping is covered
- current Rust, FFI, and service-family tests remain valid

### 5.3 Certification And Binding Verification

- direct-key verification covers `Valid`, `Invalid`, and `SignerMissing`
- User ID binding verification covers `Valid`, `Invalid`, and `SignerMissing`
- certification-kind preservation is tested through the service layer
- certificate-signature result typing remains distinct from message verification typing

### 5.4 Richer Signature Results

- detailed verify/decrypt service results preserve signature arrays, parser order, repeated signers, and unknown signers
- legacy compatibility fields still match current UI-visible behavior
- detailed decrypt adoption preserves the `DecryptionService` Phase 1 / Phase 2 boundary and current failure semantics

## 6. Ownership And Sequencing Notes

Recommended sequencing:

1. Complete selector discovery and selector-bearing Swift models.
2. Extend `KeyManagementService` for selective revocation.
3. Introduce `CertificateSignatureService`.
4. Add detailed result variants to `SigningService` and `DecryptionService`.
5. Add the app consumer for `PasswordMessageService`.

Additional review notes:

- Any Rust / UniFFI public-surface changes still require regeneration and cross-layer validation under [TESTING.md](TESTING.md) and [CODE_REVIEW.md](CODE_REVIEW.md).
- Any `DecryptionService` detailed-result adoption remains security-sensitive and requires human review under [SECURITY.md](SECURITY.md).
- This plan intentionally treats the remaining integration gaps as active service work, not as parking-lot items.
