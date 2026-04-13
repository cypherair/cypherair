# Rust / FFI Service Integration Plan

> Status: Active rollout document for the remaining Swift service and app-layer adoption work on the current Rust / FFI capability families.
> Purpose: Define the next implementation work needed to complete or deepen downstream Swift adoption of the Rust / FFI capability families that are already in scope for CypherAir.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_BASELINE](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

## 1. Role And Scope

This document is the rollout companion to [RUST_FFI_SERVICE_INTEGRATION_BASELINE.md](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md).

Use the baseline document for:

- current Rust / FFI surface
- current Swift service ownership
- current app consumers
- current coverage and current gaps

Use this document for:

- what to build next
- which service should own each remaining family
- which interface and ownership decisions are fixed before implementation starts
- what order the work should land in
- what validation must accompany it

This document intentionally absorbs the still-relevant conclusions from the earlier feasibility assessment. It should now stand on its own as the active rollout guide.

## 2. Rollout Summary

The current rollout work is:

1. Add selector discovery support at the Rust / FFI boundary and introduce selector-bearing Swift metadata.
2. Introduce `CertificateSignatureService`.
3. Add detailed-result service APIs in `SigningService`.
4. Extend the `KeyManagementService` facade for selective revocation.
5. Add an optional dedicated app consumer for `PasswordMessageService`.
6. Add detailed-result service APIs in `DecryptionService` as a separately reviewed security-sensitive phase.

Certificate Merge / Update stays out of the rollout queue because it already serves as the completed reference baseline.

## 3. Planned Workstreams

### 3.1 Add Selector Discovery Support And Selector-Bearing Swift Metadata

This is the shared prerequisite workstream for selective revocation and User ID-driven certificate-signature service adoption.

- Add a bounded Rust / FFI discovery helper or equivalent exported bounded metadata surface for:
  - selectable subkey identifiers
  - selectable raw User ID bytes
- Introduce a selector-bearing Swift metadata type that is built from that exported discovery surface.
- Keep `PGPKeyIdentity` as summary metadata for persisted identity state; do not expand it into the long-term selector catalog.
- The selector-bearing surface must be specific enough for:
  - subkey revocation selection
  - User ID revocation selection
  - User ID binding verification
  - User ID certification generation
- Selectors must remain cryptographic selectors:
  - subkey selection uses `subkeyFingerprint`
  - User ID selection uses raw `userIdData`
  - display strings must not become selector inputs

### 3.2 Introduce `CertificateSignatureService`

This family should land as a dedicated service rather than piggybacking on message services.

- Proposed service name: `CertificateSignatureService`
- Proposed owned operations:
  - `verifyDirectKeySignature(...)`
  - `verifyUserIdBindingSignature(...)`
  - `generateUserIdCertification(...)`
- Proposed input ownership:
  - candidate signer certificates come from contact public certificates plus own public certificates
  - target certificate input remains certificate bytes or a bounded Swift type that preserves `publicKeyData`
  - User ID-driven operations consume selector-bearing metadata from Workstream 3.1
  - certification generation accesses local secret key material through `KeyManagementService.unwrapPrivateKey(...)`
- Proposed result ownership:
  - certificate-signature-specific Swift result types
  - no reuse of message `SignatureVerification`

Direct-key verification is selector-independent, but this service rollout stays grouped after selector discovery because two of the three owned operations are User ID-driven.

### 3.3 Add Detailed Result APIs In `SigningService`

This workstream deepens service adoption without breaking current app behavior.

- Keep current legacy service methods and result types unchanged for existing consumers.
- Add additive detailed-result methods in `SigningService`.
- Expose Swift detailed verify result types that preserve:
  - per-signature arrays
  - parser order
  - repeated signers
  - unknown signer entries
  - legacy compatibility fields
- The current internal use of `verifyDetachedFileDetailed(...)` should become an explicit service contract instead of an internal fold-only implementation detail.

### 3.4 Extend The `KeyManagementService` Facade For Selective Revocation

After selector discovery exists, selective revocation should become a bounded `KeyManagementService` responsibility.

- Keep current key-level revocation behavior unchanged.
- Keep `KeyManagementService` as the app-facing facade and observable state owner.
- Land new key-lifecycle implementation in focused internal owners under `Sources/Services/KeyManagement/`; do not grow `KeyManagementService.swift` back into a monolithic implementation file.
- Add additive facade APIs for:
  - subkey revocation generation
  - User ID revocation generation
- Accept validated selectors from the selector-bearing metadata surface instead of raw UI strings or bytes.

Selective revocation v1 persistence/export policy is fixed as follows:

- key-level revocation storage remains unchanged
- selective revocations are generated and exported on demand
- selective revocations do not introduce a new persisted multi-artifact store in v1
- armored export remains supported for the generated revocation bytes

Connect the service APIs to `KeyDetail` or a later key-management UI only after the service contract is stable.

### 3.5 Add A Dedicated App Consumer For `PasswordMessageService`

This workstream is an independent app-ownership track, not a service rewrite and not a prerequisite for the other workstreams.

- Add a dedicated route, view, and screen-model ownership for password-message encrypt/decrypt only if product scope wants the workflow exposed now.
- Keep this workflow separate from the existing recipient-key two-phase decrypt flow.
- Document and implement UI-boundary ownership for plaintext lifetime and zeroization.
- Define explicit UI handling for:
  - `noSkesk`
  - `passwordRejected`
  - fatal auth/integrity failure
  - optional signature reporting on successful decrypt

### 3.6 Add Detailed Result APIs In `DecryptionService`

This is a separate final-phase workstream because it touches a security-sensitive boundary.

- Keep current legacy service methods and result types unchanged for existing consumers.
- Add additive detailed-result methods in `DecryptionService`.
- Expose Swift detailed decrypt result types that preserve:
  - per-signature arrays
  - parser order
  - repeated signers
  - unknown signer entries
  - legacy compatibility fields
- Keep the current Phase 1 / Phase 2 boundary intact.
- Keep current auth-failure and integrity-failure hard-stop behavior intact.
- Treat this work as security-sensitive and require dedicated human review rather than bundling it with `SigningService` detailed-result adoption.

## 4. Target Service / Interface Decisions

### 4.1 Selector Discovery Surface

- Add a new selector-bearing metadata type or equivalent bounded discovery surface.
- Build it from Rust / FFI discovery support, not from UI inference or display-string parsing.
- Do not overload `PGPKeyIdentity` with selector-bearing UI data.
- Make the new surface reusable across selective revocation and certificate-signature workflows.

### 4.2 `KeyManagementService`

- Add selective revocation service boundaries after selector discovery exists.
- Require validated selectors from the selector-bearing Swift model instead of raw caller-provided selector bytes.
- Keep current key-level revocation behavior unchanged.
- Keep new implementation logic in `Sources/Services/KeyManagement/` internal owners when it belongs to the key lifecycle domain.

### 4.3 Selective Revocation Persistence

- Key-level `PGPKeyIdentity.revocationCert` remains the only persisted revocation artifact in v1.
- Selective subkey/User ID revocations are export-on-demand only in v1.
- Any future persisted selective-revocation store is out of scope for this rollout and must be specified separately.

### 4.4 `CertificateSignatureService`

- Introduce a dedicated service for:
  - direct-key signature verification
  - User ID binding verification
  - User ID certification generation
- Use certificate-signature-specific result types instead of message verification types.
- Keep signer-candidate ownership and target-certificate ownership explicit at the service boundary.

### 4.5 `SigningService`

- Add detailed verify variants parallel to the current legacy methods.
- Return new detailed signature result types.
- Preserve legacy folded fields only as a compatibility bridge inside the new detailed result model.

### 4.6 `DecryptionService`

- Add detailed decrypt variants parallel to the current legacy methods.
- Keep the current Phase 1 / Phase 2 boundary intact.
- Return new detailed decrypt result types without weakening existing auth/failure guarantees.
- Treat this as a separate rollout phase from `SigningService`.

### 4.7 `PasswordMessageService`

- Keep the current service API unless implementation work reveals a concrete gap.
- Focus this track on app entry ownership, screen-model ownership, and UI-boundary plaintext handling rather than service refactoring.

## 5. Validation Expectations

### 5.1 Selector Discovery

- selector discovery covers selectable subkey identifiers and raw User ID bytes
- selectors remain stable across generated and imported certificates
- no caller-facing API uses display strings as cryptographic selectors
- both Profile A and Profile B are covered where the capability applies

### 5.2 Certificate Signature Service

- direct-key verification covers `Valid`, `Invalid`, and `SignerMissing`
- User ID binding verification covers `Valid`, `Invalid`, and `SignerMissing`
- certification-kind preservation is tested through the service layer
- successful subkey-signer verification preserves both primary signer fingerprint and signing-subkey fingerprint
- certificate-signature result typing remains distinct from message verification typing

### 5.3 `SigningService` Detailed Results

- detailed verify service results preserve signature arrays, parser order, repeated signers, and unknown signers
- legacy compatibility fields still match current UI-visible behavior
- service-level tests protect the detailed result contract instead of only folded legacy semantics

### 5.4 Selective Revocation

- existing key-level behavior remains unchanged
- selector discovery is used for subkey and User ID selection
- negative coverage exists for selector miss, public-only input, and unusable-secret input
- selective revocations support export-on-demand and armored export
- v1 does not silently introduce persisted multi-artifact selective-revocation storage

### 5.5 Password / SKESK App Consumer

- app entry points do not blur password decrypt with recipient-key decrypt
- plaintext zeroization ownership is documented and tested at the UI boundary
- `noSkesk`, `passwordRejected`, and auth/integrity failure UX mapping is covered
- current Rust, FFI, and service-family tests remain valid

### 5.6 `DecryptionService` Detailed Results

- detailed decrypt service results preserve signature arrays, parser order, repeated signers, and unknown signers
- legacy compatibility fields still match current UI-visible behavior
- detailed decrypt adoption preserves the `DecryptionService` Phase 1 / Phase 2 boundary and current failure semantics
- human review is obtained under [SECURITY.md](SECURITY.md) and [CODE_REVIEW.md](CODE_REVIEW.md)

## 6. Ownership And Sequencing Notes

Recommended sequencing:

1. Complete selector discovery support and selector-bearing Swift metadata.
2. Introduce `CertificateSignatureService`.
3. Add detailed-result service APIs to `SigningService`.
4. Extend the `KeyManagementService` facade for selective revocation.
5. Add the app consumer for `PasswordMessageService` only if product scope wants it now.
6. Add detailed-result service APIs to `DecryptionService` as a separately reviewed security-sensitive phase.

Additional review notes:

- Any Rust / UniFFI public-surface changes still require regeneration and cross-layer validation under [TESTING.md](TESTING.md) and [CODE_REVIEW.md](CODE_REVIEW.md).
- Any `DecryptionService` detailed-result adoption remains security-sensitive and requires human review under [SECURITY.md](SECURITY.md).
- This plan intentionally treats the remaining integration gaps as active downstream work, while keeping independent app-surface work separate from the core service-boundary sequence.
