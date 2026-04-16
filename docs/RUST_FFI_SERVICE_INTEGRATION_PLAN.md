# Rust / FFI Service Integration Plan

> Status: Active rollout document for the remaining Swift service-layer adoption work on the current Rust / FFI capability families.
> Purpose: Define the next implementation work needed to complete or deepen downstream Swift service adoption of the Rust / FFI capability families that are already in scope for CypherAir.
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

- what to build next at the service boundary
- which service should own each remaining family
- which rollout-level prerequisites must be completed first
- which interface and ownership decisions are fixed before implementation starts
- what order the work should land in
- what validation must accompany it

This document intentionally freezes rollout-level decisions only.

- it fixes prerequisites, service ownership, sequencing, persistence policy, and review posture where those decisions affect implementation order or safety
- it does not freeze implementation-level method names, record names, exact parameter wrappers, or wire shapes unless a later stage plan needs to do so explicitly
- detailed test matrices remain in [TESTING.md](TESTING.md) and semantic reference material remains in [RUST_FFI_IMPLEMENTATION_REFERENCE.md](RUST_FFI_IMPLEMENTATION_REFERENCE.md)

Current rollout posture is `service-first` compatibility mode.

- current work in this document deepens Rust / FFI, Swift service, and Swift model boundaries first
- existing UI continues to use the current legacy / folded behavior during this rollout
- new service-visible information may exist before it is shown in the app
- app-surface adoption is not part of this rollout unless a later product-scoped plan explicitly adds it

This document intentionally absorbs the still-relevant conclusions from the earlier feasibility assessment while keeping the total plan at the service-boundary level.

## 2. Rollout Summary

The current rollout work is:

1. Add selector discovery support at the Rust / FFI boundary and introduce selector-bearing Swift metadata.
2. Introduce `CertificateSignatureService`.
3. Add detailed-result service APIs in `SigningService`.
4. Extend the `KeyManagementService` facade for selective revocation.
5. Add detailed-result service APIs in `DecryptionService` as a separately reviewed security-sensitive phase.

Certificate Merge / Update stays out of the rollout queue because it already serves as the completed reference baseline.

`PasswordMessageService` app ownership is out of scope for the current rollout.

- the service-layer capability remains supported
- no new app route, view, or screen-model ownership is planned in this document
- any future app exposure for password-message flows requires a separate product-scoped plan

## 3. Planned Workstreams

### 3.1 Add Selector Discovery Support And Selector-Bearing Swift Metadata

This is the shared prerequisite workstream for selective revocation and User ID-driven certificate-signature service adoption.

Workstream decisions fixed here:

- selector discovery is an independent prerequisite and must land before later selector-driven workstreams begin
- selector discovery must be provided through an independent Rust / FFI selector-discovery surface
- selector discovery must not be reconstructed from UI inference or display-string parsing
- `PGPKeyIdentity` stays summary metadata for persisted identity state and must not become the selector catalog
- all later selector-driven workstreams must reuse the shared selector-bearing carrier / surface produced by this workstream

The selector-discovery surface must be specific enough for:

- subkey revocation selection
- User ID revocation selection
- User ID binding verification
- User ID certification generation

Selectors must remain cryptographic selectors:

- subkey selection uses `subkeyFingerprint`
- User ID selection uses raw `userIdData`
- display strings must not become selector inputs

Exact helper shape, exact exported record shape, and exact field naming remain stage-plan work.

### 3.2 Introduce `CertificateSignatureService`

This family should land as a dedicated service rather than piggybacking on message services.

Workstream decisions fixed here:

- introduce a dedicated `CertificateSignatureService`
- keep the whole service rollout after selector discovery, even though direct-key verification is selector-independent
- own the following operations inside this service:
  - `verifyDirectKeySignature(...)`
  - `verifyUserIdBindingSignature(...)`
  - `generateUserIdCertification(...)`
- keep signer-candidate ownership explicit:
  - candidate signer certificates come from contact public certificates plus own public certificates
- keep target-certificate ownership explicit:
  - the service accepts certificate bytes or a bounded Swift type that preserves `publicKeyData`
- require selector-bearing metadata from Workstream 3.1 for User ID-driven operations
- certification generation consumes the full secret certificate material returned by `KeyManagementService.unwrapPrivateKey(...)`, not a bare private-key abstraction
- treat certification generation as secret-sensitive service work requiring focused human review
- `generateUserIdCertification(...)` returns raw certification-signature bytes, not an updated certificate
- use certificate-signature-specific Swift result types
- do not reuse message `SignatureVerification`

Exact input wrapper choice and exact Swift result-type details remain stage-plan work.

### 3.3 Add Detailed Result APIs In `SigningService`

This workstream deepens service adoption without changing current UI behavior.

Workstream decisions fixed here:

- keep current legacy service methods and result types unchanged for existing consumers
- add additive detailed-result methods in `SigningService`
- expose Swift detailed verify result types that preserve:
  - per-signature arrays
  - parser order
  - repeated signers
  - unknown signer entries
  - legacy compatibility fields
- treat the current internal use of `verifyDetachedFileDetailed(...)` as the seed of an explicit service contract instead of an internal fold-only detail
- file-based detailed verification inherits the current streaming invariants for:
  - progress callbacks
  - `OperationCancelled`

See the companion Rust / FFI implementation and testing docs for the full file-path contract.

Exact detailed method names and exact Swift result-type shapes remain stage-plan work.

### 3.4 Extend The `KeyManagementService` Facade For Selective Revocation

After selector discovery exists, selective revocation becomes a bounded `KeyManagementService` responsibility.

Workstream decisions fixed here:

- keep current key-level revocation behavior unchanged
- keep `KeyManagementService` as the app-facing facade and observable state owner
- keep new implementation logic in focused internal owners under `Sources/Services/KeyManagement/`; do not grow `KeyManagementService.swift` back into a monolithic implementation file
- add additive facade APIs for:
  - subkey revocation generation
  - User ID revocation generation
- accept validated selectors from the shared selector-bearing carrier / surface produced by Workstream 3.1 instead of raw UI strings or bytes
- selective revocation generation consumes the full secret certificate material returned by `KeyManagementService.unwrapPrivateKey(...)`, not a bare private-key abstraction
- treat selective revocation generation as secret-sensitive service work requiring focused human review

Selective revocation v1 persistence and export policy is fixed as follows:

- key-level revocation storage remains unchanged
- selective revocations are generated on demand
- selective revocations do not introduce a new persisted multi-artifact store in v1
- generation and armored export are separate concerns
- armored export remains supported for generated revocation bytes

Connect the service APIs to `KeyDetail` or a later key-management UI only after the service contract is stable and after a separate app-surface plan explicitly asks for that work.

Exact facade return shapes and exact export surface details remain stage-plan work.

### 3.5 Add Detailed Result APIs In `DecryptionService`

This is a separate final-phase workstream because it touches a security-sensitive authentication boundary.

Workstream decisions fixed here:

- keep current legacy service methods and result types unchanged for existing consumers
- add additive detailed-result methods in `DecryptionService`
- expose Swift detailed decrypt result types that preserve:
  - per-signature arrays
  - parser order
  - repeated signers
  - unknown signer entries
  - legacy compatibility fields
- keep the current Phase 1 / Phase 2 boundary intact
- keep current auth-failure and integrity-failure hard-stop behavior intact
- treat this work as security-sensitive and require dedicated human review rather than bundling it with `SigningService` detailed-result adoption
- file-based detailed decrypt inherits the current streaming/file invariants for:
  - progress callbacks
  - `OperationCancelled`
  - temp-file cleanup
  - no partial plaintext exposure

See the companion Rust / FFI implementation and testing docs for the full file-path contract.

Exact detailed method sets across the current `DecryptionService` API surface remain stage-plan work, but no detailed contract may bypass the existing authentication boundary.

## 4. Target Service / Interface Decisions

### 4.1 Compatibility Mode

- current rollout completion is defined at the service boundary, not at the UI boundary
- existing UI-visible behavior remains unchanged for current consumers during this rollout
- new service contracts may land before app presentation changes exist
- this is an intentional compatibility-mode rollout, not an ambiguous partial-implementation state

### 4.2 Selector Discovery Surface

- add an independent selector-bearing metadata surface at the Rust / FFI boundary
- build it from Rust / FFI discovery support, not from UI inference or display-string parsing
- do not overload `PGPKeyIdentity` with selector-bearing UI data
- make the new surface reusable across selective revocation and certificate-signature workflows
- require later selector-driven workstreams to reuse the shared selector-bearing carrier / surface from Workstream 3.1

### 4.3 `CertificateSignatureService`

- introduce a dedicated service for:
  - direct-key signature verification
  - User ID binding verification
  - User ID certification generation
- use certificate-signature-specific result types instead of message verification types
- keep signer-candidate ownership and target-certificate ownership explicit at the service boundary
- keep the service rollout after selector discovery for a cleaner total service boundary
- keep certification generation modeled as raw certification-signature-byte production, not certificate rewriting

### 4.4 `SigningService`

- add detailed verify variants parallel to the current legacy methods
- return new detailed signature result types
- preserve legacy folded fields only as a compatibility bridge inside the new detailed result model

### 4.5 `KeyManagementService`

- add selective revocation service boundaries after selector discovery exists
- require validated selectors from the selector-bearing Swift model instead of raw caller-provided selector bytes
- keep current key-level revocation behavior unchanged
- keep new implementation logic in `Sources/Services/KeyManagement/` internal owners when it belongs to the key lifecycle domain
- keep `KeyManagementService` as the facade boundary for any later app adoption

### 4.6 Selective Revocation Persistence And Export Layering

- key-level `PGPKeyIdentity.revocationCert` remains the only persisted revocation artifact in v1
- selective subkey/User ID revocations are export-on-demand only in v1
- selective revocation generation and armored export remain separate layers
- any future persisted selective-revocation store is out of scope for this rollout and must be specified separately

### 4.7 `DecryptionService`

- add detailed decrypt variants parallel to the current legacy methods
- keep the current Phase 1 / Phase 2 boundary intact
- return new detailed decrypt result types without weakening existing auth/failure guarantees
- treat this as a separate rollout phase from `SigningService`

## 5. Validation Expectations

### 5.1 Compatibility Mode

- existing UI-visible behavior remains unchanged for current consumers during this rollout
- new service contracts are additive only
- current Rust, FFI, and service-family tests that protect legacy behavior remain valid

### 5.2 Selector Discovery

- selector discovery covers selectable subkey identifiers and raw User ID bytes
- selectors remain stable across generated and imported certificates
- no caller-facing API uses display strings as cryptographic selectors
- both Profile A and Profile B are covered where the capability applies

### 5.3 Certificate Signature Service

- direct-key verification covers `Valid`, `Invalid`, and `SignerMissing`
- User ID binding verification covers `Valid`, `Invalid`, and `SignerMissing`
- certification-kind preservation is tested through the service layer
- successful subkey-signer verification preserves both primary signer fingerprint and signing-subkey fingerprint
- certificate-signature result typing remains distinct from message verification typing

### 5.4 `SigningService` Detailed Results

- detailed verify service results preserve signature arrays, parser order, repeated signers, and unknown signers
- legacy compatibility fields still match current UI-visible behavior
- service-level tests protect the detailed result contract instead of only folded legacy semantics
- file-based detailed verification preserves current streaming cancellation/progress behavior

### 5.5 Selective Revocation

- existing key-level behavior remains unchanged
- selector discovery is used for subkey and User ID selection
- negative coverage exists for selector miss, public-only input, and unusable-secret input
- selective revocations support export-on-demand and armored export
- v1 does not silently introduce persisted multi-artifact selective-revocation storage
- tests cover the generation/export layering without introducing a new persisted selective-revocation store

### 5.6 `DecryptionService` Detailed Results

- detailed decrypt service results preserve signature arrays, parser order, repeated signers, and unknown signers
- legacy compatibility fields still match current UI-visible behavior
- detailed decrypt adoption preserves the `DecryptionService` Phase 1 / Phase 2 boundary and current failure semantics
- file-based detailed decrypt preserves cleanup and no-partial-plaintext behavior
- human review is obtained under [SECURITY.md](SECURITY.md) and [CODE_REVIEW.md](CODE_REVIEW.md)

## 6. Ownership And Sequencing Notes

Recommended sequencing:

1. Complete selector discovery support and selector-bearing Swift metadata.
2. Introduce `CertificateSignatureService`.
3. Add detailed-result service APIs to `SigningService`.
4. Extend the `KeyManagementService` facade for selective revocation.
5. Add detailed-result service APIs to `DecryptionService` as a separately reviewed security-sensitive phase.

Additional review notes:

- Any Rust / UniFFI public-surface changes still require regeneration and cross-layer validation under [TESTING.md](TESTING.md) and [CODE_REVIEW.md](CODE_REVIEW.md).
- Any `DecryptionService` detailed-result adoption remains security-sensitive and requires human review under [SECURITY.md](SECURITY.md).
- This plan intentionally treats the remaining integration gaps as active downstream service-boundary work while keeping app-surface adoption out of the current rollout.
- Any later app exposure for `PasswordMessageService`, selective revocation, or certificate-signature workflows requires a separate product-scoped plan.
