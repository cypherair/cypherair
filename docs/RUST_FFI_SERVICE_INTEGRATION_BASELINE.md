# Rust / FFI Service Integration Baseline

> Status: Active current-state document for Swift service and app-layer ownership of the current Rust / FFI capability families.
> Purpose: Record the current integration baseline for the five Rust / FFI capability families across Rust / FFI exports, Swift services, app consumers, and test coverage.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_PLAN](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT](archive/RUST_FFI_SERVICE_ADOPTION_ASSESSMENT.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md)

## 1. Role And Scope

This document is the current-state companion to [RUST_FFI_SERVICE_INTEGRATION_PLAN.md](RUST_FFI_SERVICE_INTEGRATION_PLAN.md).

It answers:

- what Rust / FFI surface exists today
- which Swift service currently owns each family
- which app workflow currently consumes it
- what coverage exists today
- what the current integration gap is

It does not define rollout order or future implementation sequencing. That belongs in the plan document.

The five families tracked here are:

1. Certificate Merge / Update
2. Revocation Construction
3. Password / SKESK Symmetric Messages
4. Certification And Binding Verification
5. Richer Signature Results

## 2. Current-State Matrix

| Family | Current Rust/FFI Surface | Current Swift Service Owner | Current App Consumer | Current Coverage | Current Integration Gap | Current State |
|---|---|---|---|---|---|---|
| Certificate Merge / Update | `mergePublicCertificateUpdate(...)`, public-certificate validation helpers | `ContactService` | `ContactImportWorkflow`, `AddContactView`, `IncomingURLImportCoordinator`, URL import flow in `CypherAirApp` | Rust merge/validation tests, FFI integration tests, `ContactServiceTests` | None on the current same-fingerprint public-update path | Completed service baseline |
| Revocation Construction | `generateKeyRevocation(...)`, `generateSubkeyRevocation(...)`, `generateUserIdRevocation(...)`, `parseRevocationCert(...)` | `KeyManagementService` for key-level generation/export only | `KeyDetailView` revocation export | Rust revocation tests, FFI integration tests, `KeyManagementServiceTests` | Swift models do not expose selector-bearing subkey/User ID data; no bounded service API yet for selective builders | Key-level integrated; selective builders not yet service-owned |
| Password / SKESK Symmetric Messages | Additive password encrypt/decrypt methods plus password-family result types | `PasswordMessageService` | No direct app route or screen-model consumer; constructed in `AppContainer` only | Rust password tests, FFI integration tests, `PasswordMessageServiceTests` | Service exists, but there is no app entry, screen-model ownership, or UI-side plaintext handling contract | Service implemented; app consumer missing |
| Certification And Binding Verification | `verifyDirectKeySignature(...)`, `verifyUserIdBindingSignature(...)`, `generateUserIdCertification(...)` | None | None | Rust certification/binding tests and FFI integration tests | No production service owner, no selector-bearing Swift surface for user-ID-driven flows, no app owner | FFI-complete; no Swift service owner |
| Richer Signature Results | `verify*Detailed(...)`, `decryptDetailed(...)`, `decryptFileDetailed(...)`, `verifyDetachedFileDetailed(...)` | Partial use in `SigningService`; no detailed owner in `DecryptionService` | `VerifyScreenModel` reaches `SigningService.verifyDetachedStreaming(...)`, which folds detailed fields back to legacy semantics | Rust detailed-result tests, FFI integration tests, streaming service tests for legacy folded behavior | Detailed semantics do not cross the service boundary and are not protected by service-level detailed-result tests | Partially integrated at the service boundary |

## 3. Family-By-Family Integration Baseline

### 3.1 Certificate Merge / Update

This family is the completed baseline.

- Rust / FFI already exports same-fingerprint public-certificate merge/update behavior and the public-only validation helpers used by contact import.
- `ContactService.addContact(...)` owns duplicate/no-op detection, same-fingerprint update absorption, different-fingerprint replacement detection, and persistence through `ContactRepository`.
- `ContactImportWorkflow`, `AddContactView`, and incoming URL import all already consume the service boundary instead of calling FFI directly.
- The current service and FFI tests already protect the key invariants that matter for this family, including secret-bearing input rejection and authoritative `Contact` rebuilding in `confirmKeyUpdate(...)`.

### 3.2 Revocation Construction

This family has a split baseline.

- Key-level revocation generation is already integrated into `KeyManagementService`.
- Selective revocation builders for subkeys and User IDs are exported at Rust / FFI level, but are not yet service-owned.

Current Swift model boundaries matter here:

- `KeyManagementService` already handles generation-time revocation availability, imported-key backfill, and armored export for key-level revocations.
- `KeyDetailView` already consumes that key-level path through `exportRevocationCertificate(...)`.
- Current Swift models such as `PGPKeyIdentity` and the existing `KeyInfo` summary expose only primary identity and summary metadata.
- They do not expose selector-bearing subkey fingerprints or raw User ID bytes for selectable User IDs.

Selective revocation is therefore not just missing service wiring. It is blocked on selector discovery and a bounded service contract.

### 3.3 Password / SKESK Symmetric Messages

This family already has a real Swift service owner.

- `PasswordMessageService` wraps additive Rust / FFI password-message encrypt/decrypt methods.
- It preserves the family-local decrypt outcomes that differ from recipient-key decryption:
  - `decrypted`
  - `noSkesk`
  - `passwordRejected`
- It stays separate from the two-phase `DecryptionService` flow and does not use Secure Enclave unwrap or PKESK recipient matching.
- Rust, FFI, and service tests already cover the family semantics.

The remaining gap is app ownership, not service existence.

### 3.4 Certification And Binding Verification

This family is complete at Rust / FFI level but still has no production service owner.

- Rust / FFI already supports direct-key signature verification, User ID binding verification, and User ID certification generation.
- FFI tests already exercise the family-local result semantics, including signer selection and certification kind preservation.
- No current service under `Sources/Services/` owns certificate-signature-specific workflows.

This family is currently FFI-complete but service-unowned.

### 3.5 Richer Signature Results

This family is partially integrated at the service boundary today.

- Rust / FFI already preserves parser-order signature entries, repeated signers, unknown signer entries, and legacy compatibility fields.
- `SigningService.verifyDetachedStreaming(...)` already calls `verifyDetachedFileDetailed(...)`, but immediately folds the result back down to legacy semantics.
- `DecryptionService` still consumes only the legacy decrypt result types.
- Current app flows therefore still expose only the legacy single-status signature semantics.

This family has crossed into production services internally, but not yet as a first-class service contract.

## 4. Current Ownership Summary

- Certificate Merge / Update: owned by `ContactService`; no active gap on the current production path.
- Revocation Construction: owned by `KeyManagementService` for key-level flows only; selective builders still need selector-bearing Swift support.
- Password / SKESK Symmetric Messages: owned by `PasswordMessageService`; missing app route and screen-model ownership.
- Certification And Binding Verification: no current service owner.
- Richer Signature Results: partially owned by `SigningService`; no detailed-result contract yet in `DecryptionService`.
