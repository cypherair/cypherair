# Rust / FFI Service Integration Baseline

> Status: Active current-state document for Swift service and app-layer ownership of the tracked Rust / FFI capability families.
> Purpose: Record what exists today at the Rust / FFI boundary, which production Swift service owns each family, which shipped app workflow consumes it, and what downstream gaps still remain.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_PLAN](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [RUST_FFI_APP_SURFACE_ADOPTION_PLAN](RUST_FFI_APP_SURFACE_ADOPTION_PLAN.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

## 1. Role And Scope

Use this document for:

- the current Rust / FFI surface for the tracked families
- the current production Swift service owner
- the current shipped app consumer, if one exists
- the current coverage shape
- the remaining downstream gap, if any

Do not use this document for rollout sequencing, Rust semantic rules, or historical capability inventory. Those belong in the companion plan, implementation reference, and archived review stack.

The tracked families remain:

1. Certificate Merge / Update
2. Revocation Construction
3. Password / SKESK Symmetric Messages
4. Certification And Binding Verification
5. Richer Signature Results

## 2. Current-State Matrix

| Family | Current Swift Service Owner | Current App Consumer | Current Coverage | Current Integration Gap | Current State |
|---|---|---|---|---|---|
| Certificate Merge / Update | `ContactService` | `ContactImportWorkflow`, `AddContactView`, `IncomingURLImportCoordinator`, URL import flow in `CypherAirApp` | Rust merge/validation tests, FFI integration tests, `ContactServiceTests` | None on the current same-fingerprint update path | Completed service and app baseline |
| Revocation Construction | `KeyManagementService` facade with focused internal key-management owners, including selective revocation support | `KeyDetailView` key-level export, `SelectiveRevocationView` for subkey/User ID export | Rust revocation tests, FFI integration tests, `KeyManagementServiceTests`, `SelectiveRevocationScreenModelTests`, `MacUISmokeTests` | None on the current shipped revocation-export workflows | Completed service and app baseline |
| Password / SKESK Symmetric Messages | `PasswordMessageService` | None | Rust password tests, FFI integration tests, `PasswordMessageServiceTests` | No app route, no screen-model owner, and no user-facing plaintext/export workflow | Service implemented; app consumer missing |
| Certification And Binding Verification | `CertificateSignatureService` | `ContactDetailView` launcher + `ContactCertificateSignaturesView` / `ContactCertificateSignaturesScreenModel` | Rust certification/binding tests, FFI integration tests, `CertificateSignatureServiceTests`, `ContactCertificateSignaturesScreenModelTests`, `MacUISmokeTests` | None on the shipped contact-scoped certificate-signature workflow | Completed service and app baseline |
| Richer Signature Results | `SigningService` and `DecryptionService` | `VerifyView` / `VerifyScreenModel`, `DecryptView` / `DecryptScreenModel`, shared `DetailedSignatureSectionView` | Rust detailed-result tests, FFI integration tests, `SigningServiceDetailedResultTests`, `DecryptionServiceTests` | No current service-boundary gap. The UI intentionally preserves a summary-first presentation through the legacy bridge while also showing detailed entries. | Completed service and app baseline |

## 3. Family Notes

### 3.1 Certificate Merge / Update

- Same-fingerprint public-certificate update absorption is complete at Rust / FFI, service, and app levels.
- `ContactService` remains the authoritative downstream owner for duplicate/no-op detection, same-fingerprint merge/update handling, and different-fingerprint replacement detection.

### 3.2 Revocation Construction

- Key-level revocation export remains available from `KeyDetailView`.
- Selector-bearing subkey and User ID revocation export is now available through `KeyManagementService.selectionCatalog(...)`, `exportSubkeyRevocationCertificate(...)`, `exportUserIdRevocationCertificate(...)`, and the shipped `SelectiveRevocationView` flow.
- Tutorial surfaces explicitly block the selective-revocation launch path rather than silently hiding it through missing route support.

### 3.3 Password / SKESK Symmetric Messages

- `PasswordMessageService` is the real service boundary for password-message encrypt/decrypt semantics.
- It remains intentionally separate from the recipient-key two-phase decrypt flow.
- The remaining gap is product and app ownership, not Rust / FFI or service completeness.

### 3.4 Certification And Binding Verification

- `CertificateSignatureService` owns direct-key verification, User ID binding verification, selector discovery for target certificates, and User ID certification generation.
- `ContactDetailView` now owns the launcher surface and `ContactCertificateSignaturesView` / `ContactCertificateSignaturesScreenModel` own the contact-scoped app workflow.
- Tutorial surfaces keep the launcher visible-but-disabled and continue to block direct route access.

### 3.5 Richer Signature Results

- Detailed result types already cross the service boundary in both verify and decrypt flows.
- The app currently keeps the existing summary-first presentation by rendering the legacy bridge together with detailed per-signature entries.
- The remaining adoption question is certificate-signature UI, not detailed verify/decrypt semantics.

## 4. Current Downstream Gaps

- `PasswordMessageService` still has no shipped app workflow.
- The other tracked families no longer have current service-boundary or app-boundary gaps on their shipped paths.
