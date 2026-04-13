# Rust / FFI Current-State Audit

> Status: Archived audit snapshot from 2026-04-11. Kept as historical evidence for the previous Rust/FFI doc-stack review; no longer treated as an active source of truth.
> Scope: Present-tense current-state claims in the then-active `RUST_FFI_IMPLEMENTATION_REFERENCE.md` and `RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`.
> Outcome: 34 audited current-state claims; 34 `准确`; 0 `部分准确`; 0 `已过时`; 0 `无法仅凭仓库确认`.

## 1. Method

- Truth sources: production code, generated UniFFI bindings, app wiring, and tests.
- Primary evidence roots:
  - `pgp-mobile/src/lib.rs`
  - `Sources/PgpMobile/pgp_mobile.swift`
  - `Sources/Services/`
  - `Sources/App/`
  - `Tests/FFIIntegrationTests/`
  - `Tests/ServiceTests/`
  - `pgp-mobile/tests/`
- Companion docs were used only for consistency checks, not to override code facts.
- Negative claims were supported by repo-wide absence checks, especially for:
  - `CertificateSignatureService`
  - app-level consumers of `PasswordMessageService`
  - app/service adoption of detailed result types beyond internal folding
- No dynamic validation commands were needed; static evidence was sufficient for every audited current-state claim.

## 2. Claim Ledger

### 2.1 Document-Stack Role

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| X-01 | `RUST_FFI_SERVICE_INTEGRATION_BASELINE.md:3-4,10-18` | `cross_doc_role` | `BASELINE` is the active current-state document for Swift service/app ownership, coverage, and current integration gaps. | `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md:9-10,18-21,34-36`; `docs/SEQUOIA_CAPABILITY_AUDIT.md:24-26` | `准确` | Companion docs consistently defer current downstream Swift integration state to `BASELINE`. |
| X-02 | `RUST_FFI_IMPLEMENTATION_REFERENCE.md:18-21,34-36` | `cross_doc_role` | `IMPLEMENTATION_REFERENCE` does not own current downstream Swift integration state; it defers that to `BASELINE` and defers current build inventory to `SEQUOIA_CAPABILITY_AUDIT`. | `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md:10-20`; `docs/SEQUOIA_CAPABILITY_AUDIT.md:24-26` | `准确` | Documentation stack is internally consistent for the audited role statements. |

### 2.2 Certificate Merge / Update

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| C-01 | `BASELINE:34`; `BASELINE:46` | `export` | Rust / FFI exports same-fingerprint public-certificate merge/update behavior plus public-certificate validation helpers. | `pgp-mobile/src/lib.rs:93-111`; `Sources/PgpMobile/pgp_mobile.swift:723-729,783-787` | `准确` | `merge_public_certificate_update` and `validate_public_certificate` are both present in Rust and generated Swift bindings. |
| C-02 | `BASELINE:34`; `BASELINE:47`; `BASELINE:105` | `service_owner` | `ContactService` owns the production service boundary for this family, including duplicate/no-op handling, same-fingerprint update absorption, different-fingerprint replacement detection, persistence, and authoritative rebuild in `confirmKeyUpdate(...)`. | `Sources/Services/ContactService.swift:83-210` | `准确` | `addContact(...)` and `confirmKeyUpdate(...)` implement the described ownership boundaries. |
| C-03 | `BASELINE:34`; `BASELINE:48` | `app_consumer` | `ContactImportWorkflow`, `AddContactView`, `IncomingURLImportCoordinator`, and the URL import path in `CypherAirApp` consume the service boundary instead of calling FFI directly. | `Sources/App/Contacts/Import/ContactImportWorkflow.swift:20-124`; `Sources/App/Contacts/AddContactView.swift:66-73`; `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift:25-58`; `Sources/App/CypherAirApp.swift:48-59` | `准确` | Production app wiring goes through `ContactService` via `ContactImportWorkflow`. |
| C-04 | `BASELINE:34`; `BASELINE:49` | `coverage` | Coverage exists in Rust merge/validation tests, FFI integration tests, and `ContactServiceTests`, including secret-bearing rejection and `confirmKeyUpdate(...)` rebuilding behavior. | `pgp-mobile/tests/certificate_merge_tests.rs:129-390`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:426-608`; `Tests/ServiceTests/ContactServiceTests.swift:326-571` | `准确` | Coverage is broader than the doc states, but the stated coverage is present. |
| C-05 | `BASELINE:34`; `BASELINE:44`; `BASELINE:105` | `gap` | There is no active gap on the current same-fingerprint public-update path; this family is the completed baseline. | `Sources/Services/ContactService.swift:95-173`; `Sources/App/Contacts/Import/ContactImportWorkflow.swift:65-123`; `Tests/ServiceTests/ContactServiceTests.swift:368-441` | `准确` | Current production path is present end to end for the bounded same-fingerprint update workflow. |

### 2.3 Revocation Construction

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| R-01 | `BASELINE:35` | `export` | Rust / FFI exports `generateKeyRevocation(...)`, `generateSubkeyRevocation(...)`, `generateUserIdRevocation(...)`, and `parseRevocationCert(...)`. | `pgp-mobile/src/lib.rs:401-435`; `Sources/PgpMobile/pgp_mobile.swift:675-692,755-757` | `准确` | All four exports exist in Rust and generated Swift bindings. |
| R-02 | `BASELINE:35`; `BASELINE:55-56`; `BASELINE:106`; `IMPLEMENTATION_REFERENCE:309,331` | `service_owner` | `KeyManagementService` owns only the key-level production boundary; selective subkey/User ID builders are exported but not service-owned. | `Sources/Services/KeyManagementService.swift:143-152`; repo-wide search for `generateSubkeyRevocation|generateUserIdRevocation` in `Sources/Services` and `Sources/App` found no production callers beyond generated bindings/tests | `准确` | Negative claim is backed by absence of production service/app callers for selective builders. |
| R-03 | `BASELINE:35`; `BASELINE:60-61` | `app_consumer` | The current app consumer is key-level revocation export via `KeyDetailView` / `exportRevocationCertificate(...)`. | `Sources/App/Keys/KeyDetailView.swift:211-219`; `Sources/Services/KeyManagementService.swift:146-151` | `准确` | App UI reaches only the key-level export path. |
| R-04 | `BASELINE:35`; `BASELINE:60`; `IMPLEMENTATION_REFERENCE:309,331` | `current_behavior` | `KeyManagementService` already handles generation-time revocation availability, imported-key backfill, and armored export for key-level revocations. | `Sources/Models/PGPKeyIdentity.swift:44-47`; `Sources/Services/KeyManagementService.swift:143-151`; `Tests/ServiceTests/KeyManagementServiceTests.swift:1137-1266` | `准确` | Tests explicitly cover existing revocation export, imported-key parity, lazy backfill, and failed metadata persistence behavior. |
| R-05 | `BASELINE:35`; `BASELINE:62-65`; `IMPLEMENTATION_REFERENCE:533` | `gap` | Current Swift-facing model surfaces do not expose selector-bearing subkey fingerprints or raw User ID bytes, so selective revocation is blocked on selector discovery plus a bounded service contract. | `Sources/Models/PGPKeyIdentity.swift:13-57`; `pgp-mobile/src/keys.rs:53-74`; `Sources/PgpMobile/pgp_mobile.swift:2492-2528` | `准确` | `PGPKeyIdentity` and `KeyInfo` expose only summary metadata, not selectable subkey fingerprints or raw User ID bytes. |
| R-06 | `BASELINE:35`; `BASELINE:60-63` | `coverage` | Coverage exists in Rust revocation tests, FFI integration tests, and `KeyManagementServiceTests`. | `pgp-mobile/tests/revocation_construction_tests.rs:77-329`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:974-1087`; `Tests/ServiceTests/KeyManagementServiceTests.swift:1137-1298` | `准确` | Coverage includes both profiles, selector miss cases, public-only rejection, backfill, and export behavior. |

### 2.4 Password / SKESK Symmetric Messages

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| P-01 | `BASELINE:36`; `BASELINE:71`; `IMPLEMENTATION_REFERENCE:360,384-424` | `export` | Additive password encrypt/decrypt methods, optional signing input, and password-family result types exist at the Rust / FFI surface. | `pgp-mobile/src/lib.rs:171-205,258-266`; `Sources/PgpMobile/pgp_mobile.swift:611-658,2723-2742,3677-3688` | `准确` | Rust and generated Swift bindings expose the documented password-message surface. |
| P-02 | `BASELINE:36`; `BASELINE:69-77`; `BASELINE:107`; `IMPLEMENTATION_REFERENCE:360,429` | `service_owner` | `PasswordMessageService` is the real production Swift service owner for this family. | `Sources/Services/PasswordMessageService.swift:3-194` | `准确` | The service wraps password-specific Rust/FFI behavior behind production service methods. |
| P-03 | `BASELINE:71-78`; `IMPLEMENTATION_REFERENCE:360,429` | `current_behavior` | `PasswordMessageService` preserves `decrypted` / `noSkesk` / `passwordRejected`, stays separate from `DecryptionService`, and authenticates optional signing through `unwrapPrivateKey(...)`. | `Sources/Services/PasswordMessageService.swift:13-17,63-108,118-123,189-193` | `准确` | The service behavior matches the family-local semantics described in both docs. |
| P-04 | `BASELINE:36`; `BASELINE:80`; `BASELINE:107`; `IMPLEMENTATION_REFERENCE:430` | `app_consumer` | There is no direct app route or screen-model consumer today; the production app only constructs `PasswordMessageService` in `AppContainer`. | `Sources/App/AppContainer.swift:14,83-106,158-181`; repo-wide search for `passwordMessageService` in `Sources/App` found only `AppContainer`; no app screen model references were found | `准确` | Tests instantiate the service separately, but there is no production app route or screen-model owner. |
| P-05 | `BASELINE:36`; `BASELINE:78` | `coverage` | Coverage exists in Rust password tests, FFI integration tests, and `PasswordMessageServiceTests`. | `pgp-mobile/tests/password_message_tests.rs:288-634`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:273-422`; `Tests/ServiceTests/PasswordMessageServiceTests.swift:68-205` | `准确` | The stated coverage exists and matches the documented family semantics. |
| P-06 | `IMPLEMENTATION_REFERENCE:459-462` | `current_behavior` | The current Swift FFI suite covers `seipdv1` / `seipdv2` round-trips, signed password-message round-trip, `noSkesk`, `passwordRejected`, and tamper/auth-failure cases. | `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:273-422` | `准确` | All listed FFI cases are present. |
| P-07 | `IMPLEMENTATION_REFERENCE:461-462` | `gap` | Dedicated Swift FFI smoke tests for mixed `PKESK + SKESK` and unsupported-algorithm password-message behavior are not currently present; those cases are covered in the Rust suite. | No matching FFI tests were found in `Tests/FFIIntegrationTests/FFIIntegrationTests.swift`; Rust coverage exists in `pgp-mobile/tests/password_message_tests.rs:478-485,608-634` | `准确` | Negative claim is backed by FFI absence plus explicit Rust coverage. |

### 2.5 Certification And Binding Verification

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| S-01 | `BASELINE:37`; `BASELINE:86`; `IMPLEMENTATION_REFERENCE:499-502` | `export` | Rust / FFI already supports `verifyDirectKeySignature(...)`, `verifyUserIdBindingSignature(...)`, and `generateUserIdCertification(...)`. | `pgp-mobile/src/lib.rs:325-365`; `Sources/PgpMobile/pgp_mobile.swift:685-687,820-827` | `准确` | All three family exports are present in Rust and generated Swift bindings. |
| S-02 | `BASELINE:37`; `BASELINE:84-90`; `BASELINE:108`; `IMPLEMENTATION_REFERENCE:497` | `service_owner` | The current production Swift service boundary for this family is none. | Repo-wide search for `verifyDirectKeySignature|verifyUserIdBindingSignature|generateUserIdCertification` in `Sources/Services` returned no production service callers; `CertificateSignatureService` has no repo hits | `准确` | The documented absence of a production service owner is supported by absence checks. |
| S-03 | `BASELINE:37`; `BASELINE:88`; `BASELINE:108` | `app_consumer` | The current app owner is none. | Repo-wide search for `verifyDirectKeySignature|verifyUserIdBindingSignature|generateUserIdCertification` in `Sources/App` returned no production app callers | `准确` | No app workflow currently consumes this family. |
| S-04 | `BASELINE:37`; `IMPLEMENTATION_REFERENCE:533-535` | `gap` | Current Swift-facing model surfaces do not expose selector-bearing raw User ID data needed for bounded service ownership. | `pgp-mobile/src/keys.rs:53-74`; `Sources/PgpMobile/pgp_mobile.swift:2492-2528`; `Sources/Models/PGPKeyIdentity.swift:13-57` | `准确` | The documented gap is visible in both Rust `KeyInfo` and Swift `PGPKeyIdentity`. |
| S-05 | `BASELINE:37`; `BASELINE:87`; `IMPLEMENTATION_REFERENCE:551-556` | `coverage` | Coverage exists in Rust certification/binding tests and FFI integration tests, including signer selection and certification-kind preservation. | `pgp-mobile/tests/certification_binding_tests.rs:256-656`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1158-1362` | `准确` | FFI tests cover valid, invalid, signer-missing, wrong-type boundary, fallback subkey, and certification-kind preservation. |

### 2.6 Richer Signature Results

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| D-01 | `BASELINE:38`; `IMPLEMENTATION_REFERENCE:597-602` | `export` | Detailed exports exist for `verify*Detailed(...)`, `decryptDetailed(...)`, `decryptFileDetailed(...)`, and `verifyDetachedFileDetailed(...)`. | `pgp-mobile/src/lib.rs:246-255,294-320,500-518`; `Sources/PgpMobile/pgp_mobile.swift:595-608,795-817` | `准确` | Rust and generated Swift bindings expose the detailed family surface. |
| D-02 | `IMPLEMENTATION_REFERENCE:134-141`; `IMPLEMENTATION_REFERENCE:566`; `IMPLEMENTATION_REFERENCE:592-595` | `current_behavior` | Current legacy behavior still collapses signature results to one status plus one optional signer fingerprint, and that signer fingerprint is the signer certificate primary fingerprint, not the signing subkey fingerprint. | `pgp-mobile/src/verify.rs:32-41,90-100`; `pgp-mobile/src/decrypt.rs:215-221`; `pgp-mobile/src/signature_details.rs:133-170`; `Sources/Services/SigningService.swift:121-146,158-181`; `Sources/Services/DecryptionService.swift:193-223,277-309` | `准确` | New certificate-signature APIs can return both primary and signing-key fingerprints, but legacy verify/decrypt flows still expose only the primary signer fingerprint. |
| D-03 | `BASELINE:38`; `BASELINE:96`; `IMPLEMENTATION_REFERENCE:679-681` | `current_behavior` | Rust / FFI preserves parser-order signature entries, repeated signers, unknown signer entries, and legacy compatibility fields. | `pgp-mobile/src/signature_details.rs:17-59,88-199`; `pgp-mobile/tests/detailed_signature_tests.rs:128-206`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677` | `准确` | Both Rust and Swift FFI tests exercise the detailed collector semantics. |
| D-04 | `BASELINE:38`; `BASELINE:97-99`; `BASELINE:109`; `IMPLEMENTATION_REFERENCE:592-595` | `service_owner` | The current Swift service boundary is partial: `SigningService.verifyDetachedStreaming(...)` uses `verifyDetachedFileDetailed(...)` and folds back to legacy fields, while `DecryptionService` still uses legacy decrypt result types only. | `Sources/Services/SigningService.swift:193-225,284-286`; `Sources/Services/DecryptionService.swift:193-223,277-309,325-340` | `准确` | This is the key partial-integration boundary described in both docs. |
| D-05 | `BASELINE:38`; `BASELINE:99`; `BASELINE:101` | `app_consumer` | Current app flows still expose only the legacy single-status `SignatureVerification` surface. | `Sources/Models/SignatureVerification.swift:3-124`; `Sources/App/Sign/VerifyScreenModel.swift:13-31,58-91`; repo-wide search for `VerifyDetailedResult|DecryptDetailedResult|FileVerifyDetailedResult` in `Sources/App` found no app-facing adoption | `准确` | App/service surfaces still normalize to `SignatureVerification`. |
| D-06 | `BASELINE:38`; `BASELINE:98-99`; `BASELINE:109` | `gap` | Detailed semantics do not cross the service boundary and are not protected by service-level detailed-result tests. | `Sources/Services/SigningService.swift:200-225`; `Sources/Services/DecryptionService.swift:193-223,277-309`; `Tests/ServiceTests/StreamingServiceTests.swift:145-180,224-260` | `准确` | Service tests cover folded legacy behavior and cancellation, not detailed service return types. |
| D-07 | `BASELINE:38`; `IMPLEMENTATION_REFERENCE:679-682` | `coverage` | Coverage exists in Rust detailed-result tests, Swift FFI integration tests, and streaming service tests for legacy folded behavior. | `pgp-mobile/tests/detailed_signature_tests.rs:128-479`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`; `Tests/ServiceTests/StreamingServiceTests.swift:145-180,224-260` | `准确` | The doc’s stated coverage is present. |
| D-08 | `IMPLEMENTATION_REFERENCE:679-682` | `gap` | The current Swift FFI suite covers detailed cleartext, detached, file verify, decrypt, and file decrypt smoke tests, fixed multi-signer fixture mapping, compatibility with legacy folded fields, and file-cancellation behavior, but it does not include a dedicated expired-signature detailed Swift FFI smoke test. | Present FFI coverage: `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`; absent expired FFI test by repo-wide search; Rust expired coverage exists in `pgp-mobile/tests/detailed_signature_tests.rs:186-206` | `准确` | The documented FFI gap is real; expired detailed coverage exists only in the Rust suite today. |

### 2.7 Existing FFI Boundary Discipline

| ID | Source | Category | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|---|
| F-01 | `IMPLEMENTATION_REFERENCE:126-129` | `current_behavior` | Existing secret-sensitive exports in `pgp-mobile/src/lib.rs` wrap secret certificate inputs in `Zeroizing` and convert password strings to Sequoia `Password` at the FFI boundary. | `pgp-mobile/src/lib.rs:121-127,145-149,162-167,179-185,197-203,241-255,265-266,273-280,359-364,407-434,489-516` | `准确` | The current FFI boundary discipline described in the implementation reference matches the code. |

## 3. Discrepancy Report

### 3.1 `RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`

- Verdict summary: all audited `BASELINE`-sourced current-state claims were `准确`.
- Finding summary: no inaccurate current-state claims were found in the audited scope.

### 3.2 `RUST_FFI_IMPLEMENTATION_REFERENCE.md`

- Verdict summary: all audited `IMPLEMENTATION_REFERENCE`-sourced current-state claims were `准确`.
- Finding summary: no inaccurate current-state claims were found in the audited scope.

### 3.3 Companion-Doc Consistency

- No material conflicts were found for the audited current-state claims across:
  - `ARCHITECTURE.md`
  - `TESTING.md`
  - `SEQUOIA_CAPABILITY_AUDIT.md`
- The then-active three-doc split remained internally coherent at the time of this audit:
  - `BASELINE` owns current downstream integration state
  - `IMPLEMENTATION_REFERENCE` owns semantic and validation guidance plus a small set of present-tense implementation facts
  - `SEQUOIA_CAPABILITY_AUDIT` remained the broader current-build inventory

## 4. Minimal Revision Suggestions

- No corrective edits are required for the audited present-tense current-state claims.
- No minimal patch set was prepared, because this audit did not identify any `部分准确`, `已过时`, or `无法仅凭仓库确认` findings within the scoped statements.
