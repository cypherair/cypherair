# Rust / FFI Three-Document Review

> Status: Archived review snapshot from 2026-04-13. Kept as a point-in-time evidence document for the active Rust / FFI doc stack.
> Scope: Comprehensive review of `RUST_FFI_IMPLEMENTATION_REFERENCE.md`, `RUST_FFI_SERVICE_INTEGRATION_BASELINE.md`, and `RUST_FFI_SERVICE_INTEGRATION_PLAN.md`.
> Outcome: 16 audited current-state claims in the three target docs were `准确`; 0 were `部分准确`; 0 were `已过时`; 0 were `无法仅凭仓库确认`. The active issues are concentrated in rollout-plan decision completeness and companion-doc consistency, not in the target docs' current-state descriptions.
> Truth sources: production code, generated UniFFI Swift bindings, Swift service/app wiring, Rust tests, Swift FFI tests, Swift service tests, and relevant companion docs.

## 1. Method

- Repository baseline date: 2026-04-13.
- Truth precedence: code and tests over docs; current generated bindings over historical descriptions; absence checks over assumptions for negative claims.
- Evidence roots:
  - `pgp-mobile/src/`
  - `Sources/PgpMobile/pgp_mobile.swift`
  - `Sources/Services/`
  - `Sources/App/`
  - `Tests/FFIIntegrationTests/`
  - `Tests/ServiceTests/`
  - companion docs `ARCHITECTURE.md`, `SECURITY.md`, `TESTING.md`
- Archived 2026-04-11 reviews were re-checked as historical baselines only:
  - `docs/archive/RUST_FFI_CURRENT_STATE_AUDIT.md`
  - `docs/archive/RUST_FFI_SERVICE_INTEGRATION_PLAN_ASSESSMENT.md`
- No dynamic build or test commands were needed for the target-doc review. Static evidence was sufficient for every audited claim.

Current-state verdict labels:

- `准确`: matches current repository truth
- `部分准确`: directionally right, but one material detail drifted
- `已过时`: contradicted by current code, bindings, or tests
- `无法仅凭仓库确认`: claim needs runtime or external evidence not available from static repo truth

Plan-workstream verdict labels:

- `合理且可直接推进`
- `合理但需补前置`
- `可做但顺序应调整`
- `当前不建议推进`

## 2. Executive Summary

- The three target docs are strong on current-state truth. I did not find a code-structure or service-ownership claim in them that has drifted away from the repository.
- `RUST_FFI_IMPLEMENTATION_REFERENCE.md` remains semantically well-aligned with the current Rust wrapper, UniFFI surface, and test suite. I did not find active `事实漂移` or `语义夸大` in its global rules or family sections.
- The active issues are in `RUST_FFI_SERVICE_INTEGRATION_PLAN.md`: the rollout direction is broadly sound, but several workstreams are still not decision-complete enough to hand directly to an implementer.
- The plan has improved since the 2026-04-11 assessment:
  - `SigningService` and `DecryptionService` detailed-result adoption are now split into separate phases.
  - selective-revocation v1 persistence is now fixed to export-on-demand instead of an implied new store.
  - selector discovery is now explicitly placed at the Rust / FFI boundary.
- Two companion docs still contain drift that can mislead implementers even though the three target docs are accurate:
  - `ARCHITECTURE.md` still lists `pgp-mobile/uniffi.toml` as a current repo file, but that file does not exist.
  - `TESTING.md` still contains stale Swift API examples that do not match the current service and FFI signatures.

## 3. Current-State Claim Ledger

| ID | Source | Claim | Evidence | Verdict | Notes |
|---|---|---|---|---|---|
| X-01 | `IMPLEMENTATION_REFERENCE:7-26,32-41` | `IMPLEMENTATION_REFERENCE` owns Rust / FFI semantic rules and validation, not current downstream Swift service inventory or rollout order. | `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md:10-27`; `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:10-27` | `准确` | The three-doc split is internally coherent. |
| X-02 | `BASELINE:3-27` | `BASELINE` is the active current-state document for existing Rust / FFI surface, service ownership, app consumers, coverage, and current gaps. | `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md:11-13,38-41`; `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:12-25` | `准确` | Role boundaries remain clean. |
| X-03 | `PLAN:3-27` | `PLAN` owns rollout order, planned service ownership, interface decisions, and validation expectations for remaining adoption work. | `docs/RUST_FFI_SERVICE_INTEGRATION_BASELINE.md:12-27`; `docs/RUST_FFI_IMPLEMENTATION_REFERENCE.md:11-13,38-41` | `准确` | `PLAN` is being used for future-state decisions rather than current-state inventory. |
| B-01 | `IMPLEMENTATION_REFERENCE:45-58` | Current Rust baseline is `sequoia-openpgp = 2.2.0`, `default-features = false`, features `crypto-openssl` and `compression-deflate`. | `pgp-mobile/Cargo.toml:13-21` | `准确` | Cargo manifest matches the doc exactly. |
| B-02 | `IMPLEMENTATION_REFERENCE:52-58` | Runtime policy customization, caller-facing backend selection, and caller-facing outgoing compression remain excluded from the exported surface. | `pgp-mobile/src/lib.rs:63-567`; `Sources/PgpMobile/pgp_mobile.swift:592-827`; `pgp-mobile/src/encrypt.rs:195-249` | `准确` | `StandardPolicy` is internal-only; no exported API takes policy/backend/compression knobs; encrypt path explicitly writes literal data without compression. |
| B-03 | `IMPLEMENTATION_REFERENCE:54-58` | Generic packet / metadata introspection beyond bounded helpers such as recipient parsing remains unwrapped. | `pgp-mobile/src/lib.rs:75-112,209-231,401-447,572-620`; `Sources/PgpMobile/pgp_mobile.swift:586-787`; absence of any generic packet-inspection API in `pgp-mobile/src/lib.rs` | `准确` | The repo exposes bounded helpers, not a generic packet-inspection surface. |
| B-04 | `IMPLEMENTATION_REFERENCE:57-58` | QR URL encode/decode helpers are app-specific extensions layered on Sequoia parsing, not missing Sequoia wrappers. | `pgp-mobile/src/lib.rs:572-620`; `Sources/PgpMobile/pgp_mobile.swift:586-627`; `Sources/Services/QRService.swift:1-142` | `准确` | The QR helpers are explicit CypherAir glue code around certificate validation and URL formatting. |
| C-01 | `BASELINE:41,49-56` | Certificate Merge / Update is already production-adopted through `ContactService`, app import flows, and Rust/FFI/service coverage. | `pgp-mobile/src/lib.rs:90-112`; `Sources/PgpMobile/pgp_mobile.swift:723-787`; `Sources/Services/ContactService.swift:83-210`; `Sources/App/Contacts/Import/ContactImportWorkflow.swift:20-124`; `Sources/App/Contacts/AddContactView.swift:66-73`; `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift:25-58`; `Sources/App/CypherAirApp.swift:49-52`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:426-608`; `Tests/ServiceTests/ContactServiceTests.swift:326-571`; `pgp-mobile/tests/certificate_merge_tests.rs:129-391` | `准确` | No current production-path gap was found. |
| R-01 | `BASELINE:42,58-72,114` | Revocation Construction is key-level production-adopted through `KeyManagementService`, while subkey/User ID builders remain FFI-only and selector-blocked. | `pgp-mobile/src/lib.rs:401-435`; `Sources/PgpMobile/pgp_mobile.swift:677-692,757`; `Sources/Services/KeyManagementService.swift:143-152`; `Sources/App/Keys/KeyDetailView.swift:211-219`; `Tests/ServiceTests/KeyManagementServiceTests.swift:1137-1298`; `pgp-mobile/tests/revocation_construction_tests.rs:77-315` | `准确` | Key-level export path is live; selective builders have no production owner. |
| R-02 | `BASELINE:67-72` | Current Swift-facing model surfaces do not expose selector-bearing subkey fingerprints or raw User ID bytes. | `pgp-mobile/src/keys.rs:51-74`; `Sources/PgpMobile/pgp_mobile.swift:2492-2577`; `Sources/Models/PGPKeyIdentity.swift:9-57` | `准确` | This selector gap is real in both Rust `KeyInfo` and persisted Swift metadata. |
| P-01 | `BASELINE:43,74-87,115` | Password / SKESK is already wrapped by a real production Swift service, but there is no app route or screen-model owner. | `pgp-mobile/src/lib.rs:171-205,258-267`; `Sources/PgpMobile/pgp_mobile.swift:611-658,677-688`; `Sources/Services/PasswordMessageService.swift:3-194`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:273-422`; `Tests/ServiceTests/PasswordMessageServiceTests.swift:68-205`; `rg -n "passwordMessageService" Sources/App` -> only `Sources/App/AppContainer.swift:14,31,47,83,106,158,181` | `准确` | The service exists, but app ownership is still absent. |
| S-01 | `BASELINE:44,89-98,116` | Certification And Binding Verification is FFI-complete, but there is no production service owner or app consumer. | `pgp-mobile/src/lib.rs:325-365`; `Sources/PgpMobile/pgp_mobile.swift:687,822-827,1876-1917`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1158-1362`; `pgp-mobile/tests/certification_binding_tests.rs:251-656`; `rg -n "verifyDirectKeySignature|verifyUserIdBindingSignature|generateUserIdCertification|CertificateSignatureService" Sources/App Sources/Services` -> no hits | `准确` | The absence claim is supported by a repo-wide search. |
| D-01 | `BASELINE:45,100-109,117` | Richer Signature Results are FFI-complete and partially consumed inside `SigningService`, but detailed semantics still do not cross the service boundary as first-class contracts. | `pgp-mobile/src/lib.rs:246-256,294-321,500-557`; `Sources/PgpMobile/pgp_mobile.swift:592-608,797-817,1972-2015,2181-2350`; `Sources/Services/SigningService.swift:193-289`; `Sources/Services/DecryptionService.swift:168-355`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`; `Tests/ServiceTests/StreamingServiceTests.swift:145-259`; `pgp-mobile/tests/detailed_signature_tests.rs:128-469` | `准确` | Partial internal adoption is real, and detailed result types are still not service-level outputs. |
| D-02 | `BASELINE:104-109` | Current app flows still expose only legacy single-status signature semantics. | `Sources/Models/SignatureVerification.swift:3-185`; `Sources/App/Sign/VerifyScreenModel.swift:13-22,48-92`; `rg -n "VerifyDetailedResult|DecryptDetailedResult|FileVerifyDetailedResult|FileDecryptDetailedResult" Sources/App Sources/Services` -> only `Sources/Services/SigningService.swift:200,284` | `准确` | App-facing models are still folded to `SignatureVerification`. |
| IR-01 | `IMPLEMENTATION_REFERENCE:479-482` | Current Swift FFI password coverage includes `seipdv1`/`seipdv2`, signed round-trip, `noSkesk`, `passwordRejected`, and auth/integrity tamper cases, but not mixed-message or unsupported-algorithm FFI smoke tests. | Present FFI coverage: `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:273-422`; Rust-only mixed/unsupported coverage: `pgp-mobile/tests/password_message_tests.rs:478-625` | `准确` | The negative claim is still true on 2026-04-13. |
| IR-02 | `IMPLEMENTATION_REFERENCE:699-702` | Current Swift FFI detailed-result coverage is broad, but there is still no dedicated expired-signature detailed FFI smoke test. | Present FFI detailed coverage: `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`; Rust expired detailed coverage: `pgp-mobile/tests/detailed_signature_tests.rs:186-206`; no expired detailed FFI test found by repo-wide search in `Tests/FFIIntegrationTests/FFIIntegrationTests.swift` | `准确` | The documented FFI gap remains real. |

Current-state verdict summary:

- `准确`: 16
- `部分准确`: 0
- `已过时`: 0
- `无法仅凭仓库确认`: 0

## 4. `IMPLEMENTATION_REFERENCE` Normative Review

| ID | Source | Normative cluster | Evidence | Verdict | Notes |
|---|---|---|---|---|---|
| N-01 | `IMPLEMENTATION_REFERENCE:83-203` | Global rules on additive API evolution, generated-binding workflow, sensitive input handling, signer-fingerprint semantics, and minimum validation remain aligned with current Rust exports and companion docs. | `pgp-mobile/src/lib.rs:121-127,145-205,233-267,325-365,401-557`; `pgp-mobile/src/signature_details.rs:24-59`; `Sources/Services/SigningService.swift:118-225`; `Sources/Services/DecryptionService.swift:168-309`; `docs/SECURITY.md:280-307`; `docs/TESTING.md:1-119` | `准确` | No active drift was found in the global contract sections. |
| N-02 | `IMPLEMENTATION_REFERENCE:226-299` | Certificate Merge / Update semantic contract and minimum-test expectations are supported by the Rust implementation, UniFFI surface, and service/FFI tests. | `pgp-mobile/src/keys.rs:459-515`; `pgp-mobile/src/lib.rs:102-112`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:426-608`; `Tests/ServiceTests/ContactServiceTests.swift:326-571`; `pgp-mobile/tests/certificate_merge_tests.rs:129-391` | `准确` | No overstatement or missing semantic guarantee was found in this family section. |
| N-03 | `IMPLEMENTATION_REFERENCE:301-375` | Revocation Construction semantics, selector deferment, and minimum-test commitments remain aligned with the current code and tests. | `pgp-mobile/src/keys.rs:771-907`; `pgp-mobile/src/lib.rs:401-435`; `pgp-mobile/tests/revocation_construction_tests.rs:77-315`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:974-1087`; `Tests/ServiceTests/KeyManagementServiceTests.swift:1137-1298` | `准确` | The active gap is still selector discovery, not a mismatch between docs and code. |
| N-04 | `IMPLEMENTATION_REFERENCE:376-486` | Password / SKESK semantics, three-way decrypt classification, fatal auth/integrity behavior, and current-repo coverage notes remain correct. | `pgp-mobile/src/password.rs:13-250`; `pgp-mobile/src/lib.rs:171-205,258-267`; `Sources/Services/PasswordMessageService.swift:13-194`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:273-422`; `Tests/ServiceTests/PasswordMessageServiceTests.swift:68-205`; `pgp-mobile/tests/password_message_tests.rs:288-625` | `准确` | No active `事实漂移` or `语义夸大` found. |
| N-05 | `IMPLEMENTATION_REFERENCE:488-580` | Certification / binding verification remains correctly specified as `crypto-only`, with two-layer signer output and candidate-order fallback semantics. | `pgp-mobile/src/cert_signature.rs:9-447`; `pgp-mobile/src/lib.rs:325-365`; `Sources/PgpMobile/pgp_mobile.swift:1870-1946`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1158-1362`; `pgp-mobile/tests/certification_binding_tests.rs:251-656` | `准确` | The current implementation already supports both `signerPrimaryFingerprint` and `signingKeyFingerprint`. |
| N-06 | `IMPLEMENTATION_REFERENCE:582-745` | Richer Signature Results semantics, legacy-compatibility rules, and minimum-test expectations remain aligned with the current collector, exported records, and FFI/Rust coverage. | `pgp-mobile/src/signature_details.rs:8-199`; `pgp-mobile/src/lib.rs:246-256,294-321,500-557`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`; `pgp-mobile/tests/detailed_signature_tests.rs:128-469` | `准确` | The active gap remains service adoption, not family semantics. |

Normative review summary:

- I did not find active `事实漂移` in `RUST_FFI_IMPLEMENTATION_REFERENCE.md`.
- I did not find an active `语义夸大` where the document promises more than the current code/tests support.
- The document's own “semantic baseline, names may freeze later” posture remains consistent with the current repository.
- The active decision-complete issues are concentrated in `RUST_FFI_SERVICE_INTEGRATION_PLAN.md`, not in `IMPLEMENTATION_REFERENCE`.

## 5. `SERVICE_INTEGRATION_PLAN` Workstream Assessment

| Workstream | Verdict | Evidence | Active issue |
|---|---|---|---|
| Selector discovery + selector-bearing Swift metadata | `合理但需补前置` | Current selector data is absent from both Rust `KeyInfo` and Swift `PGPKeyIdentity`: `pgp-mobile/src/keys.rs:51-74`; `Sources/PgpMobile/pgp_mobile.swift:2492-2577`; `Sources/Models/PGPKeyIdentity.swift:9-57`. | The plan correctly identifies the prerequisite, but it still leaves the actual exported Rust / FFI shape open as “helper or equivalent bounded metadata surface”. That choice should be frozen before implementation starts. |
| `CertificateSignatureService` | `合理但需补前置` | There is no current service owner: absence check `rg -n "verifyDirectKeySignature|verifyUserIdBindingSignature|generateUserIdCertification|CertificateSignatureService" Sources/App Sources/Services` returned no hits. Current FFI result shape already exists: `pgp-mobile/src/cert_signature.rs:26-41`; `Sources/PgpMobile/pgp_mobile.swift:1870-1917`. | The plan still leaves one material interface choice open: whether the service accepts raw certificate bytes or a new bounded Swift certificate type. It also needs to freeze the service result fields explicitly instead of only saying “certificate-signature-specific result types”. |
| `SigningService` detailed results | `可做但顺序应调整` | `SigningService.verifyDetachedStreaming(...)` already calls `verifyDetachedFileDetailed(...)`: `Sources/Services/SigningService.swift:193-289`. Detailed result types and FFI tests already exist: `Sources/PgpMobile/pgp_mobile.swift:1972-2350`; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`. | This workstream is independent of selector discovery and certificate-signature service adoption. It can land earlier than the current sequence suggests and is the lowest-risk remaining service-boundary extension. |
| `KeyManagementService` selective revocation | `合理但需补前置` | Rust exports exist but have no production owner: `pgp-mobile/src/lib.rs:417-435`; `Sources/Services/KeyManagementService.swift:143-152`; absence of selective revocation callers in `Sources/App` and `Sources/Services`. | The plan now correctly fixes v1 persistence, but it still does not freeze the service-facing generation/export contract: raw revocation bytes only, armored export only, or both. That choice affects API shape and tests. |
| `PasswordMessageService` app consumer | `当前不建议推进` | There is no app consumer today: `rg -n "passwordMessageService" Sources/App` only hits `Sources/App/AppContainer.swift:14,31,47,83,106,158,181`. Service semantics are already covered: `Sources/Services/PasswordMessageService.swift:3-194`; `Tests/ServiceTests/PasswordMessageServiceTests.swift:68-205`. | This is not a service-boundary blocker. Without an explicit product requirement to expose password-message UX now, it should stay out of the active rollout queue. |
| `DecryptionService` detailed results | `合理但需补前置` | `DecryptionService` is security-sensitive: `Sources/Services/DecryptionService.swift:3-10`; `docs/SECURITY.md:289`; there is no current detailed service contract, only legacy outputs: `Sources/Services/DecryptionService.swift:168-355`. | The plan correctly separates this phase, but it should still freeze the exact service API set across the Phase 1 / Phase 2 boundary before implementation starts. |

## 6. Findings

Findings are ordered by severity and implementation impact.

- High: `RUST_FFI_SERVICE_INTEGRATION_PLAN.md` still leaves the selector-discovery export shape under-specified.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:48-61,151-154`
  `pgp-mobile/src/keys.rs:51-74`
  `Sources/Models/PGPKeyIdentity.swift:9-57`
  Why it matters:
  all later selective-revocation and User ID-driven certificate-signature work depends on whether selector data is delivered through a new FFI helper, an expanded `KeyInfo`, or a dedicated bounded record. The active plan still says “helper or equivalent exported bounded metadata surface”, which leaves a material interface decision to the implementer.

- High: `RUST_FFI_SERVICE_INTEGRATION_PLAN.md` still leaves `CertificateSignatureService` input/result design under-specified.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:72-80,171-176,207-211`
  `pgp-mobile/src/cert_signature.rs:26-41`
  `Sources/Models/SignatureVerification.swift:3-185`
  Why it matters:
  “certificate bytes or a bounded Swift type that preserves `publicKeyData`” is not a cosmetic choice. It changes service ownership, call-site ergonomics, and test fixtures. The plan should also explicitly freeze the minimum Swift result fields as `status`, `certificationKind`, `signerPrimaryFingerprint`, and `signingKeyFingerprint`.

- Medium: `SigningService` detailed-result adoption is sequenced later than necessary.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:33-38,83-96,243-250`
  `Sources/Services/SigningService.swift:193-289`
  `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1366-1677`
  Why it matters:
  this workstream is self-contained, already partially exercised in production services, and does not depend on selector discovery or certificate-signature ownership. It can be promoted earlier to reduce risk and unlock value sooner.

- Medium: selective-revocation v1 persistence is now correctly fixed, but the plan still does not freeze the service generation/export contract.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:109-116,163-167,221-225`
  `pgp-mobile/src/lib.rs:417-435`
  `Sources/Services/KeyManagementService.swift:143-152`
  Why it matters:
  the implementer still has to choose whether selective revocation APIs return raw revocation bytes, armored export data, or a pair of generation/export methods. That affects the service facade, UI handoff, and tests.

- Medium: `DecryptionService` detailed-result adoption is correctly isolated as a security-sensitive phase, but it is still not decision-complete enough to implement safely.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:131-145,184-189,234-239`
  `Sources/Services/DecryptionService.swift:3-10,168-355`
  `docs/SECURITY.md:289`
  Why it matters:
  the plan does not yet freeze which detailed service methods should exist across the Phase 1 / Phase 2 boundary, or whether the detailed contract attaches to `decrypt(phase1:)`, `decryptFileStreaming(phase1:)`, convenience wrappers, or all three.

- Low: `PasswordMessageService` app-consumer work should remain explicitly out of the active rollout unless product scope changes.
  Evidence:
  `docs/RUST_FFI_SERVICE_INTEGRATION_PLAN.md:118-129,191-194,227-232`
  `rg -n "passwordMessageService" Sources/App` -> only `Sources/App/AppContainer.swift:14,31,47,83,106,158,181`
  Why it matters:
  the workstream is feasible, but there is no current product surface demanding it. Treating it as active rollout work would spend effort on UI exposure rather than closing service-boundary gaps.

- Low: `ARCHITECTURE.md` contains stale Rust-engine inventory that can mislead readers of the target docs.
  Evidence:
  `docs/ARCHITECTURE.md:106-122`
  `ls pgp-mobile` -> no `uniffi.toml`
  Why it matters:
  the three target docs correctly cite `ARCHITECTURE.md` as a companion, but that companion still lists a file that no longer exists in the repo.

- Low: `TESTING.md` still contains stale API examples that do not match the current Swift/FFI surface.
  Evidence:
  stale examples:
  `docs/TESTING.md:431-490`
  current APIs:
  `pgp-mobile/src/lib.rs:63-567`
  `Sources/Services/DecryptionService.swift:57-355`
  Why it matters:
  this does not invalidate the three target docs, but it weakens the surrounding validation guidance they reference.

Finding summary:

- No findings were raised against the target docs' current-state descriptions.
- Active findings are concentrated in rollout-plan completeness and companion-doc drift.

## 7. Revision Guidance For `RUST_FFI_SERVICE_INTEGRATION_PLAN.md`

Only execution-affecting revisions are included below.

1. Freeze selector discovery as a dedicated Rust / FFI export shape.
   Recommended default:
   use a new bounded discovery record/helper rather than expanding `KeyInfo`.
   The exported surface should carry selectable subkey fingerprints plus raw `userIdData`, and Swift should map it into a separate selector-bearing model.

2. Freeze `CertificateSignatureService` inputs and results.
   Recommended default:
   keep target-certificate input as public-certificate bytes or a new bounded Swift type, but choose one explicitly.
   The minimum Swift result contract should include `status`, `certificationKind`, `signerPrimaryFingerprint`, and `signingKeyFingerprint`.

3. Move `SigningService` detailed-result adoption earlier in the sequence.
   Recommended default sequence:
   1. `SigningService` detailed results
   2. selector discovery
   3. `CertificateSignatureService`
   4. selective revocation in `KeyManagementService`
   5. optional `PasswordMessageService` app consumer only if product scope asks for it
   6. `DecryptionService` detailed results

4. Freeze the selective-revocation service generation/export contract.
   Recommended default:
   additive `KeyManagementService` generation APIs return raw revocation bytes, while armored export remains a separate service concern mirroring the current key-level export flow.

5. Keep the `PasswordMessageService` app consumer explicitly outside the active rollout unless a product document asks for it.
   Recommended default:
   leave the workstream marked optional and non-blocking, not merely “later in sequence”.

6. Freeze the `DecryptionService` detailed API set before implementation.
   Recommended default:
   specify which detailed variants exist for:
   - in-memory decrypt after Phase 1
   - file decrypt after Phase 1
   - any convenience wrapper, if one is retained
   and state explicitly that none of them may bypass the existing Phase 1 / Phase 2 authentication boundary.

## 8. Keep-As-Is Summary

These conclusions in the three target docs can remain unchanged based on the current repository:

- The three-doc role split is clear and still matches the repo.
- `BASELINE` correctly describes the current service/app ownership and current gaps for all five capability families.
- `IMPLEMENTATION_REFERENCE` correctly captures the current Rust / FFI semantic contracts, current-repo coverage notes, and validation minima.
- The target docs' present-tense statements about `PasswordMessageService`, `CertificateSignatureResult`, selector-bearing metadata absence, and partial detailed-result service adoption all still match current code.

## 9. Time-Differential Re-Check Against 2026-04-11

- The 2026-04-11 current-state audit remains valid for the target-doc current-state claims. I did not find any audited current-state claim that has drifted since then.
- The active plan has already absorbed several earlier assessment corrections:
  - `SigningService` and `DecryptionService` detailed-result work are now separate phases.
  - selective-revocation v1 persistence is now explicitly fixed to export-on-demand with no new store.
  - selector discovery is now explicitly placed at the Rust / FFI boundary.
- The remaining active concerns from the 2026-04-11 plan assessment still stand in current form:
  - selector-discovery API shape is not frozen
  - `CertificateSignatureService` input/result surface is not frozen
  - `SigningService` detailed results are sequenced later than necessary
  - `PasswordMessageService` app consumer is still product-dependent
  - `DecryptionService` detailed API shape still needs a pre-implementation freeze
