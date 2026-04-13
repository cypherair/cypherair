# Rust / FFI Service Integration Plan Assessment

> Status: Archived feasibility assessment snapshot. Its still-relevant conclusions were absorbed into the active [RUST_FFI_SERVICE_INTEGRATION_PLAN](../RUST_FFI_SERVICE_INTEGRATION_PLAN.md); this file remains for historical review context.
> Purpose: Preserve the earlier assessment of whether the Service-layer integration plan was accurate, reasonable, and executable against the repository state at the time of review.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_PLAN](../RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [RUST_FFI_SERVICE_INTEGRATION_BASELINE](../RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_IMPLEMENTATION_REFERENCE](../RUST_FFI_IMPLEMENTATION_REFERENCE.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md)
> Assessment posture: This document records verified code-and-test facts first, then adds cautious architectural conclusions where the current implementation shape clearly supports them.
> Important framing: When the plan document and the repository disagree, production code and tests are treated as the source of truth. Any mismatch becomes a documentation finding, not an implementation assumption.

## 1. Scope And Method

This assessment reviews the five planned workstreams in [RUST_FFI_SERVICE_INTEGRATION_PLAN](../RUST_FFI_SERVICE_INTEGRATION_PLAN.md):

1. selector discovery and selector-bearing Swift models
2. selective revocation in `KeyManagementService`
3. `CertificateSignatureService`
4. detailed result adoption in `SigningService` and `DecryptionService`
5. app consumer adoption for `PasswordMessageService`

Each workstream is evaluated through the same four passes:

1. document-claim audit against the current baseline, architecture, security, and testing docs
2. feasibility review across architecture fit, security boundary, interface completeness, UI ownership, and testing cost
3. dependency and sequencing review
4. document-revision recommendations

This document uses two label sets consistently.

Document-claim labels:

- `准确`: matches the repository state and the current reference docs
- `不完整`: direction is sound, but a decision or boundary is still unspecified
- `夸大`: the plan assumes reuse or simplicity that the current code shape does not support
- `缺失风险`: the plan omits a meaningful security, ownership, or maintenance risk
- `缺失前置`: the plan is blocked on a prerequisite that is not made explicit enough

Workstream conclusion labels:

- `合理且可直接推进`
- `合理但需补前置`
- `可做但顺序应调整`
- `当前不建议推进`

## 2. Executive Summary

Overall judgment:

- The plan direction is broadly reasonable.
- The plan is not yet decision-complete enough to execute as-is.
- The biggest gaps are not about Rust capability completeness. They are about selector discovery ownership, selective-revocation persistence semantics, certificate-signature service inputs/results, and the current bundling of `SigningService` and `DecryptionService` detailed-result work into one workstream.
- The current repository already shows a healthier key-management shape than a "keep growing one god service file" model. `KeyManagementService` is now a relatively thin facade over internal owners under `Sources/Services/KeyManagement/`, so future work should preserve that split instead of pushing new responsibilities back into one file.

Workstream summary:

| Workstream | Conclusion | Short reason |
|---|---|---|
| Selector discovery / selector-bearing model | `合理但需补前置` | Current `KeyInfo` / `PGPKeyIdentity` cannot safely provide subkey fingerprints or raw User ID bytes. The plan must explicitly choose a Rust/FFI-backed discovery surface, not just "more Swift metadata". |
| Selective revocation in `KeyManagementService` | `合理但需补前置` | The service boundary is appropriate, but the current key-level `revocationCert` storage model does not automatically extend to multiple selective revocations. |
| `CertificateSignatureService` | `合理但需补前置` | A dedicated service is the right boundary, but signer-candidate sources, target-certificate ownership, and Swift result typing need to be fixed explicitly. |
| Detailed results in `SigningService` / `DecryptionService` | `可做但顺序应调整` | The family is feasible, but the two services should not stay in one rollout step. `SigningService` is a normal additive contract extension; `DecryptionService` is a security-sensitive boundary change. |
| `PasswordMessageService` app consumer | `可做但顺序应调整` | This is an app-ownership gap, not a service-gap blocker. It is independent work and should not compete with higher-value service-boundary cleanup by default. |

## 3. Claim Audit Against Repository Truth

### 3.1 Claims That Are Accurate

- The plan correctly identifies that [`PasswordMessageService`](../../Sources/Services/PasswordMessageService.swift) already exists as a production service and lacks a direct app route or screen-model owner today.
- The plan correctly identifies that [`SigningService`](../../Sources/Services/SigningService.swift) already consumes one detailed FFI path internally and folds back to legacy semantics.
- The plan correctly identifies that [`DecryptionService`](../../Sources/Services/DecryptionService.swift) remains bound to the current Phase 1 / Phase 2 boundary and that any detailed-result adoption there is security-sensitive.
- The plan correctly identifies that current Swift metadata does not expose selector-bearing subkey/User ID data. [`PGPKeyIdentity`](../../Sources/Models/PGPKeyIdentity.swift) only stores primary identity and summary metadata, while [`KeyInfo`](../../pgp-mobile/src/keys.rs) exposes no subkey selector list and no raw User ID collection.

### 3.2 Claims That Are Incomplete

- Selector discovery is described as a Swift-model problem, but the real gap starts at the Rust/FFI surface. Current `parse_key_info` does not expose the raw selector data that the later service APIs require.
- The proposed `CertificateSignatureService` correctly claims ownership, but does not fix the source of:
  - candidate signer certificates
  - target certificate bytes
  - selector-bearing target User ID metadata
- The detailed-result workstream is framed as one additive service family, but the repo already shows sharply different risk profiles:
  - `SigningService` has partial internal adoption and no security boundary change
  - `DecryptionService` has no detailed adoption and sits on a guarded authentication boundary

### 3.3 Claims That Are Overstated

- The plan says selective revocation should preserve the "current export and storage expectations around revocation bytes and armored export". That is too broad for the current code shape.
- Today, key-level revocation is persisted through a single field, `PGPKeyIdentity.revocationCert`, populated during generation/import and lazily backfilled through [`KeyExportService`](../../Sources/Services/KeyManagement/KeyExportService.swift).
- That singleton storage path does not naturally extend to:
  - multiple subkey revocations
  - multiple User ID revocations
  - mixed selective revocation history over time

### 3.4 Missing Risks

- The plan does not call out that selective revocation touches a sensitive data-lifecycle boundary even though it lives outside `Sources/Security/`. It requires secret certificate unwrapping and raises a new persistence-policy question.
- The plan does not call out that `CertificateSignatureResult` and [`SignatureVerification`](../../Sources/Models/SignatureVerification.swift) are structurally incompatible. This is more than a naming preference; the current app-level message-verification model cannot represent certification kind or signing-subkey fingerprint.
- The plan underweights the ambiguity caused by the current partial detailed-result adoption. [`SigningService.verifyDetachedStreaming(...)`](../../Sources/Services/SigningService.swift) already depends on `verifyDetachedFileDetailed(...)`, but service tests still protect only legacy folded behavior.

### 3.5 Missing Prerequisites

- A bounded selector discovery helper at the Rust/FFI layer must be made explicit before any service-owned selective revocation or User ID-centric certificate-signature workflow starts.
- The selective-revocation workstream needs an explicit v1 persistence/export policy before implementation begins.
- The detailed-result workstream should be split into at least:
  - `SigningService` detailed-result adoption
  - `DecryptionService` detailed-result adoption

## 4. Workstream Assessment

### 4.1 Selector Discovery And Selector-Bearing Swift Model

**Conclusion**

- `合理但需补前置`

**Evidence**

- [`pgp-mobile/src/keys.rs`](../../pgp-mobile/src/keys.rs) `KeyInfo` exposes:
  - primary fingerprint
  - key version
  - one display-oriented `user_id`
  - summary booleans and algorithm names
- [`PGPKeyIdentity`](../../Sources/Models/PGPKeyIdentity.swift) mirrors that summary level and persists only one `userId` string plus high-level metadata.
- Existing selective-revocation and certificate-signature FFI exports require:
  - `subkeyFingerprint`
  - raw `userIdData`
- Current tests confirm those FFI selectors exist, but they are only exercised at FFI level in [`Tests/FFIIntegrationTests/FFIIntegrationTests.swift`](../../Tests/FFIIntegrationTests/FFIIntegrationTests.swift).

**Assessment**

- The plan is right to treat selector discovery as a shared prerequisite.
- The plan is not explicit enough about where that prerequisite must land.
- A Swift-only expansion of `PGPKeyIdentity` is not sufficient because the required selector data is not available through current production parsing APIs.
- The most defensible default is:
  - add a bounded Rust/FFI discovery helper for selectable subkeys and raw User IDs
  - map that into a new Swift selector-bearing model
  - keep `PGPKeyIdentity` as persisted summary metadata, not as the selector catalog

**Hidden cost / blocker**

- If the selector-bearing model is added without a Rust/FFI discovery helper, later service work will be forced to infer selectors from display strings or ad hoc local parsing, which directly conflicts with the implementation reference.

**Suggested plan-document revisions**

- Explicitly state that the current exported `KeyInfo` surface is insufficient.
- Explicitly state that selector discovery requires a new Rust/FFI discovery helper or equivalent exported bounded metadata surface.
- Explicitly state that `PGPKeyIdentity` should remain summary metadata and should not become the long-term selector container.

**Minimum validation checklist**

- Rust / FFI helper exposes selectable subkey identifiers and raw User ID bytes.
- Swift selector-bearing model preserves raw selector values without string normalization loss.
- No caller-facing API uses display strings as cryptographic selectors.
- Both Profile A and Profile B selector discovery work on generated/imported certificates.

### 4.2 Selective Revocation In `KeyManagementService`

**Conclusion**

- `合理但需补前置`

**Evidence**

- Current key-level revocation ownership is already coherent:
  - [`KeyManagementService`](../../Sources/Services/KeyManagementService.swift) is now a 238-line facade that delegates to focused internal owners instead of directly implementing every workflow branch in one file
  - the current internal split is:
    - [`KeyProvisioningService`](../../Sources/Services/KeyManagement/KeyProvisioningService.swift)
    - [`KeyExportService`](../../Sources/Services/KeyManagement/KeyExportService.swift)
    - [`KeyMutationService`](../../Sources/Services/KeyManagement/KeyMutationService.swift)
    - [`PrivateKeyAccessService`](../../Sources/Services/KeyManagement/PrivateKeyAccessService.swift)
    - [`KeyCatalogStore`](../../Sources/Services/KeyManagement/KeyCatalogStore.swift)
  - [`KeyProvisioningService`](../../Sources/Services/KeyManagement/KeyProvisioningService.swift) generates or imports one key-level revocation into `PGPKeyIdentity.revocationCert`
  - [`KeyExportService`](../../Sources/Services/KeyManagement/KeyExportService.swift) exports that binary signature or lazily backfills it
  - [`KeyDetailView`](../../Sources/App/Keys/KeyDetailView.swift) exposes only key-level export
- Current FFI exports already include:
  - `generateSubkeyRevocation(...)`
  - `generateUserIdRevocation(...)`
- Current Swift tests cover key-level revocation storage/backfill/export in [`Tests/ServiceTests/KeyManagementServiceTests.swift`](../../Tests/ServiceTests/KeyManagementServiceTests.swift), but there is no service-owned selective revocation contract yet.

**Assessment**

- Putting selective revocation into `KeyManagementService` is the correct service boundary.
- The additive API direction is sound.
- The current project shape argues against re-expanding `KeyManagementService.swift` into another large mixed-responsibility file.
- The safer pattern is: keep `KeyManagementService` as the app-facing facade and observable state owner, but land new behavior in focused internal owners under `Sources/Services/KeyManagement/` when it belongs to the key lifecycle domain.
- The current plan over-assumes that selective revocation can reuse the current storage expectation unchanged.
- The current repo only has a single persisted revocation slot per identity. That model is key-level-specific.

**Hidden cost / blocker**

- The plan must choose one v1 policy before implementation:
  - export-on-demand only, with no persistence for selective revocations
  - or introduce a new persistence model for multiple selective revocation artifacts
- Until that choice is made, "preserve current export and storage expectations" is not executable guidance.

**Suggested plan-document revisions**

- Narrow the persistence claim. Do not imply that `PGPKeyIdentity.revocationCert` generalizes automatically.
- State the v1 default explicitly. The lowest-risk default is export-on-demand with armored export support and no new persisted selective-revocation store.
- State explicitly that future key-management expansion should follow the existing facade + internal-owner split, not grow `KeyManagementService.swift` back into a monolith.
- Keep UI integration explicitly downstream of the stabilized service contract.

**Minimum validation checklist**

- Service API accepts validated selectors, not raw UI text.
- Selector miss, public-only input, and unusable-secret input map cleanly through current error boundaries.
- Existing key-level revocation generation/export behavior remains unchanged.
- If v1 is export-on-demand, tests prove no accidental persistence assumptions.
- If persistence is added later, tests prove multi-artifact storage semantics explicitly rather than reusing key-level assumptions.

### 4.3 `CertificateSignatureService`

**Conclusion**

- `合理但需补前置`

**Evidence**

- Rust/FFI already exports:
  - `verifyDirectKeySignature(...)`
  - `verifyUserIdBindingSignature(...)`
  - `generateUserIdCertification(...)`
- [`pgp-mobile/src/cert_signature.rs`](../../pgp-mobile/src/cert_signature.rs) defines a family-local result with:
  - `status`
  - `certificationKind`
  - `signerPrimaryFingerprint`
  - optional `signingKeyFingerprint`
- No existing production service under `Sources/Services/` owns these operations.
- [`SignatureVerification`](../../Sources/Models/SignatureVerification.swift) is message-centric and cannot represent certification kind or signing-subkey fingerprint.

**Assessment**

- A dedicated `CertificateSignatureService` is the right boundary.
- The plan is also correct not to piggyback this family on existing message services.
- The plan still needs to lock three ownership decisions:
  - signer candidate source
  - target certificate source
  - selector-bearing target User ID source
- The most coherent default is:
  - candidate signers come from contact public certs plus own public certs
  - certification generation uses local secret-key access through `KeyManagementService`
  - target certificate is passed as certificate bytes or a bounded model that preserves raw `publicKeyData`

**Hidden cost / blocker**

- Without an explicit input-ownership rule, the first implementation will end up inventing ad hoc call-site assembly logic in the UI or screen model.
- User ID-driven operations remain blocked on selector discovery even if direct-key verification alone could technically ship earlier.

**Suggested plan-document revisions**

- Freeze that the service returns certificate-signature-specific Swift result types, not `SignatureVerification`.
- Explicitly name the input ownership expectations for:
  - signer candidates
  - target certificate bytes
  - selector-bearing User ID metadata
- Clarify that direct-key verification is selector-independent, but the service rollout is still grouped behind selector discovery because two of the three planned operations are User ID-driven.

**Minimum validation checklist**

- Service-level tests preserve `Valid`, `Invalid`, and `SignerMissing`.
- User ID binding tests preserve `certificationKind`.
- Successful subkey-signer verification preserves both primary signer fingerprint and signing-subkey fingerprint.
- `Invalid` and `SignerMissing` clear both fingerprint fields.
- Public-only certification input rejection and unusable-certifier rejection stay mapped through current cross-layer error rules.

### 4.4 Detailed Result Adoption In `SigningService` And `DecryptionService`

**Conclusion**

- `可做但顺序应调整`

**Evidence**

- Detailed-result Rust/FFI types already exist in:
  - [`pgp-mobile/src/signature_details.rs`](../../pgp-mobile/src/signature_details.rs)
  - [`pgp-mobile/src/verify.rs`](../../pgp-mobile/src/verify.rs)
  - [`pgp-mobile/src/decrypt.rs`](../../pgp-mobile/src/decrypt.rs)
- [`SigningService`](../../Sources/Services/SigningService.swift) already calls `verifyDetachedFileDetailed(...)` but folds immediately to legacy `SignatureVerification`.
- [`DecryptionService`](../../Sources/Services/DecryptionService.swift) still uses only legacy `decrypt(...)` and `decryptFile(...)`.
- FFI tests cover parser order, repeated signers, unknown signers, and legacy-compat fields.
- Service tests currently cover only legacy folded behavior on the streaming verify path in [`Tests/ServiceTests/StreamingServiceTests.swift`](../../Tests/ServiceTests/StreamingServiceTests.swift).

**Assessment**

- The family is feasible.
- The current workstream should not stay bundled as one rollout item.
- `SigningService` detailed-result adoption is a normal additive service-contract extension and is already half-present internally.
- `DecryptionService` detailed-result adoption is materially different:
  - it touches a documented security-sensitive file
  - it must not weaken the Phase 1 / Phase 2 split
  - it must not change auth-failure hard-stop behavior
- The safest interpretation is to split the current workstream into:
  - `SigningService` detailed-result adoption
  - `DecryptionService` detailed-result adoption after separate human review

**Hidden cost / blocker**

- Keeping both services in one rollout item hides the review boundary and invites one combined implementation diff across very different risk classes.

**Suggested plan-document revisions**

- Split the workstream into two sequenced items.
- State that `SigningService` can move first because it already has partial internal detailed adoption.
- State that `DecryptionService` detailed adoption is last among service-boundary changes and requires dedicated human review.
- Clarify that shared Swift helper structures are acceptable only if service-level result semantics remain distinct.

**Minimum validation checklist**

- `SigningService` service tests preserve detailed signature arrays, parser order, repeated signers, unknown signers, and legacy-compat fields.
- `DecryptionService` tests prove the current Phase 1 / Phase 2 boundary is unchanged.
- `DecryptionService` tests prove auth/integrity failures still hard-fail and do not leak partial plaintext.
- Streaming file detailed paths keep cancellation and cleanup semantics.

### 4.5 `PasswordMessageService` App Consumer

**Conclusion**

- `可做但顺序应调整`

**Evidence**

- [`PasswordMessageService`](../../Sources/Services/PasswordMessageService.swift) is production-ready and covered by dedicated service tests in [`Tests/ServiceTests/PasswordMessageServiceTests.swift`](../../Tests/ServiceTests/PasswordMessageServiceTests.swift).
- [`AppContainer`](../../Sources/App/AppContainer.swift) constructs the service.
- [`AppRoute`](../../Sources/App/AppRoute.swift) has no password-message route today.
- Current app review of `Sources/App/` shows no direct screen-model or route consumer.

**Assessment**

- The plan is correct that this is an app-ownership workstream, not a service rewrite.
- It is also the least coupled of the five items.
- It does not unblock selector discovery, selective revocation, certificate-signature services, or detailed-result service contracts.
- That makes it a good independent product workstream, but a weak sequencing dependency inside a Service-integration roadmap.

**Hidden cost / blocker**

- The work itself is not blocked technically.
- The real decision is product priority plus UI-boundary plaintext ownership:
  - where decrypted plaintext lives
  - when it is cleared
  - how signed password-message results are presented

**Suggested plan-document revisions**

- Reframe this item as an independent app-ownership track, not a dependency tail of the Service-integration sequence.
- Keep the explicit UI-boundary ownership requirements:
  - `noSkesk`
  - `passwordRejected`
  - fatal auth/integrity failure
  - optional signature reporting
- If the app does not need this workflow soon, say so explicitly and lower its priority.

**Minimum validation checklist**

- Add route, view, and screen-model ownership without reusing recipient-key decrypt flow.
- UI tests or screen-model tests cover `noSkesk`, `passwordRejected`, and fatal auth/integrity failure mapping.
- Plaintext lifetime and zeroization ownership are documented at the screen boundary.
- Existing `PasswordMessageService` tests remain unchanged and valid.

## 5. Sequencing Review

### 5.1 Why The Current 1 → 5 Order Is Only Partly Good

The current order gets one important dependency right:

- selector discovery really is the shared prerequisite for selective revocation and most of `CertificateSignatureService`

The current order is weaker in three places:

- it puts selective revocation ahead of a lower-coupling new service (`CertificateSignatureService`)
- it keeps `SigningService` and `DecryptionService` detailed adoption in one risk bucket
- it treats `PasswordMessageService` app consumer work like the natural tail of service integration, even though it is independent product-surface work

### 5.2 Recommended Execution Order

Recommended order:

1. selector discovery + Rust/FFI-backed bounded discovery helper + selector-bearing Swift model
2. `CertificateSignatureService`
3. `SigningService` detailed-result service contract
4. selective revocation in `KeyManagementService`
5. `PasswordMessageService` app consumer, only if product wants the workflow now
6. `DecryptionService` detailed-result service contract, as a separately reviewed security-sensitive phase

Why this order is lower risk:

- step 1 unblocks all selector-dependent work with one explicit contract
- step 2 lands a new bounded service without touching existing security-critical flows
- step 3 resolves the current partial-adoption ambiguity already present in `SigningService`
- step 4 lands the more stateful selective-revocation service work after selector contracts are stable
- step 5 stays decoupled from the Service-boundary work
- step 6 isolates the most security-sensitive contract expansion to the end

## 6. Required Plan-Document Revisions

### 6.1 Must Fix Before Implementation

1. State explicitly that selector discovery requires new Rust/FFI discovery support, not only new Swift metadata.
2. Replace the broad selective-revocation storage claim with an explicit v1 persistence/export policy.
3. Split detailed-result adoption into `SigningService` and `DecryptionService` phases.
4. Define `CertificateSignatureService` input ownership and result-shape expectations more concretely.

### 6.2 Safe To Revise Alongside Implementation

1. Freeze exact Swift type names for selector-bearing metadata after the bounded discovery shape is chosen.
2. Freeze route/view/screen-model names for the password-message app consumer only if product decides to expose the workflow.
3. Decide whether detailed verify/decrypt result types share a small common helper layer or stay fully separate.

### 6.3 Safe To Defer

1. UI attachment point for selective revocation after the service contract is stable.
2. Concrete certificate-management UI entry point for `CertificateSignatureService`.
3. Any broader trust-management or contact-verification workflow that may eventually consume certificate-signature features.

## 7. Final Verdict

The current plan is not fundamentally misguided. It is mostly pointing at real remaining integration work. The main issue is that it still mixes three different classes of work:

- true prerequisites that need interface decisions first
- normal additive service adoption
- independent app-surface exposure

If the plan document is revised with the prerequisites and sequencing changes recorded here, it becomes a feasible downstream implementation guide. If it is executed without those revisions, the most likely failure modes are:

- ad hoc selector discovery leaking into Swift callers
- selective-revocation persistence semantics being invented mid-implementation
- certificate-signature result typing getting flattened into message-verification concepts
- `DecryptionService` detailed adoption getting bundled into an oversized mixed-risk diff

Final per-workstream verdicts:

- Selector discovery / selector-bearing model: `合理但需补前置`
- Selective revocation in `KeyManagementService`: `合理但需补前置`
- `CertificateSignatureService`: `合理但需补前置`
- Detailed results in `SigningService` / `DecryptionService`: `可做但顺序应调整`
- `PasswordMessageService` app consumer: `可做但顺序应调整`
