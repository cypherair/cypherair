# Rust / FFI Implementation Reference

> Purpose: Provide the implementation reference for future `pgp-mobile` and UniFFI surface expansion.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [RUST_FFI_SERVICE_INTEGRATION_BASELINE](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) · [RUST_FFI_SERVICE_INTEGRATION_PLAN](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) · [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [archive/RUST_SEQUOIA_INTEGRATION_TODO](archive/RUST_SEQUOIA_INTEGRATION_TODO.md) · [PRD](PRD.md) · [TDD](TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md) · [CODE_REVIEW](CODE_REVIEW.md)

This document does not replace the service baseline, rollout plan, audit, or the archived roadmap snapshot:

- [RUST_FFI_SERVICE_INTEGRATION_BASELINE.md](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md) is the active current-state document for Swift service ownership, app ownership, and current integration gaps.
- [RUST_FFI_SERVICE_INTEGRATION_PLAN.md](RUST_FFI_SERVICE_INTEGRATION_PLAN.md) is the active planning document for Swift service ownership, app ownership, and integration sequencing.
- [SEQUOIA_CAPABILITY_AUDIT.md](SEQUOIA_CAPABILITY_AUDIT.md) remains the canonical current-build inventory.
- [archive/RUST_SEQUOIA_INTEGRATION_TODO.md](archive/RUST_SEQUOIA_INTEGRATION_TODO.md) remains the historical roadmap snapshot from the Sequoia expansion phase.
- This document is the implementation reference for future Rust / FFI expansion work.

This document is intentionally narrower than a full design package:

- it covers the Rust layer, the UniFFI export surface, Rust tests, and Swift FFI tests
- it does not own current downstream Swift integration state or rollout planning
- current service ownership, app ownership, and current gaps live in [RUST_FFI_SERVICE_INTEGRATION_BASELINE.md](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md)
- rollout sequencing and next service-integration work live in [RUST_FFI_SERVICE_INTEGRATION_PLAN.md](RUST_FFI_SERVICE_INTEGRATION_PLAN.md)
- it is a hybrid reference spec: strong on semantics, boundaries, and validation, but not automatically a frozen public-API contract for every family
- only current blockers that still affect interface semantics or validation belong in `Open Questions`

## 1. Purpose And Role

### 1.1 Role In The Documentation Stack

Use this document when planning or implementing new Rust / FFI capability in `pgp-mobile`.

Use the companion documents as follows:

- product goals and user-facing requirements live in [PRD.md](PRD.md)
- library choice, platform constraints, and existing FFI architecture live in [TDD.md](TDD.md)
- current Swift service ownership, app ownership, and current integration gaps live in [RUST_FFI_SERVICE_INTEGRATION_BASELINE.md](RUST_FFI_SERVICE_INTEGRATION_BASELINE.md)
- rollout sequencing and planned downstream service ownership live in [RUST_FFI_SERVICE_INTEGRATION_PLAN.md](RUST_FFI_SERVICE_INTEGRATION_PLAN.md)
- current implementation coverage lives in [SEQUOIA_CAPABILITY_AUDIT.md](SEQUOIA_CAPABILITY_AUDIT.md)
- historical workstream priority and recommended execution order from that phase live in [archive/RUST_SEQUOIA_INTEGRATION_TODO.md](archive/RUST_SEQUOIA_INTEGRATION_TODO.md)
- this document defines implementation-facing rules, semantics, and validation for Rust / FFI work

### 1.2 What This Document Must Answer

For every active-roadmap Rust / FFI capability family, this document should answer:

- what behavior is in scope
- what behavior is explicitly deferred
- what semantic guarantees the Rust wrapper must provide
- what the FFI surface should look like at a high level
- which helper exports are required to make the API usable
- what the minimum Rust and Swift FFI validation must cover

### 1.3 Decision-Complete Rule

This document is the implementation reference, not a parking lot for unresolved interface decisions or a substitute for a final API contract.

- Active-roadmap families in this document must be specific enough that an implementer does not need to choose semantic meaning, safety boundaries, or validation scope on the fly.
- Some families in this document are still recorded at the semantic-baseline level rather than the exact type-name level.
- If a future option is intentionally left for later, it belongs in `Deferred / Out-of-Scope`, not in `Open Questions`.
- `Open Questions` are reserved for current blockers that still affect interface semantics, helper requirements, or validation commitments, not merely later naming freeze work.
- If implementation work needs to change a conclusion recorded here, update this reference first and then implement the code change.

## 2. Global Rust / FFI Rules

### 2.1 API Evolution

Default rule: exported `PgpEngine` expansion is additive only.

- Existing exported methods, records, and enums should remain source-compatible unless a later document explicitly approves a breaking change.
- New semantics should be introduced through parallel methods and parallel result records instead of mutating legacy result shapes in place.
- `Sources/PgpMobile/pgp_mobile.swift` is generated output and must only change through UniFFI regeneration.

### 2.2 Input Format Classes For OpenPGP Payload Inputs

Every new byte-oriented OpenPGP payload input that crosses the FFI boundary must be classified explicitly as one of:

- `binary-only`: the caller must pass raw OpenPGP bytes; any armor normalization is outside the method contract
- `armored-only`: the caller must pass ASCII-armored bytes; binary input is a precondition failure
- `dual-format`: the method must accept either raw binary or ASCII-armored bytes and normalize internally before semantic processing

Rules:

- Each capability family below must declare the format class for its byte-oriented OpenPGP payload inputs.
- Scalar and structured non-payload parameters such as passwords, fingerprints, and selectors are described by their own semantic rules and are not forced into this taxonomy.
- New families must not rely on implicit repository habits about armor acceptance.
- If a method inherits legacy parser behavior, the family must say so explicitly instead of using an informal shorthand term.

### 2.3 FFI Data Semantics

Use bytes when the exact OpenPGP packet payload is semantically significant.

- Certificates, revocations, detached signatures, message bytes, session-key related inputs, and User ID packet content use `Vec<u8>` / `Data`.
- Display-oriented strings may use `String`, but they must not be used as cryptographic identity selectors.
- User ID selectors for certification, binding verification, or User ID revocation must use raw User ID bytes, not display strings.

If an API requires parameters that the current export surface cannot reliably discover, the capability family must either:

- export a bounded helper for discovery, or
- explicitly defer Swift consumer adoption

### 2.4 Result Semantics Taxonomy

The following terms are fixed for this document:

- `crypto-only`: verifies cryptographic validity for the provided inputs only; does not imply policy acceptance, signer usability, or certificate health
- `graded message verification`: keeps decryption or verification success separate from signature interpretation and reports signature state as a graded result
- `policy-valid`: requires broader certificate or signer evaluation beyond raw cryptographic checking; this is outside the current certificate-signature verification scope

Result-shape rules:

- Family-local semantic detail should be expressed through new result records or status enums.
- `PgpError` remains reserved for parse failures, unmet preconditions, existing cross-family fatal failures, and other failures whose meaning is not scoped to one family-specific result record.

### 2.5 Parse Failure vs Cryptographic Invalid

Malformed input and cryptographic invalidity must remain distinct.

- Parse failure, shape mismatch, or unmet API preconditions return `Err(...)`.
- Successful parsing followed by failed cryptographic checking returns a family-specific result status or an already-established `PgpError`, depending on the capability family.

This boundary should remain aligned with the current `verify` / `decrypt` split:

- parse/setup failures generally map to `CorruptData` or `InvalidKeyData`
- established message-verification grading remains a separate layer

### 2.6 Sensitive Input Handling

Any new API that consumes secret certificate material must follow the same boundary discipline already used by existing secret-sensitive exports in [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs).

- Secret certificate inputs must be wrapped in `Zeroizing` at the FFI entrypoint.
- Password inputs must be converted into Sequoia `Password` as early as practical and should not remain in ordinary Rust-owned buffers longer than necessary.
- Any new result record that carries plaintext or signed content must explicitly document that the Swift caller must zeroize the returned `Data` after use.

### 2.7 Signer Fingerprint Semantics

Current legacy behavior returns the signer certificate's primary fingerprint, not the specific signing subkey fingerprint.

This behavior is observable today in:

- [`pgp-mobile/src/verify.rs`](../pgp-mobile/src/verify.rs)
- [`pgp-mobile/src/decrypt.rs`](../pgp-mobile/src/decrypt.rs)
- [`Sources/Services/SigningService.swift`](../Sources/Services/SigningService.swift)
- [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift)

Future Rust / FFI work must either:

- keep returning the signer certificate primary fingerprint and name the field accordingly, or
- add a separate explicit subkey-fingerprint field

It must not reuse an ambiguous field name while silently changing the meaning.

### 2.8 Error Model Evolution

CypherAir is sensitive to stable Rust/Swift error mapping.

- Family-specific semantic expansion should prefer new result/status types over new `PgpError` variants.
- A new `PgpError` variant is allowed only for cross-family fatal failure semantics that cannot be modeled as a family-local result status.
- Any new `PgpError` variant requires same-change updates to Rust mapping, UniFFI bindings, Swift error mapping, and tests that prove the Rust/Swift 1:1 contract still holds.
- This rule must stay aligned with [CODE_REVIEW.md](CODE_REVIEW.md) and [TESTING.md](TESTING.md).

### 2.9 Generated Binding Workflow

Any exported Rust surface change requires:

- UniFFI regeneration
- Rust test updates
- Swift FFI test updates
- review against existing Swift call sites that depend on legacy semantics

### 2.10 Minimum Validation

Every meaningful Rust / FFI expansion should preserve the repository's real review/build contract, not a reduced local subset.

At minimum:

- `cargo build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml`
- `cargo build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml`
- `cargo build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml`
- UniFFI regeneration when the public surface changes
- `cargo test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
- both Profile A and Profile B coverage where the capability applies
- FFI round-trip and error-shape coverage for any new public API or any new `PgpError` behavior

Nothing in this document lowers requirements from [CODE_REVIEW.md](CODE_REVIEW.md) or [TESTING.md](TESTING.md).

### 2.11 Naming Freeze Level

This document does not freeze public names by default.

- For families recorded as semantic baselines, this document should fix semantic categories, safety rules, and validation requirements without necessarily freezing exact exported method, record, or enum names.
- Public names may be finalized later in a more detailed implementation document, provided they remain compatible with the semantic commitments recorded here.
- If a family section intentionally freezes exact names, it should do so explicitly rather than by implication.

## 3. Capability Family Reference

Each family below intentionally records only implementation-reference material:

- purpose
- scope
- deferred behavior
- input format classification
- required semantics
- high-level FFI shape expectations
- helper/discovery needs
- minimum tests

### 3.1 Certificate Merge / Update

#### Purpose

Provide a bounded Rust / FFI wrapper for same-fingerprint public-certificate update absorption.

#### In-Scope

- existing public certificate + incoming public certificate/update
- same-fingerprint merge/update result
- absorption of new User IDs
- absorption of new subkeys
- absorption of public update material that `merge_public` can safely absorb

#### Deferred / Out-of-Scope

- generic packet-diff APIs
- generic policy engines
- secret-key merge behavior
- same-UID different-fingerprint product workflow
- broader Swift adoption beyond same-fingerprint contact import/update

#### Input Format Classification

- `existing_cert`: `binary-only`
- `incoming_cert_or_update`: `binary-only`

#### Required Semantics

- This family remains broader than a `merge_public`-only wrapper and is aligned with the companion roadmap/audit description of same-fingerprint public-certificate update absorption.
- The wrapper may use `merge_public` and bounded packet-update paths where needed to cover current-scope update categories.
- Both inputs must parse as same-fingerprint public certificates.
- Secret-bearing input is an unmet API precondition and returns `Err(InvalidKeyData)`.
- Fingerprint mismatch is an unmet API precondition and returns `Err(InvalidKeyData)`.
- The merge result must remain public-certificate-only.
- Current product behavior for same-fingerprint contact import is now:
  - absorb material public updates through the merge/update wrapper
  - preserve duplicate/no-op semantics for exact re-imports
- The public semantic contract must distinguish:
  - duplicate / no-op merge
  - material update
- If implementation uses stripped-public byte comparison internally, that is an implementation detail only. Callers must not treat the public merge outcome as a generic packet-level semantic diff.
- Merge tests must not depend on User ID or subkey ordering.

#### Expected FFI Surface Shape

- additive entry point for public-certificate merge/update
- merged public certificate bytes plus a semantic update/no-op indicator

#### Required Helper / Discovery Support

- none required for the baseline merge operation itself

#### Minimum Rust Tests

- revocation update merge
- expiry refresh merge
- absorb new User ID
- absorb new subkey
- exact duplicate no-op merge
- reject unrelated fingerprints
- reject secret-bearing input
- assertions based on content presence and state, not component order

#### Minimum Swift FFI Tests

- round-trip through the merge entry point
- verify the merged bytes still parse through existing metadata helpers
- verify duplicate merge preserves the public no-op outcome
- verify secret-bearing input rejection maps through UniFFI

#### Open Questions

- none currently

### 3.2 Revocation Construction

#### Purpose

Provide Rust / FFI coverage for revocation material that can be generated from existing secret certificates.

#### In-Scope

- key-level revocation generation from a secret certificate
- subkey-specific revocation material
- User ID-specific revocation material
- byte-oriented output suitable for later storage, export, or verification

#### Deferred / Out-of-Scope

- full Swift revocation-application flows
- configurable reason strings, notations, or hash selection
- view-level selector construction without a bounded service contract

#### Input Format Classification

- `secret_cert`: `binary-only`
- `subkey_fingerprint`: hex fingerprint string, matched case-insensitively after lowercase normalization
- `user_id_data`: `binary-only`

#### Required Semantics

- These APIs require secret certificate material.
- The current Swift production boundary is key-level only through `KeyManagementService`.
- Public-only certificate input must use one uniform family-wide rule:
  - return `Err(InvalidKeyData)` under a family-wide "secret certificate required" semantic rule
- User ID revocation uses raw User ID bytes as selector input.
- Default reason-code policy is fixed:
  - key revocation: `ReasonForRevocation::KeyRetired`
  - subkey revocation: `ReasonForRevocation::KeyRetired`
  - User ID revocation: `ReasonForRevocation::UIDRetired`
- Default reason text is the empty byte string for all three APIs.
- Outputs remain raw revocation-signature bytes.
- Selective subkey/User ID revocation should reach production Swift through additive `KeyManagementService` APIs after selector discovery exists; it should not be framed as a UI-only direct FFI call path.

#### Expected FFI Surface Shape

- separate additive exports for:
  - key revocation
  - subkey revocation
  - User ID revocation
- byte-oriented outputs

#### Required Helper / Discovery Support

- key-level revocation does not require new discovery helpers and is already integrated through `KeyManagementService`
- selective subkey/User ID adoption requires bounded selector discovery that exposes:
  - selectable subkey identifiers
  - selectable raw User ID bytes
- service integration should introduce selector-bearing Swift models or equivalent bounded discovery helpers before adding selective `KeyManagementService` APIs

#### Minimum Rust Tests

- Profile A and Profile B key revocation generation
- subkey revocation generation
- User ID revocation generation
- generated revocation validates against the source certificate
- mismatched-certificate validation fails
- public-only input rejection returns `InvalidKeyData` under the documented family rule
- selector-miss rejection returns `InvalidKeyData`
- no-usable-primary-signer rejection returns `InvalidKeyData`

#### Minimum Swift FFI Tests

- key revocation round-trip across UniFFI
- key revocation bytes validate through the existing `parse_revocation_cert` path
- subkey revocation smoke test across UniFFI
- User ID revocation smoke test across UniFFI
- selector-miss rejection for subkey/User ID exports maps through UniFFI

### 3.3 Password / SKESK Symmetric Messages

#### Purpose

Define the password-encrypted message family that is already present in `pgp-mobile` and wrapped by a dedicated Swift service.

#### In-Scope

- password-based message encryption
- password-based message decryption
- explicit handling of `SKESK`
- mixed `PKESK + SKESK` semantics for password-only decrypt entry points

#### Deferred / Out-of-Scope

- new UI / product exposure beyond the dedicated Swift service wrapper
- streaming password file APIs
- reusing `KeyProfile` as the password-message format selector

#### Input Format Classification

- `plaintext`: `binary-only`
- `encrypted_message` for password decrypt: `dual-format`

#### Required Semantics

- This family requires additive password-message encrypt/decrypt exports.
- The outward-facing contract must distinguish armored encryption output, binary encryption output, and password decrypt.
- Password message APIs use a dedicated password-message format concept that is independent from `KeyProfile`.
- Outgoing payload symmetric algorithm is fixed to `AES-256`.
- `seipdv1` output uses non-AEAD symmetric message construction with `AES-256`.
- `seipdv2` output explicitly pins `AEADAlgorithm::OCB` with `AES-256`.
- All SKESK packets in this family use a pinned baseline of Sequoia 2.2.0 `S2K::default()`, which is iterated+salted SHA-256 with the maximum encodable count.
- `SEIPDv2` in this family does not imply Argon2 or any stronger password KDF.
- Password decrypt accepts message bytes plus a password and evaluates only the `SKESK` path.
- Password decrypt must not fall back to recipient-key decrypt semantics.
- Mixed `PKESK + SKESK` messages are valid input for this family, but PKESK presence does not change password-only decrypt classification.
- The public decrypt contract must distinguish exactly three semantic categories:
  - decrypted
  - no `SKESK` present
  - password rejected after attempting the password path
- The decrypted category requires plaintext to be present.
- The two non-success categories require plaintext to be absent.
- `password_rejected` is only returned when:
  - at least one `SKESK` was present
  - the password path was attempted
  - no candidate session key completed payload decryption successfully
  - and no fatal payload authentication / integrity failure occurred
- If a candidate session key is tried and message authentication or integrity then fails, the API returns the existing fatal error instead of a family-local status:
  - `AeadAuthenticationFailed`
  - `IntegrityCheckFailed`
- Malformed input returns `Err(CorruptData)`.
- Unsupported algorithms return `Err(UnsupportedAlgorithm)`.
- `WrongPassphrase` is reserved for backup/import semantics and is not used by this family.
- Any returned plaintext must document the Swift-side zeroization requirement.

#### Expected FFI Surface Shape

- separate additive password encrypt / decrypt methods
- a dedicated password-message format type
- a password-family-specific decrypt result shape that can represent the three semantic categories above
- legacy recipient-key APIs remain separate

#### Required Helper / Discovery Support

- no new Rust-side discovery helper is required for the existing service boundary; the inputs are self-contained
- the current Swift service owner is `PasswordMessageService`
- the next adoption step is app-level route and screen-model ownership with an explicit UI-boundary plaintext handling contract

#### Minimum Rust Tests

- armored round-trip with `seipdv1`
- armored round-trip with `seipdv2`
- binary round-trip with `seipdv1`
- binary round-trip with `seipdv2`
- mixed `PKESK + SKESK` message behavior
- no-`SKESK` input classification
- `password_rejected` classification
- tampered ciphertext
- malformed input
- unsupported algorithm classification
- explicit assertion that outbound payload algorithm is `AES-256`
- explicit assertion that `seipdv2` pins `AEADAlgorithm::OCB`
- explicit assertion of the pinned SKESK `S2K::default()` baseline

#### Minimum Swift FFI Tests

- password encrypt / decrypt round-trip
- coverage for both `seipdv1` and `seipdv2`
- mixed-message smoke test
- no-`SKESK` smoke test
- `password_rejected` smoke test
- tamper/auth-failure smoke tests
- unsupported-algorithm smoke test

#### Open Questions

- none currently

### 3.4 Certification And Binding Verification

#### Purpose

Expose certificate-signature semantics needed for certification-related Rust completeness without overstating the trust or policy meaning of the result.

#### In-Scope

- direct-key signature verification
- User ID binding verification
- User ID certification material generation

#### Deferred / Out-of-Scope

- trust or web-of-trust semantics
- policy-valid certificate acceptance
- folding certificate-signature workflows into message-verification services

#### Input Format Classification

- `signature`: `binary-only`
- `target_cert`: `binary-only`
- `candidate_signers`: `binary-only`
- `signer_secret_cert` for certification generation: `binary-only`
- `user_id_data`: `binary-only`

#### Required Semantics

- Results in this family are `crypto-only`.
- The current Swift production boundary is none; planned service ownership belongs to a dedicated `CertificateSignatureService`.
- They must not imply signer validity under policy.
- This family requires additive exports for:
  - direct-key verification
  - User ID binding verification
  - User ID certification generation
- The certification kind concept must preserve the four OpenPGP certification signature types.
- Parse/type/precondition failure returns `Err(...)`.
- Cryptographic invalidity after successful parsing returns a family-local invalid result, not `Err(...)`.
- If no candidate signer can be selected for cryptographic checking, verification returns a family-local signer-missing result, not `Err(...)`.
- Signer output for new APIs is two-layered:
  - signer certificate primary fingerprint is returned only after successful crypto verification and only for the cryptographically confirmed signer
  - signing-subkey fingerprint is optional and returned only after successful crypto verification when the successful path used a non-primary signer key
  - `Invalid` and `SignerMissing` results return neither fingerprint
- Verification signer selection is fixed:
  - first, issuer-guided selection from the signature packet
  - second, fallback scan in caller-provided candidate order
- Fallback selection may inspect raw key identity and raw certification capability only.
- Fallback selection must not run `with_policy`, `alive()`, `revoked(false)`, or equivalent policy-like filtering.
- Certification generation signer selection is fixed:
  - prefer the primary key first
  - if the primary key is unavailable, use the first explicit certification-capable key in certificate order
- Certification-generation fallback selection must not run `with_policy`, `alive()`, `revoked(false)`, or equivalent policy-like filtering.
- Public-only signer input for certification generation returns `Err(InvalidKeyData)`.
- Secret signer certificate with no usable certification signer returns `Err(SigningFailed)`.
- Certification generation returns raw certification-signature bytes suitable for later insertion or verification.
- Service adoption for this family should introduce certificate-signature-specific Swift result types rather than reusing message verification result records.

#### Expected FFI Surface Shape

- dedicated additive verification methods for certificate-signature semantics
- dedicated additive certification-generation method for User ID certification
- family-specific result/status types separate from message verification records

#### Required Helper / Discovery Support

- current Swift models do not expose selector-bearing raw User ID data for bounded service ownership
- service integration should introduce selector-bearing discovery support for User ID-driven operations before or alongside `CertificateSignatureService`
- the planned service owner for this family is `CertificateSignatureService`

#### Minimum Rust Tests

- valid direct-key crypto verification
- invalid direct-key crypto verification
- valid User ID binding crypto verification
- invalid User ID binding crypto verification
- signer-missing direct-key verification
- signer-missing User ID binding verification
- issuer-guided success
- missing-issuer fallback success
- third-party certification generation followed by successful crypto verification
- signer selection prefers the primary key before explicit certification-capable fallbacks
- public-only certification input rejection

#### Minimum Swift FFI Tests

- certificate-signature verify smoke tests for both direct-key and User ID binding paths
- invalid-vs-`Err(...)` boundary smoke tests
- issuer-guided and fallback selection smoke tests
- User ID certification generation smoke test

#### Open Questions

- none currently

### 3.5 Richer Signature Results

#### Purpose

Preserve multi-signature information that is currently collapsed into one legacy status and one optional signer fingerprint.

#### In-Scope

- detailed cleartext verification
- detailed detached verification
- detailed decryption-side signature reporting
- detailed file verify / file decrypt signature reporting

#### Deferred / Out-of-Scope

- in-place mutation of existing legacy result records
- replacing current legacy Swift service methods in place

#### Input Format Classification

- `verify_cleartext_detailed` input uses the same accepted cleartext-signed message format as legacy `verify_cleartext`
- `verify_detached_detailed` uses:
  - `data`: `binary-only`
  - `signature`: same parser acceptance as legacy `verify_detached`
- `decrypt_detailed` input uses the same `dual-format` message acceptance as legacy `decrypt`
- `verify_detached_file_detailed` and `decrypt_file_detailed` use the same file-input acceptance as their corresponding legacy file APIs

#### Required Semantics

- Detailed APIs must be parallel additions; legacy APIs remain unchanged.
- The current Swift service boundary is partial:
  - `SigningService.verifyDetachedStreaming(...)` already uses `verify_detached_file_detailed`
  - the service immediately folds back to legacy fields
  - `DecryptionService` still uses legacy decrypt result types only
- Detailed method names are fixed to the corresponding legacy name plus `_detailed`.
- The additive detailed methods are:
  - `verify_cleartext_detailed`
  - `verify_detached_detailed`
  - `decrypt_detailed`
  - `verify_detached_file_detailed`
  - `decrypt_file_detailed`
- Detailed per-signature statuses use a dedicated enum:
  - `DetailedSignatureStatus::valid`
  - `DetailedSignatureStatus::unknown_signer`
  - `DetailedSignatureStatus::bad`
  - `DetailedSignatureStatus::expired`
- No detailed per-signature entry may represent `NotSigned`.
- The per-signature entry record preserves one entry per observed signature result in global parser order across all `MessageLayer::SignatureGroup` values and must not collapse repeated signers.
- `DetailedSignatureStatus::unknown_signer` entries return no signer fingerprint.
- Collector traversal and legacy folding are separate concerns:
  - the collector must keep recording every observed result even after the legacy winner is known
  - any "stop" behavior applies only to `legacy_status` / `legacy_signer_fingerprint` computation
- Every top-level detailed result record must contain:
  - `legacy_status`
  - `legacy_signer_fingerprint`
  - `signatures`
- In-memory detailed records also carry the same content/plaintext shape as the corresponding legacy API.
- File detailed records must be file-specific records and must not carry in-memory plaintext/content buffers.
- The representation for "the message was not signed at all" is fixed:
  - `signatures = []`
  - `legacy_status = NotSigned`
- `legacy_status` and `legacy_signer_fingerprint` must match exactly what the corresponding legacy API would return for the same input.
- The current legacy fold behavior is fixed and must remain unchanged:
  - legacy `verify_*` detailed wrappers must preserve the same winner/priority behavior as the existing non-detailed `verify_*` APIs
  - legacy `decrypt*` detailed wrappers must preserve the same fold outcome as the existing non-detailed decrypt APIs
  - compatibility is defined by observable result equality with the legacy APIs, not by reproducing a line-by-line internal algorithm in the reference text
- `verify_cleartext_detailed` must use the same parser acceptance and early-setup behavior as legacy `verify_cleartext`.
- `verify_cleartext_detailed` must not promise to always return content; early setup failure may still produce no content.
- `verify_detached_detailed` and `verify_detached_file_detailed` must preserve the same graded legacy outcomes as the existing detached verify APIs for:
  - `with_policy(...)` failure
  - payload verification failure after setup
  - when those paths observe no per-signature results, `signatures = []`
- File-based detailed verification and decrypt must inherit current file semantics:
  - progress callbacks
  - cancellation mapped to `OperationCancelled`
  - temp-file cleanup
  - AEAD hard-fail with no partial plaintext exposure
- `verify_detached_file_detailed` must surface progress cancellation as `Err(OperationCancelled)` instead of collapsing it into a graded `bad` result.
- Refactors in this family must preserve password-message behavior because password decrypt reuses the fixed-session-key decrypt path.
- Any detailed record carrying plaintext or signed content must document Swift-side zeroization requirements.
- Swift service adoption for this family should proceed through additive detailed result types in `SigningService` and `DecryptionService` while preserving current legacy service methods for compatibility.

#### Expected FFI Surface Shape

- parallel detailed methods
- dedicated detailed result records
- dedicated per-signature entry record

#### Required Helper / Discovery Support

- none beyond the detailed result records themselves
- service adoption requires dedicated Swift detailed result types instead of reusing the current legacy folded `SignatureVerification` surface

#### Minimum Rust Tests

- multiple signatures with different outcomes
- same signer repeated
- known signer + missing verification key mixture
- mixed expired + bad legacy-fold compatibility
- mixed expired + unknown-signer legacy-fold compatibility
- expired-signature outcome coverage
- empty-signature-array semantics
- compatibility tests proving `legacy_status` and `legacy_signer_fingerprint` match the legacy APIs exactly
- cleartext early-setup behavior with missing content
- file and in-memory detailed behavior stay aligned where semantically comparable
- file detailed cancel / cleanup / hard-fail inheritance

#### Minimum Swift FFI Tests

- detailed cleartext verification smoke test
- detailed detached verification smoke test
- detailed file verify smoke test
- detailed decrypt and file decrypt smoke tests
- expired-signature smoke test
- fixed multi-signer fixture coverage for UniFFI array/record mapping
- compatibility smoke tests proving legacy APIs still behave as before

## 4. Validation And Review Rules

### 4.1 Every Constraint Must Map To Validation

Implementation-reference statements in this document should only be added if they can later be checked through one or more of:

- Rust tests
- Swift FFI tests
- direct source review against the Rust wrapper
- direct source review against existing Swift dependencies

### 4.2 Sources To Re-Check Before Coding

Before implementing a capability family, re-check:

- upstream Sequoia docs and source for the specific APIs involved
- [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs)
- the family-specific Rust module that currently owns the closest legacy behavior
- existing Swift consumers that rely on legacy result semantics

At minimum, legacy signer and verification semantics should be checked against:

- [`pgp-mobile/src/verify.rs`](../pgp-mobile/src/verify.rs)
- [`pgp-mobile/src/decrypt.rs`](../pgp-mobile/src/decrypt.rs)
- [`pgp-mobile/src/streaming.rs`](../pgp-mobile/src/streaming.rs)
- [`Sources/Services/SigningService.swift`](../Sources/Services/SigningService.swift)
- [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift)

### 4.3 Review-Gate Alignment

This document must stay aligned with the repository's broader validation and review rules.

- [CODE_REVIEW.md](CODE_REVIEW.md) remains the checklist for build, binding, error-mapping, and cross-profile review expectations.
- [TESTING.md](TESTING.md) remains the source of truth for test-layer expectations, FFI round-trip coverage, and `PgpError` mapping coverage.
- This document may add family-specific minimum tests, but it must not define a lower bar than those documents.
- Every public semantic rule in family sections must map to a Rust minimum test and, when the API is public across UniFFI, to a Swift FFI minimum test.

### 4.4 Family Sections Are The Single Source Of Truth

- Family sections above are the implementation source of truth for their semantics.
- Only current blocker-level open questions should be summarized separately.
- Do not silently diverge in code from an existing rule in this document.

## 5. Naming To Freeze Later

This section tracks public naming that is intentionally deferred even though the surrounding semantic contracts are already fixed.

### 5.1 Certificate Merge / Update

- exact public naming for the merge result shape and semantic update/no-op indicator

### 5.2 Password / SKESK Symmetric Messages

- exact public naming for the password-message format type and decrypt-result type

### 5.3 Certification And Binding Verification

- exact public naming for certificate-signature result types and certification-kind types
