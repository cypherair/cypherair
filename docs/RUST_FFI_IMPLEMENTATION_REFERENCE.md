# Rust / FFI Implementation Reference

> Purpose: Provide the implementation reference for future `pgp-mobile` and UniFFI surface expansion.
> Audience: Human developers, reviewers, and AI coding tools.
> Companion documents: [SEQUOIA_CAPABILITY_AUDIT](SEQUOIA_CAPABILITY_AUDIT.md) · [RUST_SEQUOIA_INTEGRATION_TODO](RUST_SEQUOIA_INTEGRATION_TODO.md) · [PRD](PRD.md) · [TDD](TDD.md) · [ARCHITECTURE](ARCHITECTURE.md) · [SECURITY](SECURITY.md) · [TESTING](TESTING.md)

This document does not replace the audit or the roadmap:

- [SEQUOIA_CAPABILITY_AUDIT.md](SEQUOIA_CAPABILITY_AUDIT.md) remains the canonical current-build inventory.
- [RUST_SEQUOIA_INTEGRATION_TODO.md](RUST_SEQUOIA_INTEGRATION_TODO.md) remains the active Rust roadmap.
- This document is the implementation reference for future Rust / FFI expansion work.

This document is intentionally narrower than a full design package:

- it covers the Rust layer, the UniFFI export surface, Rust tests, and Swift FFI tests
- it does not define Swift service adoption
- it records both fixed constraints and unresolved implementation questions

## 1. Purpose And Role

### 1.1 Role In The Documentation Stack

Use this document when planning or implementing new Rust / FFI capability in `pgp-mobile`.

Use the companion documents as follows:

- product goals and user-facing requirements live in [PRD.md](PRD.md)
- library choice, platform constraints, and existing FFI architecture live in [TDD.md](TDD.md)
- current implementation coverage lives in [SEQUOIA_CAPABILITY_AUDIT.md](SEQUOIA_CAPABILITY_AUDIT.md)
- workstream priority and recommended execution order live in [RUST_SEQUOIA_INTEGRATION_TODO.md](RUST_SEQUOIA_INTEGRATION_TODO.md)
- this document defines implementation-facing rules, semantics, and open questions for Rust / FFI work

### 1.2 What This Document Must Answer

For every future Rust / FFI capability family, this document should answer:

- what behavior is in scope
- what behavior is explicitly deferred
- what semantic guarantees the Rust wrapper must provide
- what the FFI surface should look like at a high level
- which helper exports are required to make the API usable
- what the minimum Rust and Swift FFI validation must cover

### 1.3 What This Document Must Not Do

This document must not:

- become another broad backlog
- duplicate the full capability audit
- define Swift service adoption rules
- hide unresolved interface questions behind over-specified pseudo-final APIs

## 2. Global Rust / FFI Rules

### 2.1 API Evolution

Default rule: exported `PgpEngine` expansion is additive only.

- Existing exported methods, records, and enums should remain source-compatible unless a later document explicitly approves a breaking change.
- New semantics should be introduced through parallel methods and parallel result records instead of mutating legacy result shapes in place.
- `Sources/PgpMobile/pgp_mobile.swift` is generated output and must only change through UniFFI regeneration.

### 2.2 FFI Data Semantics

Use bytes when the exact OpenPGP packet payload is semantically significant.

- Certificates, revocations, detached signatures, message bytes, session-key related inputs, and User ID packet content use `Vec<u8>` / `Data`.
- Display-oriented strings may use `String`, but they must not be used as cryptographic identity selectors.
- User ID selectors for certification, binding verification, or User ID revocation must use raw User ID bytes, not display strings.

If an API requires parameters that the current export surface cannot reliably discover, the capability family must either:

- export a bounded helper for discovery, or
- explicitly defer Swift consumer adoption

### 2.3 Result Semantics Taxonomy

The following terms are fixed for this document:

- `crypto-only`: verifies cryptographic validity for the provided inputs only; does not imply policy acceptance, signer usability, or certificate health
- `graded message verification`: keeps decryption or verification success separate from signature interpretation and reports signature state as a graded result
- `policy-valid`: requires broader certificate or signer evaluation beyond raw cryptographic checking; this is outside the current certificate-signature verification scope

Certificate-signature verification work in this document is limited to `crypto-only` semantics.

### 2.4 Parse Failure vs Cryptographic Invalid

Malformed input and cryptographic invalidity must remain distinct.

- Parse failure, shape mismatch, or unmet API preconditions return `Err(...)`
- Successful parsing followed by failed cryptographic checking returns a family-specific result status or an already-established `PgpError`, depending on the capability family

This boundary should remain aligned with the current `verify` / `decrypt` split:

- parse/setup failures generally map to `CorruptData` or `InvalidKeyData`
- established message-verification grading remains a separate layer

### 2.5 Sensitive Input Handling

Any new API that consumes secret certificate material must follow the same boundary discipline already used by existing secret-sensitive exports in [`pgp-mobile/src/lib.rs`](../pgp-mobile/src/lib.rs).

- Secret certificate inputs must be wrapped in `Zeroizing` at the FFI entrypoint.
- Password inputs must be converted into Sequoia `Password` as early as practical and should not remain in ordinary Rust-owned buffers longer than necessary.
- Any new result record that carries plaintext or signed content must explicitly document that the Swift caller must zeroize the returned `Data` after use.

### 2.6 Signer Fingerprint Semantics

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

### 2.7 Generated Binding Workflow

Any exported Rust surface change requires:

- UniFFI regeneration
- Rust test updates
- Swift FFI test updates
- review against existing Swift call sites that depend on legacy semantics

### 2.8 Minimum Validation

Every meaningful Rust / FFI expansion should preserve:

- `cargo test --manifest-path pgp-mobile/Cargo.toml`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`

Each capability family below adds its own minimum Rust and Swift FFI validation expectations.

## 3. Capability Family Reference

Each family below intentionally records only implementation-reference material:

- purpose
- scope
- required semantics
- high-level FFI shape expectations
- helper/discovery needs
- minimum tests
- open decisions

### 3.1 Certificate Merge / Update

#### Purpose

Provide a bounded public-certificate update path for same-fingerprint certificate refresh and merge behavior.

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
- Swift contact-service adoption

#### Required Semantics

- Version 1 baseline uses `merge_public` only.
- Version 1 must not automatically run `insert_packets` after `merge_public`.
- `insert_packets_merge` may only be considered later if tests prove that `merge_public` misses a current-scope update class.
- If such an insertion path is introduced later, the merge policy must be written explicitly; default `insert_packets` replacement semantics are not sufficient.
- The merge result must remain public-certificate-only.
- `changed` must not reuse upstream insertion booleans. It should instead represent whether the serialized stripped-public output differs from the serialized stripped-public baseline.
- Merge tests must not depend on User ID or subkey ordering.

#### Expected FFI Surface Shape

- dedicated additive entry point
- input: existing certificate bytes
- input: incoming certificate/update bytes
- output: merged public certificate bytes
- output: a narrowly defined `changed` flag

#### Required Helper / Discovery Support

- none required for the baseline merge operation itself

#### Minimum Rust Tests

- revocation update merge
- expiry refresh merge
- absorb new User ID
- absorb new subkey
- exact duplicate no-op merge
- reject unrelated fingerprints
- assertions based on content presence and state, not component order

#### Minimum Swift FFI Tests

- round-trip through the merge entry point
- verify the merged bytes still parse through existing metadata helpers
- verify duplicate merge preserves `changed = false`

#### Open Decisions

- whether later bounded `insert_packets_merge` support is needed after evidence-backed tests
- whether rejection metadata beyond ordinary errors is needed for first FFI export

### 3.2 Revocation Construction

#### Purpose

Provide Rust / FFI coverage for revocation material that can be generated from existing secret certificates.

#### In-Scope

- key-level revocation generation from a secret certificate
- subkey-specific revocation material
- User ID-specific revocation material
- byte-oriented output suitable for later storage, export, or verification

#### Deferred / Out-of-Scope

- Swift persistence and UI policy
- configurable reason strings, notations, or hash selection
- revocation application in Swift production flows

#### Required Semantics

- These APIs require secret certificate material.
- Public-only certificate input must use one uniform error rule across the family.
- User ID revocation should use raw User ID bytes as selector input.
- If custom reasons are not yet exposed, default reasons must be fixed in the implementation and documented:
  - key revocation: key-retired style default
  - subkey revocation: key-retired style default
  - User ID revocation: `UIDRetired`
- Outputs remain raw revocation bytes.

#### Expected FFI Surface Shape

- separate additive exports for:
  - key revocation
  - subkey revocation
  - User ID revocation
- byte-oriented outputs

#### Required Helper / Discovery Support

- reliable subkey fingerprint discovery helper, or explicit deferral of Swift consumer adoption
- reliable raw User ID bytes discovery helper, or explicit deferral of Swift consumer adoption

#### Minimum Rust Tests

- Profile A and Profile B key revocation generation
- subkey revocation generation
- User ID revocation generation
- generated revocation validates against the source certificate
- mismatched-certificate validation fails
- public-only input rejection follows the family-wide rule

#### Minimum Swift FFI Tests

- key revocation smoke test across UniFFI
- subkey revocation smoke test across UniFFI
- User ID revocation smoke test across UniFFI

#### Open Decisions

- the exact uniform error mapping for public-only input if it is not aligned with existing `InvalidKeyData` conventions
- whether discovery helpers belong in the same implementation phase or remain explicitly deferred

### 3.3 Password / SKESK Symmetric Messages

#### Purpose

Add the password-encrypted message surface that is currently absent from `pgp-mobile`.

#### In-Scope

- password-based message encryption
- password-based message decryption
- explicit handling of `SKESK`
- mixed `PKESK + SKESK` semantics documented for password-specific decrypt entry points

#### Deferred / Out-of-Scope

- Swift product adoption
- streaming password file APIs
- reusing `KeyProfile` as the password-message format selector

#### Required Semantics

- Password message APIs must use a message-format-specific enum, not `KeyProfile`.
- The selected message format and the selected password KDF must be documented independently.
- `SEIPDv2` must not be described as implying Argon2 or a stronger password KDF.
- Mixed `PKESK + SKESK` messages must have explicit classification rules.
- Password-specific decryption may classify `WrongPassphrase` only on a best-effort basis.
- The API must distinguish:
  - no `SKESK` present
  - `SKESK` present but password path failed
  - message authentication / integrity failure after a candidate session key is tried

#### Expected FFI Surface Shape

- separate additive password encrypt / decrypt methods
- password message format enum independent from certificate profile enums
- legacy recipient-key APIs remain separate

#### Required Helper / Discovery Support

- none required for baseline use; the inputs are self-contained

#### Minimum Rust Tests

- armored round-trip
- binary round-trip
- mixed `PKESK + SKESK` message behavior
- no-`SKESK` input classification
- best-effort wrong-password classification
- tampered ciphertext
- malformed input
- explicit assertion of the chosen password-message format behavior
- explicit assertion of the chosen S2K baseline

#### Minimum Swift FFI Tests

- password encrypt / decrypt round-trip
- mixed-message smoke test
- no-`SKESK` smoke test
- error-shape smoke tests for wrong-password and tamper paths

#### Open Decisions

- whether `SEIPDv2` should explicitly pin `AEADAlgorithm::OCB` or allow backend default with OCB-first behavior
- whether the first iteration should expose one decrypt entry point for password-only messages or document mixed-message handling through shared decrypt semantics
- whether to document the Sequoia-default SKESK S2K as the stable baseline or to pin a custom policy in the wrapper

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
- Swift service adoption

#### Required Semantics

- Results in this family are `crypto-only`.
- They must not imply signer validity under policy.
- Signer selection for verification should be issuer-guided first, then candidate fallback.
- Signer selection for certification should prefer the primary key, then explicit certification-capable keys.
- User ID selectors use raw bytes, not display strings.
- The result should use signer certificate primary fingerprint semantics unless a separate subkey field is added explicitly.

#### Expected FFI Surface Shape

- dedicated additive verification methods for certificate-signature semantics
- dedicated additive certification-generation method for User ID certification
- family-specific result record separate from message verification records

#### Required Helper / Discovery Support

- raw User ID discovery helper, or explicit Swift-adoption deferral

#### Minimum Rust Tests

- valid direct-key crypto verification
- invalid direct-key crypto verification
- valid User ID binding crypto verification
- invalid User ID binding crypto verification
- issuer-guided success
- missing-issuer fallback success
- third-party certification generation followed by successful crypto verification
- signer selection prefers the primary key before explicit certification-capable fallbacks

#### Minimum Swift FFI Tests

- certificate-signature verify smoke tests for both direct-key and User ID binding paths
- issuer-guided and fallback selection smoke tests
- User ID certification generation smoke test

#### Open Decisions

- the exact field names for family-specific result records
- whether the first result record should include only signer and target certificate primary fingerprints or also add optional explicit signer-subkey metadata

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
- Swift production adoption

#### Required Semantics

- Detailed APIs must be parallel additions; legacy APIs remain unchanged.
- Detailed per-signature statuses should use a dedicated status enum rather than reusing legacy `SignatureStatus` directly.
- No detailed entry should represent `NotSigned`.
- `verify_cleartext_detailed` must inherit the current wide parsing behavior of `verify_cleartext`.
- `verify_cleartext_detailed` must not promise to always return content; early setup failure may still produce no content.
- File-based detailed verification should use file-specific result records instead of reusing in-memory content-bearing records.
- Any detailed record carrying plaintext or signed content must document Swift-side zeroization requirements.

#### Expected FFI Surface Shape

- parallel detailed methods
- dedicated detailed result records
- dedicated per-signature entry record

#### Required Helper / Discovery Support

- none beyond the detailed result records themselves

#### Minimum Rust Tests

- multiple signatures with different outcomes
- same signer repeated
- known signer + missing verification key mixture
- empty-signature-array semantics
- legacy fold behavior remains unchanged
- file and in-memory detailed behavior stay aligned where semantically comparable

#### Minimum Swift FFI Tests

- detailed cleartext verification smoke test
- detailed detached verification smoke test
- detailed file verify smoke test
- detailed decrypt and file decrypt smoke tests
- compatibility smoke tests proving legacy APIs still behave as before

#### Open Decisions

- the exact dedicated per-signature status enum shape
- whether legacy method names should be mirrored exactly in detailed variants or whether new names should clarify the inherited wide parsing semantics

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
- [`Sources/Services/SigningService.swift`](../Sources/Services/SigningService.swift)
- [`Sources/Services/DecryptionService.swift`](../Sources/Services/DecryptionService.swift)

### 4.3 Reference-First Rule

If implementation work needs to change a conclusion recorded here, update this reference first.

Do not silently diverge in code from an existing rule in this document.

## 5. Decision Log And Open Questions

### 5.1 Confirmed Decisions

- Certificate merge version 1 baseline uses `merge_public` only.
- `insert_packets` is not the default follow-up to `merge_public`.
- Certification signer selection is primary-key-first, then explicit certification-capable fallback.
- Certificate-signature verification uses issuer-guided first-pass selection with candidate fallback.
- Certificate-signature verification is `crypto-only`.
- User ID cryptographic selectors use raw bytes, not display strings.
- Password-message APIs use a dedicated message-format enum, not `KeyProfile`.
- Password decrypt may classify `WrongPassphrase` only on a best-effort basis.
- Mixed `PKESK + SKESK` message handling must be documented explicitly.
- Legacy signer fingerprint behavior is signer certificate primary fingerprint semantics.
- Detailed plaintext/content-carrying results inherit explicit zeroization duties.
- New cryptographic selector APIs require either bounded discovery helpers or explicit adoption deferral.
- Merge `changed` must be defined independently from upstream insertion booleans.

### 5.2 Open Questions

- For password messages, should `SEIPDv2` explicitly pin OCB or rely on backend default with OCB-first behavior?
- What exact dedicated per-signature status enum should detailed APIs use?
- What exact uniform error variant should all secret-cert-required APIs use for public-only input if future evidence suggests that `InvalidKeyData` is insufficient?
- What is the smallest bounded discovery-helper export set needed to make `user_id_data` and `subkey_fingerprint` usable from Swift without growing a general packet-inspection API?
- Should detailed API names mirror legacy names exactly, or should wide parsing semantics be called out more explicitly in the new names?
