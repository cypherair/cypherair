# Rust Sequoia Integration TODO

> Purpose: Turn the Sequoia audit into a Rust-first execution backlog for `pgp-mobile`.
> Audience: Human developers, reviewers, and AI coding tools.

This document is derived from:

- [`SEQUOIA_CAPABILITY_AUDIT.md`](SEQUOIA_CAPABILITY_AUDIT.md)
- [`SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md`](SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md)

It is intentionally **Rust-first**:

- the main backlog focuses on Rust wrapper and Rust+FFI work
- Swift consumption is deferred unless a Rust item inherently needs an exported surface
- Rust-complete capabilities that still need product wiring are tracked separately as handoff items

## 1. Main Rust TODO Backlog

### P0 — Same-Fingerprint Certificate Update Absorption

**Problem**

CypherAir cannot currently absorb a new public-certificate update when the incoming cert has the same primary fingerprint as an already-stored local cert.

**Why it matters**

This blocks important public-certificate evolution paths, including:

- revocation updates
- refreshed expiry material
- accumulated third-party certifications or other packet updates

Without this capability, same-fingerprint imports are treated as duplicates instead of updates.

**Rust work needed**

- Add a Rust wrapper for public certificate update/merge flows based on Sequoia certificate merge and packet insertion APIs.
- Support the minimum update path needed for CypherAir:
  - existing public cert + incoming public cert update
  - same-fingerprint merge/update result
- Return a merged public certificate in binary form suitable for later FFI export.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **yes**, because the merge operation needs an explicit input/output surface

**Rust vs FFI vs Swift boundary**

- Rust: implement merge/update wrapper
- FFI: export a merge/update entry point
- Swift: deferred from this document, but expected later to consume the exported capability in contact-update flows

**Out of scope for this doc**

- Swift contact-storage policy
- UI behavior for showing “duplicate” vs “updated”
- contact replacement flows for different fingerprints

**Minimum test coverage**

- Rust tests for:
  - revocation update merge
  - expiry refresh merge
  - no-op merge for identical certs
  - reject mismatched fingerprints
- FFI tests for:
  - merge round-trip across the boundary
  - merged cert retains updated status metadata

### P0 — Revocation Regeneration / Export Parity For Imported Private Keys

**Problem**

Imported private keys do not regain revocation-export parity, because CypherAir currently stores an empty `revocationCert` for imported identities.

**Why it matters**

Keys generated outside the app lose a meaningful recovery/safety capability after import. This creates a capability gap between locally generated keys and imported keys.

**Rust work needed**

- Add a Rust wrapper that generates a key revocation signature from an existing secret certificate.
- Make the wrapper work for both supported profiles.
- Return revocation-cert bytes in a form that can later be stored or exported by upper layers.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **possibly**, depending on whether the capability is exposed as a standalone function or attached to an existing export flow

**Rust vs FFI vs Swift boundary**

- Rust: implement revocation generation from an existing secret cert
- FFI: export the capability
- Swift: deferred from this document, but expected later to use the exported capability during import or on-demand export flows

**Out of scope for this doc**

- Swift storage policy for imported revocation certs
- UI/export behavior
- migration of already-imported identities in persistent storage

**Minimum test coverage**

- Rust tests for:
  - Profile A revocation generation
  - Profile B revocation generation
  - generated revocation verifies against the source cert
  - mismatched-cert validation fails
- FFI tests for:
  - generated revocation survives the boundary
  - exported bytes validate through the existing revocation-validation path

### P1 — Password / SKESK Encrypt And Decrypt Support

**Problem**

CypherAir currently wraps only recipient-key message encryption and decryption. Password/SKESK message support is absent even though Sequoia supports it in the current build.

**Why it matters**

This leaves a real interoperability gap with OpenPGP symmetric-message workflows.

**Rust work needed**

- Add Rust wrappers for password-based encryption.
- Add Rust wrappers for password/SKESK decryption.
- Extend error mapping so wrong-password, auth-failure, and malformed-message behavior stay explicit.
- Keep this capability separate from the recipient-key API surface so it does not blur current message flows.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **likely**, because password-based decrypt inputs differ from current recipient-key decrypt inputs

**Rust vs FFI vs Swift boundary**

- Rust: implement password/SKESK entry points
- FFI: export them
- Swift: deferred from this document; product adoption can happen later

**Out of scope for this doc**

- Swift/UI entry points for password-based message workflows
- product messaging about whether symmetric-message support is officially exposed yet

**Minimum test coverage**

- Rust tests for:
  - password encrypt/decrypt round-trip
  - wrong password
  - tampered symmetric ciphertext
  - Profile A / Profile B compatibility where relevant to message format handling
- FFI tests for:
  - password encrypt/decrypt round-trip
  - error mapping for wrong password

### P1 — Third-Party Certification And Binding Verification

**Problem**

CypherAir does not currently wrap Sequoia’s certificate-signature verification surfaces for direct-key, User ID binding, and related third-party certification checks.

**Why it matters**

This is foundational for any future certification or trust-oriented feature. Without Rust support, later higher-level work has no safe typed surface to build on.

**Rust work needed**

- Add Rust wrappers for certificate-signature verification surfaces that are relevant to:
  - direct-key verification
  - User ID binding verification
  - related third-party certification checks
- Define a compact result model appropriate for Rust/FFI use.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **yes**, because current exported verification results are message-oriented, not certificate-signature-oriented

**Rust vs FFI vs Swift boundary**

- Rust: implement certificate-signature verification capability
- FFI: export typed verification results
- Swift: deferred from this document

**Out of scope for this doc**

- certification UX
- trust model or trust graph
- any Swift-side contact-certification workflows

**Minimum test coverage**

- Rust tests for:
  - valid direct-key / binding verification
  - invalid signature
  - mismatched cert/signature inputs
- FFI tests for:
  - result mapping across the boundary
  - invalid-case error/result behavior

### P1 — Certificate-Structure Update Wrappers

**Problem**

CypherAir does not currently wrap broader certificate-structure update operations such as merging new certificate material, new User IDs, new subkeys, and updated bindings.

**Why it matters**

Same-fingerprint update absorption is the immediate gap, but the underlying capability family is larger. A narrow one-off fix may create a dead-end API if broader update handling is needed soon after.

**Rust work needed**

- Introduce a certificate-update wrapper family that can support:
  - merge/update of same-fingerprint public certificate material
  - new User IDs
  - new subkeys
  - updated binding packets
- Keep the initial exported surface minimal, but design it so future update categories can fit without breaking the FFI shape.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **yes**

**Rust vs FFI vs Swift boundary**

- Rust: define the update/merge capability family
- FFI: export the initial surface
- Swift: deferred, except where future contact update flows need it

**Out of scope for this doc**

- full Swift-side update policy
- migration of stored contact files
- UI prompts for update classes

**Minimum test coverage**

- Rust tests for:
  - same-fingerprint merge success
  - new-UID absorption
  - new-subkey absorption
  - reject unrelated certificates
- FFI tests for:
  - update output round-trip
  - metadata after merge remains parseable

### P1 — Subkey / User ID Revocation Builders

**Problem**

CypherAir does not wrap Sequoia’s selective revocation builders for subkeys and individual User IDs.

**Why it matters**

This is part of the broader revocation capability family. If CypherAir later needs finer-grained revocation flows, the Rust layer currently has no starting point.

**Rust work needed**

- Add Rust wrappers for:
  - subkey-specific revocation generation
  - User ID-specific revocation generation
- Keep the outputs compatible with the certificate update/merge path so generated revocations can later be applied or transported cleanly.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **possibly**, depending on whether outputs are raw revocation signatures or richer typed results

**Rust vs FFI vs Swift boundary**

- Rust: implement selective revocation generation
- FFI: export it
- Swift: deferred from this document

**Out of scope for this doc**

- UI for selecting a subkey or User ID to revoke
- product policy around when fine-grained revocation is exposed

**Minimum test coverage**

- Rust tests for:
  - valid subkey revocation generation
  - valid User ID revocation generation
  - revocation verification/application path
- FFI tests for:
  - generated revocation bytes survive the boundary

### P1 — Richer Multi-Signature Result Model

**Problem**

Current verification and decrypt-result surfaces collapse potentially multiple signatures into a single `status` and optional single signer fingerprint.

**Why it matters**

This loses Sequoia’s richer signature-group semantics and constrains future message-verification fidelity.

**Rust work needed**

- Design a richer Rust-side verification result model that can represent multiple signatures.
- Update message verification wrappers to emit a multi-signature-aware result.
- Keep backward-compatibility risk explicit, because exported result records may need to change.

**Rust surface affected**

- Rust wrapper: **required**
- `PgpEngine` export: **required**
- result/type changes: **definitely yes**

**Rust vs FFI vs Swift boundary**

- Rust: define the richer result shape
- FFI: export the new type(s)
- Swift: deferred from this document, but any consumer will later need adaptation

**Out of scope for this doc**

- Swift UI presentation of multiple signatures
- backward-compatibility migration strategy in Swift call sites

**Minimum test coverage**

- Rust tests for:
  - multi-signature valid/invalid combinations
  - known + unknown signer combinations
  - detached and cleartext variants where applicable
- FFI tests for:
  - multi-entry result mapping across the boundary

## 2. Rust Complete, Swift Handoff

These items should remain visible, but they are **not active Rust TODO items**.

### Standalone Revocation Validation

**Current state**

Rust already wraps and exports standalone revocation validation.

**Why it is here**

The unresolved work is primarily Swift/product consumption, not Rust capability creation.

**Rust status**

- Rust wrapper: complete
- `PgpEngine` export: complete

**Deferred Swift work**

- decide whether production services should consume the existing export
- wire it into any revocation-import or validation flows later

### Generic Armor Encode

**Current state**

Rust already wraps and exports generic armor encoding.

**Why it is here**

Production Swift code currently uses `dearmor` and `armorPublicKey`, so the remaining question is product consumption rather than Rust implementation.

**Rust status**

- Rust wrapper: complete
- `PgpEngine` export: complete

**Deferred Swift work**

- only needed if a future product flow requires generic armor by kind

## 3. Experimental / Optional Future Work

These are intentionally **not** part of the main Rust backlog.

### Runtime Policy Customization

**Current state**

CypherAir fixes Sequoia usage around `StandardPolicy` and product-default validation behavior.

**Why it is experimental**

Exposing runtime policy control would broaden the lower-level API surface and shift product/security decisions upward.

**Current decision**

Track as an optional future capability, not as committed Rust TODO.

### Algorithm / Backend Selection Knobs

**Current state**

CypherAir fixes backend and algorithm-policy choices around the current product/security model.

**Why it is experimental**

Exposing these knobs would expand configurability in ways that are not currently aligned with the product model.

**Current decision**

Track as an optional future capability, not as committed Rust TODO.

## 4. Notes For Future Execution

- This document is intentionally **Rust-first**. Swift work should be planned separately after the Rust layer is settled.
- If a Rust item changes exported records or method shapes, the follow-up work must include:
  - UniFFI regeneration
  - FFI integration tests
  - a separate Swift adaptation plan
- The audit documents remain the source of truth for capability mapping and rationale. This document is the execution backlog derived from them.
