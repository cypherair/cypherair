# Rust Sequoia Integration Roadmap

> Status: Archived roadmap snapshot. Kept for historical execution context; no longer treated as the active roadmap.

> Purpose: Preserve the historical Sequoia expansion roadmap for `pgp-mobile`.
> Audience: Human developers, reviewers, and AI coding tools.

Primary objective:

> Improve `pgp-mobile` as a more complete Sequoia wrapper surface, even when immediate CypherAir service adoption is deferred.

This roadmap snapshot is derived from:

- [`SEQUOIA_CAPABILITY_AUDIT.md`](../SEQUOIA_CAPABILITY_AUDIT.md)
- [`SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md`](SEQUOIA_CAPABILITY_AUDIT_APPENDIX.md)

This document is intentionally narrower than the main audit:

- the audit is the **canonical inventory**
- this file is the archived roadmap snapshot from the Sequoia expansion phase
- the appendix records the archived `out-of-boundary surface` snapshot

## 1. Roadmap Framing

The workstreams below are listed in recommended execution order. They are grouped by capability family rather than by current product exposure.

Default rules:

- Rust wrapper coverage is the primary objective.
- FFI export is part of the roadmap whenever a wrapper family needs a stable boundary for later consumers.
- `service adoption deferred` is the default stance unless explicitly stated otherwise.
- If a workstream changes exported record shapes or public method shapes, the implementation must include:
  - UniFFI regeneration
  - FFI integration tests
  - a separate Swift migration/adaptation plan

## 2. Active Rust Roadmap

### 2.1 Certificate Merge/Update Family

Status: implemented

**Purpose**

Close the current-build omission around same-fingerprint public-certificate updates, while establishing a bounded certificate-update family instead of a one-off merge hook.

**Rust scope**

- Wrap Sequoia public-certificate merge/update flows around `merge_public` and packet-insertion paths.
- Support an initial bounded scope:
  - existing public certificate + incoming public-certificate update
  - same-fingerprint merge/update result
  - absorption of new User IDs
  - absorption of new subkeys
  - absorption of updated binding packets
- Return merged public-certificate bytes as the primary output.
- Do not design a generic packet-diff or policy engine in this workstream.

**FFI scope**

- Export a dedicated `PgpEngine` entry point for certificate merge/update.
- Keep the first FFI shape narrow:
  - input: existing certificate bytes
  - input: incoming certificate/update bytes
  - output: merged certificate bytes, plus any minimal metadata needed to distinguish success vs rejection
- Keep the first export independent from Swift-specific contact replacement policy.

**Service stance**

- Implemented in `ContactService` for same-fingerprint public certificate update absorption.
- Same-UID different-fingerprint replacement policy remains a separate product workflow.

**Minimum testing**

- Rust tests:
  - revocation update merge
  - expiry refresh merge
  - absorb new User ID
  - absorb new subkey
  - exact-duplicate no-op merge
  - reject unrelated fingerprints
- FFI tests:
  - merge round-trip across the boundary
  - merged certificate still parses into expected metadata

**Interface compatibility notes**

- Prefer additive methods and result records over overloading current import helpers.
- The first export should be small, but extensible enough that future update categories do not require breaking the initial FFI method shape.

### 2.2 Revocation Construction Family

**Purpose**

Restore revocation-construction coverage for imported secret certificates and provide a coherent family for finer-grained revocation material.

**Rust scope**

- Add a wrapper that generates a key revocation certificate from an existing secret certificate.
- Add selective revocation builders for:
  - subkey-specific revocation material
  - User ID-specific revocation material
- Return raw revocation bytes suitable for storage, export, validation, or later application.
- Do not couple this workstream to Swift persistence or UI/export policy.

**FFI scope**

- Export key-level revocation generation as a first-class `PgpEngine` method.
- Export subkey and User ID revocation builders as separate methods rather than mode flags on one overloaded API.
- Keep the output shape byte-oriented in the first iteration.

**Service stance**

- Default: `service adoption deferred`
- Current production-flow exception: imported-key revocation availability parity is the approved first downstream consumer
- Current delivery boundary:
  - key-level revocation generation is adopted in Swift for imported-key revocation export capability
  - subkey and User ID revocation builders remain Rust / FFI only until selector discovery helpers are added

**Minimum testing**

- Rust tests:
  - Profile A key revocation generation
  - Profile B key revocation generation
  - generated revocation validates against the source certificate
  - mismatched-certificate validation fails
  - valid subkey revocation generation
  - valid User ID revocation generation
- FFI tests:
  - generated revocation bytes cross the boundary cleanly
  - exported bytes validate through the existing revocation-validation path

**Interface compatibility notes**

- Keep the first exported outputs as raw revocation bytes instead of freezing a richer revocation record too early.
- Prefer separate methods for key, subkey, and User ID revocation so later semantic expansion does not overload one API surface.

### 2.3 Password/SKESK Symmetric-Message Family

Status: implemented

**Purpose**

Add the current-build symmetric-message surface to `pgp-mobile` even if CypherAir does not currently expose it as a product workflow.

**Rust scope**

- Add password-based encryption wrappers.
- Add password/SKESK decryption wrappers.
- Extend result and error mapping so `passwordRejected`, authentication/integrity failure, malformed/corrupt message, and unsupported-algorithm outcomes remain distinguishable without reusing `WrongPassphrase`.
- Handle `SKESK` packets explicitly instead of ignoring them.
- Keep this family separate from recipient-key workflows.

**FFI scope**

- Export separate `PgpEngine` methods for password encrypt/decrypt.
- Do not overload existing recipient-key methods with optional password arguments.
- Reuse existing decrypt result models only if the semantics remain identical; otherwise add dedicated records.

**Service stance**

- Delivered: dedicated `PasswordMessageService` adoption approved
- UI / product exposure remains deferred

**Minimum testing**

- Rust tests:
  - password encrypt/decrypt round-trip
  - deterministic `passwordRejected` coverage for `SKESK6` / `SEIPDv2`
  - tampered symmetric ciphertext
  - `noSkesk` classification
  - mixed `PKESK + SKESK` decrypt through the password path
  - compatibility coverage across Profile A / Profile B message handling where applicable
- FFI tests:
  - password encrypt/decrypt round-trip
  - deterministic `passwordRejected` mapping for `SKESK6` / `SEIPDv2`
  - `noSkesk` mapping
  - integrity/authentication failure mapping

**Interface compatibility notes**

- This workstream should be additive only.
- Do not blur symmetric-message APIs into the existing recipient-key APIs.

### 2.4 Certification And Binding Verification Family

Status: implemented in Rust, FFI, and tests; service adoption deferred

**Purpose**

Expose typed certificate-signature semantics needed for future certification features, trust-related tooling, and richer certificate validation.

**Rust scope**

- Wrap:
  - direct-key verification
  - User ID binding verification
  - third-party User ID certification verification through the same crypto-only User ID binding path
- Include the broader certification surface needed to create third-party certification material built on current-build Sequoia flows such as `UserID::certify`.
- Define compact certificate-signature result models distinct from message verification results.

**FFI scope**

- Export dedicated verification and certification methods on `PgpEngine`.
- Export dedicated certificate-signature result records separate from message `VerifyResult` and `DecryptResult`.
- Keep certificate-signature APIs isolated from current message-verification entry points.

**Service stance**

- Default: `service adoption deferred`
- Rust completeness remains the objective even without current CypherAir exposure

**Minimum testing**

- Rust tests:
  - valid direct-key verification
  - valid User ID binding verification
  - invalid-vs-`Err(...)` boundary coverage
  - signer-missing direct-key and User ID binding coverage
  - issuer-guided success and missing-issuer fallback success
  - third-party certification generation followed by successful verification
  - all four OpenPGP certification kinds preserved through generation and verification
  - primary-vs-subkey signer fingerprint contract coverage
- FFI tests:
  - direct-key and User ID binding result mapping across the boundary
  - invalid-input behavior across the boundary
  - certification-kind preservation across the boundary
  - primary / subkey / signer-missing fingerprint mapping across the boundary

**Interface compatibility notes**

- Do not extend current message-verification enums to carry certificate-signature semantics.
- Use new records and new methods for this family from the first export.

### 2.5 Richer Signature Result Family

Status: implemented in Rust, FFI, and tests; service adoption deferred

**Purpose**

Preserve Sequoia's multi-signature semantics instead of collapsing verification and decryption results to one status and one optional signer fingerprint.

**Rust scope**

- Define a multi-entry signature result model for:
  - cleartext verification
  - detached verification
  - decryption-side signature reporting
- Preserve per-signature status and signer identity where available.
- Remove last-result-wins semantics from the detailed path.

**FFI scope**

- Export parallel detailed methods and detailed result records rather than silently changing current result shapes in place.
- Keep the existing single-status methods available during the first rollout.

**Service stance**

- Default: `service adoption deferred`
- Rust completeness is delivered; production Swift adoption remains a later follow-up

**Minimum testing**

- Rust tests:
  - multi-signature all-valid case
  - mixed valid/invalid signatures
  - known signer + unknown signer combinations
  - cleartext and detached variants
  - decryption-side signed message coverage
- FFI tests:
  - multi-entry result mapping across the boundary
  - compatibility of legacy and detailed methods during the transition

**Interface compatibility notes**

- The first rollout must be additive.
- Do not break existing verify/decrypt record shapes in place; introduce parallel detailed entry points first.

## 3. Tracked In Audit, Not On The Active Rust Roadmap

The following `current-build omission` remains recorded in the audit, but is intentionally outside the current active roadmap:

1. **Generic packet/metadata introspection beyond recipient header parsing**
   - Keep it visible in the audit.
   - Do not expand it into a general packet-inspection API without a concrete consumer and a bounded schema.

## 4. Already Implemented In Rust, Still Waiting On Service Adoption

These are visible for handoff tracking, but they are **not** active roadmap items because no new wrapper work is required:

1. **Standalone revocation-signature validation**
   - Rust wrapper: complete
   - `PgpEngine` export: complete
   - current status: `service adoption deferred`

2. **Generic armor encode**
   - Rust wrapper: complete
   - `PgpEngine` export: complete
   - current status: `service adoption deferred`
