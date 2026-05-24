# Apple Secure Enclave Custody POC Phase 2

> Status: macOS OpenPGP public-certificate feasibility evidence for a proposal
> planning track.
> Date: 2026-05-24.
> Purpose: Record Phase 2 public-certificate feasibility results before
> Secure Enclave-backed OpenPGP signing or decrypt integration work begins.
> Truth sources: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md), and
> [Phase 1 Evidence](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE1.md).
> Current-state note: This is POC evidence only. It does not describe shipped
> behavior, authorize production integration, or change CypherAir's current
> Secure Enclave wrapping architecture.

## 1. Phase 2 Role

Phase 2 validates OpenPGP public-certificate feasibility around P-256 public
keys. It does not implement Secure Enclave-backed OpenPGP signatures, decrypt,
ECDH session-key recovery, app UI, production custody metadata, or current
Profile A / Profile B changes.

The disposable probes live at:

- `poc/apple-secure-enclave-custody-phase2/swift/`
- `poc/apple-secure-enclave-custody-phase2/rust/`

The Swift probe emits a temporary fixture containing only Secure Enclave P-256
public keys in X9.63 form. It does not print or write Secure Enclave key
handles, private key material, shared secrets, or stable OpenPGP fingerprints.

The Rust probe uses Sequoia 2.3.0 with the same OpenSSL feature family as
CypherAir and calls CypherAir's existing Rust public-certificate helpers for
public parsing, selector discovery, and recipient matching where a complete
software-control certificate is available.

## 2. Tested Environment

- Machine: Apple Silicon Mac (`arm64`).
- OS: macOS 26.5 build 25F71.
- Swift: Apple Swift 6.3.2 (`swiftlang-6.3.2.1.108`), target
  `arm64-apple-macosx26.0`.
- Rust: `rustc 1.95.0`, `cargo 1.95.0`.
- Secure Enclave availability from the Swift fixture probe: `true`.
- Fixture path used for local validation:
  `/private/tmp/cypherair-phase2-public-fixture.json`.

The fixture is temporary POC material and is not committed. It contains public
X9.63 bytes only; the probes did not print or write Secure Enclave key handles,
private material, shared secrets, raw certificates, or stable OpenPGP
fingerprints.

## 3. Results

### 3.1 Swift Secure Enclave Public Fixture

`Phase2SecureEnclavePublicKeyProbe --mode emit-public-fixture` generated two
fresh Secure Enclave P-256 keys:

- signing public key: X9.63 length 65 bytes.
- key-agreement public key: X9.63 length 65 bytes.
- `privateMaterialCaptured: false`.
- `handleBytesCaptured: false`.

This confirms Phase 2 can obtain only the public material needed for OpenPGP
public packet feasibility without depending on private scalar export or handle
printing.

### 3.2 Software P-256 Control Certificates

The Rust software-control mode generated minimal P-256 public certificate
candidates with:

- primary key: ECDSA P-256, certification/signing capable.
- subkey: distinct ECDH P-256, transport-encryption capable.
- User ID count: 1.
- transport-encryption subkey count: 1.

Results:

| Candidate | Sequoia/CypherAir parse | Recipient selection | Key version | CypherAir profile | Public cert bytes | Fingerprint hex length |
| --- | --- | --- | --- | --- | ---: | ---: |
| P-256 v4 software control | pass | pass | 4 | Universal | 836 | 40 |
| P-256 v6 software control | pass | pass | 6 | Advanced | 742 | 64 |

Revocation artifact lengths were also generated in the control group:

| Candidate | CertBuilder key revocation | Generated key revocation | Subkey revocation | User ID revocation |
| --- | ---: | ---: | ---: | ---: |
| P-256 v4 software control | 206 | 195 | 195 | 195 |
| P-256 v6 software control | 172 | 161 | 161 | 161 |

Interpretation: Sequoia 2.3.0 plus CypherAir's existing public-certificate
helpers can parse, validate, discover selectors, encrypt to, and match
recipients for complete v4 and v6 P-256 public certificate shapes when signing
material exists.

### 3.3 Secure Enclave Public-Only Candidates

The `secure-enclave-publics` mode used the Swift fixture's two Secure Enclave
public keys and built bare OpenPGP public packet candidates:

| Candidate | Packet bytes | Bare cert parsed | CypherAir public parse | Selector discovery | User IDs | Subkeys | Policy usable for transport encryption |
| --- | ---: | --- | --- | --- | ---: | ---: | --- |
| P-256 v4 SE publics | 240 | pass | pass | pass | 1 | 1 | no |
| P-256 v6 SE publics | 248 | pass | pass | pass | 1 | 1 | no |

The signing and key-agreement public keys were distinct, and both reported
65-byte X9.63 public-key encodings.

Interpretation: Secure Enclave public keys can be encoded into v4 and v6
P-256 OpenPGP public key packet shapes, and CypherAir's parser/selector
helpers can see the public components. The candidates are not policy-usable
transport-encryption recipients yet because Phase 2 intentionally does not
produce the required Secure Enclave-backed User ID self-certification and ECDH
subkey binding signatures.

### 3.4 Artifact Map

The artifact map mode recorded five required durable artifacts:

- User ID self-certification.
- ECDH subkey binding.
- Key revocation artifact.
- Subkey revocation artifact.
- User ID revocation artifact.

All five ultimately require signatures from the Secure Enclave-backed primary
P-256 ECDSA signing key. The first two are Phase 3 prerequisites for a usable
public certificate; revocation artifacts can be validated in Phase 3 or later
lifecycle follow-up work.

### 3.5 Mismatch and Capability Resolver

The disposable role/public-key binder rejected:

- swapped signing/agreement public keys.
- duplicate public keys.
- wrong signing role metadata.
- wrong key-agreement role metadata.

The capability resolver kept algorithm profile and custody separate:

- Profile A software keys remain selectable today.
- Profile B software keys remain selectable today.
- Apple Secure Enclave custody is not selectable for Profile A or Profile B
  because Secure Enclave is P-256-only.
- P-256 v4/v6 Secure Enclave custody candidates remain non-selectable until
  Phase 3 binding-signature evidence and later decrypt/session-key evidence
  exist.

## 4. Security Findings

- Software P-256 control certificates can prove Sequoia's v4/v6 P-256 public
  certificate support when private signing material is available.
- Secure Enclave public keys can prove public packet encoding and role/public
  key binding checks, but policy-usable recipient selection still requires real
  Secure Enclave signatures for User ID self-certification and ECDH subkey
  binding. Public parsing is not the same as a complete, usable certificate.
- Phase 1's role-substitution finding is carried forward: the Phase 2 binder
  rejects public-key swaps, duplicates, and role metadata mismatches before
  trusting Sequoia parsing or CryptoKit wrapper types.
- No production app code, `Sources/Security/`, `pgp-mobile/src/`, Xcode
  project files, entitlements, or current Profile A/B behavior were changed.

## 5. Residual Questions

- Phase 3 must prove the exact OpenPGP signature preimage/hash flow needed for
  User ID self-certification and ECDH subkey binding, with the signatures
  produced by the Secure Enclave P-256 signing key.
- Phase 3 should determine whether Sequoia's `Signer` trait, a Swift signing
  bridge, or another external-signature adapter is the least risky way to bind
  Secure Enclave signatures into OpenPGP packets.
- v4 and v6 remain viable candidates after Phase 2. The final production
  choice should wait for SE-backed binding signatures and later ECDH decrypt
  evidence.
- This phase does not prove OpenPGP message signing, ECDH session-key recovery,
  secret-key custody metadata, UI behavior, or lifecycle recovery semantics.

## 6. Commands Run

```bash
xcrun swift build --package-path poc/apple-secure-enclave-custody-phase2/swift
xcrun swift run --package-path poc/apple-secure-enclave-custody-phase2/swift Phase2SecureEnclavePublicKeyProbe -- --mode emit-public-fixture --out /private/tmp/cypherair-phase2-public-fixture.json
cargo test --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml
cargo run --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml -- --mode software-control
cargo run --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml -- --mode secure-enclave-publics --fixture /private/tmp/cypherair-phase2-public-fixture.json
cargo run --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml -- --mode artifact-map
cargo run --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml -- --mode mismatch
cargo run --manifest-path poc/apple-secure-enclave-custody-phase2/rust/Cargo.toml -- --mode capability-resolver
```

All commands passed.

## 7. Next Phase Entry Condition

Phase 2 should enter Phase 3 only if the evidence shows that P-256 public
certificate shapes are viable enough to justify Secure Enclave-backed OpenPGP
signature generation for User ID self-certification and subkey binding.
