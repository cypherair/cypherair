# Apple Secure Enclave Custody POC Phase 3

> Status: macOS external-signing feasibility evidence for a proposal planning
> track.
> Date: 2026-05-24.
> Purpose: Record Phase 3 evidence that Secure Enclave P-256 ECDSA signatures
> can be converted into OpenPGP signatures accepted by Sequoia and CypherAir's
> verification/public-certificate helpers.
> Truth sources: [Product Model](APPLE_SECURE_ENCLAVE_CUSTODY.md),
> [Security Model](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY.md),
> [Reference](APPLE_SECURE_ENCLAVE_CUSTODY_REFERENCE.md),
> [Phase 1 Evidence](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE1.md), and
> [Phase 2 Evidence](APPLE_SECURE_ENCLAVE_CUSTODY_POC_PHASE2.md).
> Current-state note: This is POC evidence only. It does not describe shipped
> behavior, authorize production integration, or change CypherAir's current
> Secure Enclave wrapping architecture.

## 1. Phase 3 Role

Phase 3 validates external OpenPGP signing around a Secure Enclave P-256
signing key. It does not implement OpenPGP ECDH session-key recovery, decrypt,
app UI, production custody metadata, lifecycle UX, or current Profile A /
Profile B behavior changes.

The disposable probes live at:

- `poc/apple-secure-enclave-custody-probe/`
- `poc/apple-secure-enclave-custody-phase3/rust/`

The Xcode-signed `SecureEnclaveCustodyProbe` app target creates restricted
local state, generates permanent Secure Enclave `SecKey` rows, and signs
request-file digests through a Secure Enclave P-256 signing key. The Rust probe
implements a disposable Sequoia `crypto::Signer` adapter that writes
per-signature bridge request/response files, invokes the signed bridge,
converts fixed-width P-256 `r`/`s` values into OpenPGP ECDSA MPIs, and deletes
per-signature bridge files.

## 2. Tested Environment

- Machine: Apple Silicon Mac (`arm64`).
- OS: macOS 26.5 build 25F71.
- Swift: Apple Swift 6.3.2 (`swiftlang-6.3.2.1.108`), target
  `arm64-apple-macosx26.0`.
- Rust: `rustc 1.95.0`, `cargo 1.95.0`.
- Xcode: signed macOS `.app` target `SecureEnclaveCustodyProbe`, bundle id
  `com.chentianren.cypherair.poc.secureenclavecustody.probe`.
- Secure Enclave availability from the Swift bridge: `true`.
- Sequoia: `sequoia-openpgp 2.3.0` with the same OpenSSL feature family used
  by CypherAir's Rust crate.

Secure Enclave bridge runs executed outside the repository sandbox because the
signed app target creates Keychain rows and uses the app container for
request/state/response files. The POC itself is repository-local and does not
require network access at runtime.

## 3. Implementation Finding

The initial SwiftPM command-line bridge hit `errSecMissingEntitlement`
(`-34018`) when trying to generate Secure Enclave `SecKey` keys. That earlier
CryptoKit handle bridge is now superseded and is not final Phase 3 acceptance
evidence.

The follow-up implementation adds an isolated Xcode-signed macOS app-like POC
target, `SecureEnclaveCustodyProbe`. Xcode automatic signing produced an
embedded Mac Team provisioning profile and expanded the POC-only
`keychain-access-groups` entitlement into the team-prefixed access group. The
signed app target successfully created permanent Secure Enclave P-256 `SecKey`
private-key rows with `SecKeyCreateRandomKey` and
`kSecAttrTokenIDSecureEnclave`.

The bridge preserves the important Phase 3 security properties:

- digest bytes, hash algorithm, state path, and response path are carried in a
  private `0600` request file, not in `sign-digest` argv.
- state/request/response/result files are opened with no-follow semantics and
  require a `0700` parent directory plus `0600` file mode.
- each signing operation reloads the Secure Enclave `SecKey` row from Keychain
  and revalidates key type, key size, Secure Enclave token, role metadata, and
  signing public X9.63 bytes against state before signing.
- the signing public key must be distinct from the key-agreement public key.
- stdout reports only sanitized booleans, byte lengths, algorithm names, key
  versions, artifact counts, and error classes.

## 4. Results

### 4.1 Signed Secure Enclave Custody Probe

`SecureEnclaveCustodyProbe` results:

| Mode | Result | Evidence |
| --- | --- | --- |
| Xcode build/signing | pass | Built `SecureEnclaveCustodyProbe.app`; final entitlements contained app sandbox and the expected team-prefixed keychain access group. |
| `create-state` | pass | Generated distinct permanent Secure Enclave P-256 signing and key-agreement `SecKey` rows; wrote sensitive state as `0600` in a `0700` app-container directory. |
| `sign-digest` | pass | Signed a SHA-256 digest from a `0600` request file; wrote DER-to-fixed-width `r`/`s` response as `0600`; `r` and `s` were 32 bytes each. |
| `failure` | pass | Rejected unsupported hash, wrong digest length, corrupted state, substituted tags, public-key mismatch, missing row, non-SE row, wrong-size row, and symlinked request file. |
| `cleanup` | pass | Removed probe Keychain rows and 13 temporary capability files; the private temp directory had zero regular files afterward. |

State/request/response/result permissions were checked with `stat`; the
observed files were `0600` and owned by the current user. Per-signature Rust
bridge request and response files were also checked after SE runs; zero
per-call bridge files remained.

### 4.2 Software External Signer Control

The Rust `external-signer-control` mode generated software P-256 control
material and wrapped Sequoia's `crypto::Signer` trait. This proves the same
external-signer path without requiring Secure Enclave hardware.

| Candidate | Cert valid | CypherAir public parse | Recipient match | Detached | Cleartext | Binary message |
| --- | --- | --- | --- | --- | --- | --- |
| P-256 v4 software external signer | pass | pass | pass | pass | pass | pass |
| P-256 v6 software external signer | pass | pass | pass | pass | pass | pass |

Binding artifact sizes:

| Candidate | Direct-key sig | User ID binding | ECDH subkey binding |
| --- | ---: | ---: | ---: |
| P-256 v4 software external signer | 198 | 207 | 195 |
| P-256 v6 software external signer | 148 | 157 | 145 |

### 4.3 Secure Enclave Binding Signatures

The Rust `secure-enclave-bindings` mode used Secure Enclave public keys from
the signed probe state file and the SE-backed bridge signer to construct v4 and
v6 candidate public certificates with:

- direct-key metadata signature.
- User ID self-certification.
- ECDH transport-encryption subkey binding.

Results:

| Candidate | Cert valid | CypherAir public parse | Selector discovery | Recipient match | Public cert bytes | Bridge signatures |
| --- | --- | --- | --- | --- | ---: | ---: |
| P-256 v4 SE external signer | pass | pass | pass | pass | 840 | 3 |
| P-256 v6 SE external signer | pass | pass | pass | pass | 698 | 3 |

Interpretation: Secure Enclave P-256 ECDSA signatures can produce the binding
artifacts needed to make Phase 2's public-only candidate certificates usable by
Sequoia policy and CypherAir's public-certificate helper paths.

### 4.4 Secure Enclave Message Signatures

The Rust `message-signatures` mode built v4 and v6 SE-backed candidate
certificates, then produced and verified OpenPGP message-signature shapes.

| Candidate | Detached | Cleartext | Binary signed message | Hashes used |
| --- | --- | --- | --- | --- |
| P-256 v4 SE external signer | pass | pass | pass | SHA-384, SHA-512, SHA-256 |
| P-256 v6 SE external signer | pass | pass | pass | SHA-384, SHA-512, SHA-256 |

Observed signed artifact byte lengths:

| Candidate | Detached sig | Cleartext signed message | Binary signed message |
| --- | ---: | ---: | ---: |
| P-256 v4 SE external signer | 191 | 405 | 244 |
| P-256 v6 SE external signer | 150 | 348 | 268 |

CypherAir's detailed verification helpers verified detached and cleartext
outputs. Sequoia's streaming verifier verified the binary signed-message
coverage.

### 4.5 Failure Behavior

The Rust `failure` mode passed seven negative cases:

- wrong public-key binding.
- duplicate signing/agreement public keys.
- unsupported hash.
- wrong digest length.
- corrupted bridge response `r`/`s` shape.
- symlinked request file.
- missing bridge executable / bridge failure without software fallback.

The signed Swift bridge failure mode additionally rejected substituted Keychain
tags, public-key mismatch, corrupted state, missing Keychain rows, non-SE rows,
wrong-size rows, invalid hashes/digest lengths, and symlinked request files
before signing.

## 5. Security Findings

- Phase 3 proves the core OpenPGP signing compatibility question: Sequoia can
  compute OpenPGP digests, delegate P-256 ECDSA digest signing to a Secure
  Enclave-backed signer, and accept the returned `r`/`s` MPIs as valid OpenPGP
  signatures.
- The Phase 1 role-substitution risk remains real. Phase 3 mitigates it in the
  POC by reloading each `SecKey` row from Keychain and binding state role,
  application tag, expected X9.63 public key, key type, key size, Secure
  Enclave token, and distinct signing/agreement public keys before every
  signing operation.
- The request-file transport avoids digest/hash/response-path exposure in the
  signer argv. Request, response, result, and state files are still local
  capability material and must be treated as sensitive.
- The state file contains Keychain locator material, so it is more sensitive
  than a pure public fixture. The POC requires `0700`/`0600`, no-follow open
  checks, owner checks, and cleanup.
- The POC did not modify production app code, `Sources/Security/`,
  `pgp-mobile/src/`, production entitlements, or current Profile A/B behavior.
  It adds only an isolated POC target/scheme and POC-only entitlements.

## 6. Residual Questions

- Production integration still needs a design pass for app-owned custody
  metadata, lifecycle UX, and how the POC bridge responsibilities map into
  production modules.
- This phase does not prove OpenPGP ECDH session-key recovery, AES Key Wrap
  unwrap, fixed-session-key decrypt integration, decrypt hard-fail behavior,
  or sensitive-buffer zeroization for recovered session keys.
- v4 and v6 both remain viable after Phase 3. Both produced usable binding
  signatures and message signatures; the final production choice should wait
  for Phase 4 decrypt evidence and later product constraints.
- Manual authentication policy, cancellation, and lifecycle revocation
  artifacts remain outside this phase's implemented scope.

## 7. Commands Run

```bash
xcodebuild -list -project CypherAir.xcodeproj
xcodebuild build -project CypherAir.xcodeproj -scheme SecureEnclaveCustodyProbe -destination 'platform=macOS'
codesign -dvvv --entitlements - <built SecureEnclaveCustodyProbe.app>
<built SecureEnclaveCustodyProbe.app>/Contents/MacOS/SecureEnclaveCustodyProbe --mode create-state --out <app-container-private-dir>/state.json
<built SecureEnclaveCustodyProbe.app>/Contents/MacOS/SecureEnclaveCustodyProbe --mode sign-digest --request <app-container-private-dir>/sign-request.json
<built SecureEnclaveCustodyProbe.app>/Contents/MacOS/SecureEnclaveCustodyProbe --mode failure --request <app-container-private-dir>/failure-request.json
cargo test --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml
cargo run --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml -- --mode external-signer-control
cargo run --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml -- --mode secure-enclave-bindings --request <private-dir>/rust-request-bindings.json
cargo run --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml -- --mode message-signatures --request <private-dir>/rust-request-messages.json
cargo run --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml -- --mode failure --request <private-dir>/rust-request-failure.json
<built SecureEnclaveCustodyProbe.app>/Contents/MacOS/SecureEnclaveCustodyProbe --mode cleanup --request <app-container-private-dir>/cleanup-request.json
```

All commands passed. The SE-backed Rust modes used private request files under
the signed probe app container so the sandboxed bridge could read/write
capability files without exposing digest material in bridge argv.

## 8. Next Phase Entry Condition

Phase 3 provides enough evidence to enter Phase 4: SE-backed OpenPGP signing
compatibility is proven for v4 and v6 candidate certificates, direct/User ID/
subkey binding signatures, and detached/cleartext/binary message signatures.
Phase 4 must now prove ECDH session-key recovery and decrypt hard-fail behavior
without exposing partial plaintext.
