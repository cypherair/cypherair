# Apple Secure Enclave Custody POC Phase 3

> Status: SecKey follow-up implemented; final Secure Enclave acceptance is
> blocked by local macOS provisioning for the entitled POC tool.
> Date: 2026-05-24.
> Purpose: Record Phase 3 evidence for Secure Enclave P-256 ECDSA digest
> signing as an external Sequoia signer, including the follow-up that replaces
> the earlier CryptoKit bridge with the intended Security-framework `SecKey`
> permanent-Keychain-row path.
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

- `poc/apple-secure-enclave-custody-phase3/swift/`
- `poc/apple-secure-enclave-custody-phase3/rust/`

The follow-up bridge source still lives under the Phase 3 POC directory, but is
now built by an isolated Xcode macOS command-line target named
`Phase3SecKeySigningBridge`. The target is not part of the production app
target or the main `CypherAir` scheme build action.

## 2. Superseded Evidence

The first Phase 3 commit proved Sequoia's external `Signer` path using a
CryptoKit Secure Enclave handle bridge after the unsigned SwiftPM command-line
environment returned `errSecMissingEntitlement` for
`SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)`.

That CryptoKit bridge evidence is now superseded. It remains useful only as
historical evidence that OpenPGP P-256 `r`/`s` signatures can verify. It is not
final Phase 3 acceptance evidence for the production-shaped SecKey permanent
Keychain row lifecycle.

## 3. Follow-up Implementation

The Swift bridge has been changed to the intended Security framework path:

- `create-state` uses `SecKeyCreateRandomKey` with
  `kSecAttrTokenIDSecureEnclave`, `kSecAttrKeyTypeECSECPrimeRandom`,
  `kSecAttrKeySizeInBits = 256`, `kSecAttrIsPermanent = true`,
  UUID-scoped `kSecAttrApplicationTag` / `kSecAttrLabel`, and
  `SecAccessControl(.privateKeyUsage)`.
- The state file stores only local capability locator metadata and public
  X9.63 bytes. Stdout does not print application tags, labels, state paths,
  digests, signatures, certificates, or stable fingerprints.
- `sign-digest --request <0600 json>` keeps digest/hash/response path out of
  argv.
- Each signing operation reloads the private `SecKey` from Keychain and
  revalidates key type, key size, Secure Enclave token, signing/agreement role
  binding, and `SecKeyCopyPublicKey` X9.63 equality before signing.
- The bridge uses `SecKeyIsAlgorithmSupported` and `SecKeyCreateSignature` with
  `ecdsaSignatureDigestX962SHA256`, `ecdsaSignatureDigestX962SHA384`, or
  `ecdsaSignatureDigestX962SHA512`, then converts DER X9.62 signatures to
  fixed-width P-256 `r`/`s`.
- `cleanup` deletes exact state tags and stale Phase 3 tag-prefix Keychain rows
  plus requested state/request/response/result files.

The Rust probe now accepts only the SecKey bridge state metadata:

- implementation must be `Security SecKey Secure Enclave P-256 permanent
  Keychain row`.
- `secKeyCreateRandomKeyAvailable` must be true.
- signing key type must be `SecKey.ECSECPrimeRandom.SecureEnclave.Signing`.
- key-agreement type must be
  `SecKey.ECSECPrimeRandom.SecureEnclave.KeyAgreement`.

## 4. Tested Environment

- Machine: Apple Silicon Mac (`arm64`).
- OS: macOS 26.5 build 25F71.
- Swift: Apple Swift 6.3.2 (`swiftlang-6.3.2.1.108`).
- Rust: `rustc 1.95.0`, `cargo 1.95.0`.
- Sequoia: `sequoia-openpgp 2.3.0` with the same OpenSSL feature family used
  by CypherAir's Rust crate.

The signed POC target was built with:

- target/scheme: `Phase3SecKeySigningBridge`.
- product type: macOS command-line tool.
- signing identity: Apple Development identity for team `7P9PPXP2SF`.
- hardened runtime: enabled by Xcode code-signing option.
- embedded entitlements inspected from the built executable:
  app sandbox, `com.apple.application-identifier`,
  `com.apple.developer.team-identifier`, `com.apple.security.get-task-allow`,
  and Keychain access group
  `7P9PPXP2SF.com.chentianren.cypherair.poc.phase3.seckeybridge`.

## 5. Results

### 5.1 Xcode-Signed SecKey Bridge

| Check | Result | Evidence |
| --- | --- | --- |
| Project discovery | pass | `xcodebuild -list` shows target and scheme `Phase3SecKeySigningBridge`. |
| Signed build, default macOS destination | pass | `xcodebuild build -scheme Phase3SecKeySigningBridge -destination 'platform=macOS'` succeeded; Xcode selected `arm64e`. |
| Signed build, explicit `arm64` | pass | `xcodebuild build -destination 'platform=macOS,arch=arm64'` succeeded. |
| Entitlements inspection | pass | `codesign -d --entitlements -` shows app identifier, team identifier, app sandbox, get-task-allow, and the POC Keychain access group. |
| Direct execution | blocked | AMFI denied launch before `main`; unified logs report `No matching profile found` for restricted entitlements. |
| `create-state` | not accepted | Not executed because the signed tool is blocked before `SecKeyCreateRandomKey`. |
| `sign-digest` / `failure` / `cleanup` | not accepted | Depend on a runnable SecKey state; no fallback evidence recorded. |

The blocker is local signing/provisioning, not a code fallback decision. The
machine has no local provisioning profile directory at
`~/Library/MobileDevice/Provisioning Profiles`, and unified logs show:

- `Disallowing Phase3SecKeySigningBridge because no eligible provisioning profiles found`.
- `No matching profile found`.
- `Code has restricted entitlements, but the validation of its code signature failed`.

Because the process is killed by AMFI before `main`, the POC cannot yet prove
SecKey permanent-row creation, per-signature Keychain reload/revalidation, or
Secure Enclave digest signing in this local environment.

### 5.2 Software External Signer Control

The Rust `external-signer-control` mode remains CI-safe and passed. It verifies
the same Sequoia external-signer trait shape without Secure Enclave hardware.

| Candidate | Cert valid | CypherAir public parse | Recipient match | Detached | Cleartext | Binary message |
| --- | --- | --- | --- | --- | --- | --- |
| P-256 v4 software external signer | pass | pass | pass | pass | pass | pass |
| P-256 v6 software external signer | pass | pass | pass | pass | pass | pass |

Binding artifact sizes:

| Candidate | Direct-key sig | User ID binding | ECDH subkey binding |
| --- | ---: | ---: | ---: |
| P-256 v4 software external signer | 198 | 207 | 195 |
| P-256 v6 software external signer | 148 | 157 | 145 |

### 5.3 Secure Enclave Binding And Message Signatures

The SE-backed Rust modes were intentionally not accepted in this follow-up
because the Xcode-signed SecKey bridge cannot launch without a matching
provisioning profile.

No software fallback, CryptoKit fallback, raw private-key fallback, or stale
Phase 3 CryptoKit evidence is counted as acceptance for:

- `secure-enclave-bindings`.
- `message-signatures`.
- SE-backed `failure`.

## 6. Security Findings

- The follow-up corrects the prior POC deviation by implementing the intended
  `SecKeyCreateRandomKey + kSecAttrTokenIDSecureEnclave + permanent Keychain
  private-key row` bridge.
- Request files remain the only digest transport; digest bytes, hash algorithm,
  state path, and response path are not placed in `sign-digest` argv.
- State/request/response/result files are treated as local capability material:
  `0700` parent directory, `0600` file mode, no-follow opens, owner checks, and
  cleanup paths are enforced in the bridge code.
- The bridge code revalidates the Keychain-loaded signing key against the state
  public X9.63 bytes and rejects role/tag substitution before each signature.
- Final SecKey feasibility is not proven until the signed tool can execute with
  a matching provisioning profile and create real Secure Enclave Keychain rows.
- Production app code, `Sources/Security/`, `pgp-mobile/src/`, production
  entitlements, and current Profile A/B behavior were not modified. The only
  project wiring change is the isolated POC target/scheme.

## 7. Commands Run

```bash
xcodebuild -list -project CypherAir.xcodeproj
xcodebuild build -project CypherAir.xcodeproj -scheme Phase3SecKeySigningBridge -destination 'platform=macOS' -derivedDataPath /private/tmp/cypherair-phase3-seckey-derived
codesign -d --entitlements - /private/tmp/cypherair-phase3-seckey-derived/Build/Products/Debug/Phase3SecKeySigningBridge
xcodebuild build -project CypherAir.xcodeproj -scheme Phase3SecKeySigningBridge -destination 'platform=macOS,arch=arm64' -derivedDataPath /private/tmp/cypherair-phase3-seckey-derived-arm64
codesign -dvvv --entitlements - /private/tmp/cypherair-phase3-seckey-derived-arm64/Build/Products/Debug/Phase3SecKeySigningBridge
/private/tmp/cypherair-phase3-seckey-derived-arm64/Build/Products/Debug/Phase3SecKeySigningBridge --mode create-state --out <private-dir>/state.json
/usr/bin/log show --style compact --last 5m --predicate "process == 'Phase3SecKeySigningBridge' OR eventMessage CONTAINS 'Phase3SecKeySigningBridge'"
cargo test --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml
cargo run --manifest-path poc/apple-secure-enclave-custody-phase3/rust/Cargo.toml -- --mode external-signer-control
```

SwiftPM syntax checking was attempted with explicit temp module caches, but
SwiftPM's internal sandboxing was blocked by the outer command sandbox. The
Xcode target build is the authoritative compile check for the follow-up.

## 8. Next Phase Entry Condition

The corrected SecKey implementation is in place, but Phase 3 final acceptance
is blocked until a matching macOS provisioning profile can run the entitled POC
tool. Once that is available, rerun:

- `create-state`.
- `sign-digest`.
- Swift bridge `failure`.
- Swift bridge `cleanup`.
- Rust `secure-enclave-bindings`.
- Rust `message-signatures`.
- Rust SE-backed `failure`.

Phase 4 should not count the SecKey signing path as proven until those commands
pass without CryptoKit or software fallback. Phase 4 still owns ECDH
session-key recovery and decrypt hard-fail behavior.
