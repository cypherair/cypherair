# Technical Design Document (TDD)

> **Version:** v4.4
> **Companion to:** [PRD](PRD.md) v4.4
> **Audience:** Developers, Security Auditors

## 1. OpenPGP Library: Sequoia PGP

### 1.1 Selection

sequoia-openpgp 2.2.0. Rust. RFC 9580 + RFC 4880 complete. Licensed under LGPL-2.0-or-later.

Current stable app-build release ordering and the shared source/compliance asset contract are documented in [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md) and [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md). This section records the current technical library selection, not a final legal conclusion about distribution compatibility.

| Library | Lang | RFC 9580 | Argon2id | iOS | Decision |
|---------|------|----------|----------|-----|----------|
| Sequoia 2.2.0 | Rust | Full | Native | Excellent | **SELECTED** |
| OpenPGP.js | JS | Partial | Yes | Uncertain | Rejected |
| PGPainless | Java/Kotlin | Partial | Bouncy Castle | KMP bridge | Rejected |
| rPGP | Rust | No | No | Excellent | Rejected |
| Swift native | Swift | N/A | Manual | Native | Rejected |

### 1.2 Backend: crypto-openssl (Vendored)

```toml
sequoia-openpgp = { version = "2.2", default-features = false, features = [
    "crypto-openssl", "compression-deflate"
    # compression-deflate: enabled for READING incoming compressed messages only.
    # Outgoing messages MUST NOT use compression. Bzip2 excluded (extra C dependency).
] }
```

**Why crypto-openssl:**

| Criterion | crypto-openssl | crypto-rust |
|-----------|---------------|-------------|
| Maturity | Battle-tested | Experimental |
| Constant-time | Guaranteed | Not guaranteed |
| Opt-in flags | None | `allow-experimental` + `allow-variable-time` |
| C deps | Yes (vendorable) | None |
| PQC support | Yes | No |

**Summary:** Battle-tested, constant-time operations, no experimental opt-in flags, PQC-ready.

**Vendored build:** `openssl-src` compiles OpenSSL from source for target arch. Zero system dependency. Build needs: Xcode C compiler + perl + make. First build ~3–5 min.

### 1.3 Dual Profile Configuration

The App uses Sequoia's `Profile` and `CipherSuite` enums to implement two encryption profiles:

| Setting | Profile A (Universal) | Profile B (Advanced) |
|---------|----------------------|---------------------|
| `Profile` | `Profile::RFC4880` | `Profile::RFC9580` |
| `CipherSuite` | `CipherSuite::Cv25519` | `CipherSuite::Cv448` |
| Key version | v4 | v6 |
| Signing algo | Ed25519 (legacy EdDSA) | Ed448 |
| Encryption algo | X25519 (legacy ECDH) | X448 |
| Hash | SHA-512 (accepts SHA-256 for legacy verification) | SHA-512 |
| Symmetric | AES-256 | AES-256 |
| Message format | SEIPDv1 (MDC) | SEIPDv2 (AEAD OCB) |
| S2K (export) | Iterated+Salted (mode 3) | Argon2id (512 MB / p=4 / ~3s) |
| Compression | DEFLATE (read-only) | DEFLATE (read-only) |
| Security level | ~128 bit | ~224 bit |

*Compression note: `compression-deflate` is enabled for reading compatibility with other OpenPGP implementations that compress messages. Outgoing messages are never compressed. Bzip2 is excluded (extra C dependency).*

**Key generation (Rust wrapper):**

```rust
// Profile A
let (cert, rev) = CertBuilder::general_purpose(Some(user_id))
    .set_cipher_suite(CipherSuite::Cv25519)
    .set_profile(Profile::RFC4880)?
    .set_features(Features::empty().set_seipdv1())?
    .generate()?;

// Profile B
let (cert, rev) = CertBuilder::general_purpose(Some(user_id))
    .set_cipher_suite(CipherSuite::Cv448)
    .set_profile(Profile::RFC9580)?
    .generate()?;
```

**Profile A `set_features` rationale:** Sequoia 2.2.0 defaults to advertising SEIPDv2 support in the Features subpacket (because the library itself supports it). For Profile A (GnuPG-compatible), we must explicitly set `Features::empty().set_seipdv1()` so that other implementations send SEIPDv1 messages to this key. Without this, a GnuPG sender would see SEIPDv2 advertised and attempt to send an AEAD-encrypted message, which GnuPG cannot produce correctly — resulting in interoperability failure. `set_profile(Profile::RFC4880)` is also set explicitly rather than relying on defaults, for clarity and forward-compatibility.

### 1.4 Encryption Format Auto-Selection

When encrypting, the message format is determined by the recipient's key version, not the sender's profile:

- **All recipients have v4 keys** → SEIPDv1 (MDC). No AEAD.
- **All recipients have v6 keys** → SEIPDv2 (AEAD OCB, with GCM as secondary preference).
- **Mixed v4 + v6 recipients** → SEIPDv1 (lowest common denominator).
- **Encrypt-to-self** adds the sender's own key. If sender has v6 and recipient has v4, the mixed rule applies → SEIPDv1.

Sequoia handles this automatically when the recipient certificates are passed to the encryption API. The Rust wrapper does not need to implement format selection logic manually.

### 1.5 AEAD Preference Subpacket

Profile B keys advertise their AEAD preferences in the key's self-signature:

```
Preferred AEAD Ciphersuites: [AES-256 + OCB, AES-256 + GCM, AES-128 + OCB]
```

This tells other RFC 9580 implementations which AEAD combinations the key holder can decrypt. OCB first (maximum interoperability), GCM second (for implementations that prefer it, e.g., OpenPGP.js), AES-128+OCB implicitly appended per RFC 9580.

Profile A keys do not include this subpacket (v4 keys do not use AEAD).

### 1.6 Decryption Compatibility

The App decrypts all supported formats regardless of the user's own key profile:

- SEIPDv1 (MDC) — from GnuPG and Profile A senders
- SEIPDv2 with OCB — from Sequoia and other RFC 9580 senders
- SEIPDv2 with GCM — from OpenPGP.js senders
- Legacy SEIPD (no MDC) — rejected per security policy (hard-fail)

### 1.7 Cross-Compilation

Targets: `aarch64-apple-ios` (device) + `aarch64-apple-ios-sim` (Apple Silicon sim) + `aarch64-apple-darwin` (macOS Apple Silicon) + `aarch64-apple-visionos` (visionOS device) + `aarch64-apple-visionos-sim` (visionOS simulator). Tier 2 in Rust. `getrandom` uses `SecRandomCopyBytes` on Apple platforms. LTO and strip are **disabled** in the release profile (`lto = false`, `strip = "none"`) — enabling them causes linker failures with vendored OpenSSL. Binary size is managed via `codegen-units = 1` and Xcode dead code elimination. Estimated app binary contribution: ~6–8 MB.

The current release pipeline includes native visionOS support. `build-xcframework.sh` builds and validates the visionOS device and simulator archives, packages all Apple slices into `PgpMobile.xcframework`, and the Xcode project links that XCFramework. The native app path is probed with `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS' CODE_SIGNING_ALLOWED=NO`.

To keep vendored OpenSSL reproducible across the current Apple `arm64e`
build chain, `pgp-mobile/Cargo.toml` patches `openssl-src` through
`[patch.crates-io]` to the CypherAir fork
`https://github.com/cypherair/openssl-src-rs` on branch
`carry/apple-arm64e-openssl-fork`. That branch is expected to track the
CypherAir OpenSSL fork branch `carry/apple-arm64e-targets`. `Cargo.toml`
intentionally tracks the branch so local branch status/docs updates are not
left behind; `pgp-mobile/Cargo.lock` records the resolved git commit for
repeatable builds.

The current deployment baseline for the app targets is `iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+`.

---

## 2. Rust-to-Swift FFI: UniFFI

### 2.1 Architecture

Three-layer bridge: `pgp-mobile` Rust wrapper → UniFFI C scaffolding → generated Swift bindings.

1. **pgp-mobile wrapper crate:** Wraps Sequoia. `Vec<u8>`/`String` API. UniFFI proc-macros.
2. **Generated C scaffolding:** `pgp_mobileFFI.h`. RustBuffer serialization.
3. **Generated Swift wrapper:** `pgp_mobile.swift`. snake_case → camelCase. Arc lifecycle.

### 2.2 Wrapper Crate API

```toml
[lib]
crate-type = ["lib", "staticlib"]
```

The wrapper exposes profile-aware operations. Accept/return `Vec<u8>` for crypto material. Expose operations, not Sequoia internals. `Send + Sync`.

```rust
#[uniffi::export]
impl PgpEngine {
    fn generate_key(&self, user_id: String, profile: KeyProfile) -> Result<GeneratedKey, PgpError>;
    fn encrypt(&self, plaintext: Vec<u8>, recipients: Vec<Vec<u8>>, 
               signing_key: Option<Vec<u8>>, encrypt_to_self: Option<Vec<u8>>) -> Result<Vec<u8>, PgpError>;
    fn decrypt(&self, ciphertext: Vec<u8>, secret_keys: Vec<Vec<u8>>) -> Result<DecryptResult, PgpError>;
    fn export_secret_key(&self, key: Vec<u8>, passphrase: String, profile: KeyProfile) -> Result<Vec<u8>, PgpError>;
    // ...
}

#[derive(uniffi::Enum)]
pub enum KeyProfile { Universal, Advanced }
```

- `generate_key`: selects CipherSuite and Profile based on `KeyProfile` enum.
- `encrypt`: auto-selects message format from recipient certificates (no profile parameter needed).
- `export_secret_key`: uses Iterated+Salted S2K for Universal, Argon2id for Advanced.
- All crypto material as `Vec<u8>`. Zeroized before returning.

### 2.3 Type Mapping

| Rust | Swift | Transfer |
|------|-------|----------|
| `Vec<u8>` | `Data` | Copy (RustBuffer) |
| `String` | `String` | Copy (UTF-8) |
| `Result<T, E>` | `throws` | Error enum |
| `uniffi::Object` | `class` | Arc pointer |
| `uniffi::Record` | `struct` | Copy by value |
| `Option<T>` | `T?` | Optional |
| `Vec<T>` | `[T]` | Array |

See also [ARCHITECTURE.md](ARCHITECTURE.md) Section 2 for extended type mapping details.

### 2.4 Error Handling

`#[derive(uniffi::Error)]` enum maps to Swift throwing functions. Convert `anyhow::Error` to typed `PgpError`. Each `PgpError` variant maps 1:1 to a Swift enum case.

### 2.5 Build Pipeline

1. `cargo +stable build --release --target aarch64-apple-ios` / `aarch64-apple-ios-sim` / `aarch64-apple-darwin` / `aarch64-apple-visionos` / `aarch64-apple-visionos-sim` refreshes ordinary stable `arm64` archives when you only need target-specific Rust outputs
2. `./build-xcframework.sh --release` refreshes stable `arm64` and patched `arm64e` release archives, generates UniFFI Swift bindings and headers from an `arm64e-apple-darwin` host dylib, validates host-dylib cleanup, produces the packaged `PgpMobile.xcframework` output, and writes `PgpMobile.arm64e-build-manifest.json`
3. The current Xcode project links `PgpMobile.xcframework` and imports the generated headers through `bindings/module.modulemap`
4. Local Swift / FFI validation runs through `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`

The current `openssl-src` override for the Apple `arm64e` build chain must
remain explicit: use the checked-in CypherAir `openssl-src-rs` git branch plus
the checked-in `Cargo.lock`, not a machine-local `path` dependency. Release
automation records the resolved `openssl-src-rs` commit and OpenSSL submodule
commit in `PgpMobile.arm64e-build-manifest.json`. If the carry chain changes in
the future, update `pgp-mobile/Cargo.toml`, `pgp-mobile/Cargo.lock`, and the
local arm64e status documentation together.

See also [CLAUDE.md](../CLAUDE.md) Build Commands for the full pipeline with exact commands.

### 2.6 Memory

- Objects: `Arc<T>`, dropped via Swift deinit callback. Bytes: copied via RustBuffer. Sensitive data: `zeroize` (Rust) + `resetBytes` (Swift).

### 2.7 Precedents

Bitwarden (UniFFI), Firefox iOS (UniFFI XCFramework), Signal (cbindgen), Delta Chat (rPGP iOS).

### 2.8 Durable Rust / FFI Contract Rules

- **API evolution is additive by default.** New semantics should land as parallel methods, result records, or enums instead of mutating legacy verify/decrypt record shapes in place.
- **Payload input classes must stay explicit.** Byte-oriented OpenPGP payload inputs are classified as `binary-only`, `armored-only`, or `dual-format`; new APIs must document which class they accept instead of relying on implicit parser behavior.
- **Cryptographic selectors use bytes, not display strings.** Selector-bearing User ID operations use raw `userIdData + occurrenceIndex`, and cryptographically significant payloads stay as `Vec<u8>` / `Data`.
- **Discovery helpers are part of the contract when needed.** If a downstream Swift service cannot safely discover required selectors or metadata from the current exported surface, the Rust / FFI boundary must grow a bounded helper rather than pushing string inference into Swift callers.
- **Parse/setup failure stays distinct from cryptographic invalidity.** Parse, type, and precondition failures return `Err(PgpError)`. Successful parsing followed by crypto failure should stay in family-specific result or graded-status types.
- **`PgpError` remains the cross-family fatal boundary.** UniFFI-visible error changes must preserve the Rust/Swift 1:1 mapping and should be reserved for fatal semantics that cannot be modeled as a family-local result.
- **Signer fingerprint meaning must stay explicit.** Legacy verify/decrypt APIs return the signer certificate primary fingerprint, not the signing subkey fingerprint. New APIs must either preserve that meaning or add a separate explicit subkey field.
- **Any UniFFI-visible surface change is a multi-layer change.** Regenerate bindings, update Swift service call sites, refresh `PgpMobile.xcframework`, and rerun Rust plus Swift / FFI validation together.
- **Plaintext-bearing results still inherit Swift-side zeroization expectations.** When FFI results carry plaintext or signed content, the service and app layers must continue to zeroize temporary `Data` buffers after use.

### 2.9 Current FFI Capability Families

| Family | Rust / FFI role | Swift service owner | Current app owner | Current state |
|--------|------------------|---------------------|-------------------|---------------|
| Certificate Merge / Update | Same-fingerprint public-certificate update absorption | `ContactService` | `ContactImportWorkflow`, `AddContactView`, `IncomingURLImportCoordinator`, URL import flow in `CypherAirApp` | Shipped |
| Revocation Construction | Key-level and selective revocation construction | `KeyManagementService` | `KeyDetailView`, `SelectiveRevocationView`, `SelectiveRevocationScreenModel` | Shipped; selective revocation remains export-on-demand and does not extend persisted key-level revocation state |
| Password / SKESK Symmetric Messages | Additive password encrypt/decrypt methods and result types | `PasswordMessageService` | None | Service-only; no shipped app route or screen-model owner |
| Certification And Binding Verification | Direct-key verify, User ID binding verify, and User ID certification generation | `CertificateSignatureService` | `ContactDetailView`, `ContactCertificateSignaturesView`, `ContactCertificateSignaturesScreenModel` | Shipped; workflow is crypto-only and does not mutate trust state automatically |
| Richer Signature Results | Additive detailed verify/decrypt APIs | `SigningService` and `DecryptionService` | `VerifyView`, `VerifyScreenModel`, `DecryptView`, `DecryptScreenModel`, shared `DetailedSignatureSectionView` | Shipped; current UI keeps the summary-first bridge while also rendering detailed entries |

All current app-surface workflows continue to call Swift service owners rather than `PgpEngine` directly.

---

## 3. Secure Enclave Key Wrapping

### 3.1 Constraint

SE supports P-256 only. Ed25519/X25519/Ed448/X448 keys all require indirect wrapping. The wrapping scheme is identical for both profiles — the SE protects the raw private key bytes regardless of the key algorithm.

### 3.2 Wrapping Flow

1. Generate `SecureEnclave.P256.KeyAgreement.PrivateKey()` with access control flags.
2. Self-ECDH (SE private key × own public key, computed inside SE hardware).
3. HKDF: `deriveKey(inputKeyMaterial: sharedSecret, salt: randomSalt, info: "CypherAir-SE-Wrap-v1:" + hexFingerprint, outputByteCount: 32)`.
4. `AES.GCM.seal(privateKeyBytes)`.
5. Store: SE key `dataRepresentation` + salt + sealed box in Keychain. **Confirm success.**
6. Zeroize raw key bytes + symmetric key **after storage confirmed.**

### 3.3 Unwrapping Flow

1. Retrieve SE key blob, salt, and sealed box from Keychain.
2. Reconstruct SE key from `dataRepresentation` (triggers device authentication — Face ID / Touch ID, with or without passcode fallback depending on auth mode).
3. Re-derive symmetric key (self-ECDH inside SE + HKDF with stored salt and same info string).
4. `AES.GCM.open()` → Ed25519/X25519/Ed448/X448 private key in application memory.
5. Perform PGP operation.
6. Zeroize private key bytes and symmetric key immediately.

See also [SECURITY.md](SECURITY.md) Section 3 for the full unwrapping security analysis.

### 3.4 Access Control (Dual Mode)

| Mode | Flags | Behavior |
|------|-------|----------|
| Standard (default) | `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]` | Face ID / Touch ID with passcode fallback. Equivalent to `deviceOwnerAuthentication`. |
| High Security | `[.privateKeyUsage, .biometryAny]` | Face ID / Touch ID only. No passcode fallback. If biometrics unavailable, private key is inaccessible. |

**Mode switching:** When the user changes authentication mode in Settings, the App must re-wrap all SE-protected private keys with the new access control flags:

1. Unwrap each private key using the current SE key (requires current auth).
2. Delete the current SE wrapping key from Keychain.
3. Generate a new SE wrapping key with the new access control flags.
4. Re-wrap each private key with the new SE key.
5. Store the new wrapped blobs in Keychain.

*This operation requires the user to authenticate once (under the current mode) and is atomic: if any step fails, the original keys remain intact.* Crash recovery uses the post-unlock `private-key-control.recoveryJournal`. See [SECURITY.md](SECURITY.md) Section 4.

### 3.5 Keychain Layout

Per identity (fingerprint = lowercase hex, no spaces):
```
com.cypherair.v1.se-key.<fingerprint>
com.cypherair.v1.salt.<fingerprint>
com.cypherair.v1.sealed-key.<fingerprint>
com.cypherair.v1.metadata.<fingerprint>
```

**Keychain item configuration:**

| Item | kSecClass | kSecAttrAccessible | Access Control |
|------|-----------|-------------------|----------------|
| SE key `dataRepresentation` | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | Per auth mode |
| Salt | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |
| Encrypted private key | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |
| Legacy key metadata migration rows (PGPKeyIdentity JSON) | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None (no SE auth); migration/cleanup source before verified ProtectedData `key-metadata` domain creation |
| ProtectedData SE device-binding key | Keychain-backed SE key representation | `WhenPasscodeSetThisDeviceOnly` | `.privateKeyUsage` only; no Face ID flags |

ProtectedData uses this device-binding key only to open the app-data
root-secret envelope after the existing Keychain / `LAContext` gate succeeds.
It is not part of the private-key bundle model and must fail closed if missing.

### 3.6 Security Properties

- Keychain extraction without SE hardware → encrypted blob useless.
- SE `dataRepresentation` bound to SoC UID (fused at manufacturing).
- Ed25519/X25519/Ed448/X448 key exists in app memory briefly during use (inherent tradeoff).
- SE ECDH adds ~2–5ms. Imperceptible.

### 3.7 Key Loss & Recovery

SE keys destroyed by: device erase, iCloud restore, backup restore. App detects → prompts restore from backup → generates new SE key → re-wraps.

---

## 4. Argon2id Configuration (Profile B Only)

| Parameter | Value | RFC 9580 Encoding | Rationale |
|-----------|-------|-------------------|-----------|
| Memory | 512 MB | encoded_m = 19 | ~6% of 8 GB min RAM |
| Parallelism | 4 | p = 4 | 128 MB per lane |
| Time | Fixed at 3 passes (~3s target on contemporary hardware) | t = 3 | Stable, explicit export profile |

**Not used by Profile A.** Profile A uses Iterated+Salted S2K (mode 3) for key export, which is universally supported by GnuPG.

### iOS Memory Safety Guard

Before Argon2id derivation (importing passphrase-protected Profile B keys):
1. Parse S2K specifier. 2. Calculate `2^encoded_m` KiB. 3. Query `os_proc_available_memory()`. 4. If > 75% of available: refuse with error.

Jetsam kills apps exceeding memory limits. This guard prevents Argon2id from triggering a Jetsam termination.

---

## 5. QR Code

Format: `cypherair://import/v1/<base64url binary key, no padding>`. Works for both v4 and v6 keys — the binary OpenPGP format is self-describing.

~250–350 bytes binary → ~340–470 chars base64url → <600 chars total. Single QR at Level M.

Generate: `CIQRCodeGenerator`. Decode from photo: PHPicker + CoreImage `CIDetector` (QR code type).

---

## 6. Storage Architecture

```
Keychain default account: SE key + salt + sealed-key + pending private-key recovery rows
Keychain metadata account: legacy `PGPKeyIdentity` migration/cleanup source
Keychain protected-data row: shared app-data root secret
/Application Support/ProtectedData/: registry, private-key-control domain, key-metadata domain, protected-settings domain, domain bootstrap metadata
/Documents/: contacts/ (public keys + `contact-metadata.json`), legacy self-test/ cleanup source only
/Library/Preferences/ (UserDefaults):
  com.cypherair.preference.authMode              → legacy source removed after private-key-control migration
  com.cypherair.preference.appSessionAuthenticationPolicy → boot auth profile
  com.cypherair.preference.gracePeriod           → legacy cleanup-only after protected-settings schema v2 migration
  com.cypherair.preference.encryptToSelf         → legacy cleanup-only after protected-settings schema v2 migration
  com.cypherair.preference.clipboardNotice       → legacy cleanup-only after protected-settings migration
  com.cypherair.preference.onboardingComplete    → legacy cleanup-only after protected-settings schema v2 migration
  com.cypherair.preference.guidedTutorialCompletedVersion → legacy cleanup-only after protected-settings schema v2 migration
  com.cypherair.preference.colorTheme            → legacy cleanup-only after protected-settings schema v2 migration
  com.cypherair.internal.rewrapInProgress        → legacy source removed after private-key-control migration
  com.cypherair.internal.rewrapTargetMode        → legacy source removed after private-key-control migration
  com.cypherair.internal.modifyExpiryInProgress  → legacy source removed after private-key-control migration
  com.cypherair.internal.modifyExpiryFingerprint → legacy source removed after private-key-control migration
  com.cypherair.tutorial.sandbox.plist           → fixed tutorial sandbox defaults, cleared on container creation/startup/reset
  com.cypherair.tutorial.<UUID>.plist            → legacy tutorial sandbox defaults, fallback-cleaned on startup/reset if orphaned
/tmp/decrypted/op-<UUID>/: per-operation decrypted file previews
/tmp/streaming/op-<UUID>/: per-operation streaming encryption outputs
/tmp/export-<UUID>-<filename>: temporary fileExporter handoff files
/tmp/CypherAirGuidedTutorial-<UUID>/: tutorial contacts sandbox
```

Protected app-data planning covers all CypherAir-owned local data, not only preferences. Current permanent exceptions are limited to the app-session boot authentication profile, private-key material rows protected by Keychain / Secure Enclave, ProtectedData framework bootstrap metadata, test-only or legacy-cleanup state, short-lived temporary files with cleanup requirements, and user-exported files after they leave the app-controlled sandbox. Private-key control state now lives in the post-unlock `private-key-control` ProtectedData domain, and key metadata now lives in the post-unlock `key-metadata` ProtectedData domain. The canonical per-surface classification, status, and migration-readiness table lives in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md).

### 6.1 ProtectedData Current Contract

ProtectedData is the current shared framework for app-owned local state that opens only after app privacy authentication. It is separate from the private-key material domain and does not store OpenPGP secret key bytes.

Current framework contracts:

- `ProtectedDataRegistry` is the plaintext bootstrap authority for committed domain membership, shared-resource lifecycle state, root-secret envelope minimum version, and a single pending create/delete mutation.
- Pre-auth startup may classify the registry and per-domain bootstrap metadata, but must not load the shared app-data root secret, unwrap any domain master key, or open protected payload generations.
- The shared app-data root secret is stored in the Keychain as a v2 `CAPDSEV2` envelope and is loaded with an authenticated `LAContext` handoff. The ProtectedData-only Secure Enclave device-binding key silently unwraps that envelope under the same app-session gate.
- `ProtectedDomainKeyManager` derives a wrapping root key from the raw root secret, zeroizes the raw root secret, then unwraps per-domain 256-bit domain master keys from wrapped-DMK records.
- Protected domain files live under `Application Support/ProtectedData/`; registry, bootstrap metadata, scratch writes, and wrapped-DMK files verify explicit file protection where available.
- Relock clears the wrapping root key, unwrapped DMKs, and registered domain-local decrypted state. A relock participant failure latches runtime-only `restartRequired`.

Current production domains:

- `private-key-control`: `settings.authMode` plus rewrap / modify-expiry recovery journal state.
- `key-metadata`: schema v1 `PGPKeyIdentity` list, migrated from legacy metadata Keychain rows after app unlock.
- `protected-settings`: schema v2 stores `clipboardNotice` plus the ordinary-settings snapshot for grace period, onboarding completion, color theme, encrypt-to-self, and guided tutorial completion.
- `protected-framework-sentinel`: framework-owned schema/purpose marker only, used to exercise multi-domain lifecycle behavior.

Migration and exception rules:

- Legacy `authMode`, rewrap, and modify-expiry `UserDefaults` keys are migration sources only after verified `private-key-control` creation/open.
- Legacy key metadata rows in the dedicated metadata account and older default-account rows are migration/cleanup sources only after verified `key-metadata` readability.
- Permanent and pending private-key bundles remain in the existing Keychain / Secure Enclave private-key material domain.
- Self-test reports are in-memory export-only data, and legacy `Documents/self-test/` is cleanup-only on startup and local-data reset.
- Phase 7 temporary artifacts are centralized through `AppTemporaryArtifactStore`: streaming/decrypted outputs use one `op-<UUID>` owner directory per operation, export handoff files use atomic complete-protection writes, tutorial sandbox directories use verified complete protection, and startup/reset cleanup removes `decrypted`, `streaming`, `export-*`, `CypherAirGuidedTutorial-*`, fixed `com.cypherair.tutorial.sandbox` defaults, and orphaned legacy `com.cypherair.tutorial.<UUID>.plist` suites. Contacts remain outside the completed Phase 1-7 scope and are pending unblocked Phase 8 protected-domain implementation.
- Future protected-domain migrations must preserve readable source state until the protected destination is created/opened and verified through the normal post-auth path.
- After cutover, legacy sources are cleanup/quarantine only and must not become fallback sources of truth.
- Protected-after-unlock settings must not add pre-unlock shadow copies; `appSessionAuthenticationPolicy` is the only ordinary settings boot-authentication exception.
- Documentation updates for storage or migration changes belong in `PERSISTED_STATE_INVENTORY.md`, `ARCHITECTURE.md`, `SECURITY.md`, `TDD.md`, `TESTING.md`, and affected Contacts docs when Contacts is involved.

---

## 7. UI Framework

SwiftUI (iOS 26.4+). UIKit: UIActivityViewController, UIDocumentPickerViewController, PHPickerViewController, beginBackgroundTask.

---

## 8. Memory Integrity Enforcement (MIE)

### 8.1 Overview

Memory Integrity Enforcement is Apple's hardware-level memory safety system, built right into Apple hardware and software in all models of iPhone 17 and iPhone Air (A19/A19 Pro chips). It combines Enhanced Memory Tagging Extension (EMTE), secure typed memory allocators, and Tag Confidentiality Enforcement to detect and block memory corruption (buffer overflows, use-after-free) in real time.

### 8.2 Why MIE Matters for CypherAir

- **Vendored OpenSSL is C code:** Memory corruption vulnerabilities are the primary attack vector against C cryptographic libraries. MIE provides hardware-level defense against exploitation of any undiscovered OpenSSL bugs.
- **Security-sensitive app:** Apple explicitly recommends MIE for apps that are "likely entry points for attackers — such as social networks, messaging apps, or any other app where a specific user can be targeted." CypherAir fits this description.
- **Zero performance cost:** Apple has optimized MIE to maintain device performance. The protection is always on and invisible to users on supported hardware.

### 8.3 Enablement

In Xcode 26:

1. Open Signing & Capabilities for the app target.
2. Add Capability → Enhanced Security.
3. Enable Hardware Memory Tagging.

Xcode manages Enhanced Security via the `ENABLE_ENHANCED_SECURITY = YES` build setting and writes the required entitlement keys (Hardened Process, Hardware Memory Tagging, etc.) into `CypherAir.entitlements`. These entitlement keys must be committed to source control — Xcode reads them to determine which protections are enabled. No code changes are required.

### 8.4 Compatibility

- **All models of iPhone 17 and iPhone Air (A19/A19 Pro):** Full MIE protection active.
- **Older devices (A15, A16, A17, A18):** App runs normally. Enhanced Security capability is ignored. No hardware memory tagging.

The Enhanced Security capability is additive and does not affect compatibility with older devices.

### 8.5 Testing

- Run the App on an A19 device with Hardware Memory Tagging enabled. Perform full workflow (both profiles: key gen, encrypt/decrypt, sign/verify).
- Verify no tag mismatch terminations occur (check Console.app and Xcode crash logs).
- Test under Xcode Instruments "Memory Tag Violations" instrument if available.

See also [SECURITY.md](SECURITY.md) Section 8 for additional MIE security analysis.
