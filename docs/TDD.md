# Technical Design Document (TDD)

> **Status:** Canonical current-state.
> **Version:** v4.4
> **Companion to:** [PRD](PRD.md) v4.4
> **Audience:** Developers, Security Auditors
> **Update triggers:** Library/backend selection, profile configuration, FFI contract rules, SE wrapping, storage contracts, or MIE enablement change.
> **Last reviewed:** 2026-07-03.

## 1. OpenPGP Library: Sequoia PGP

### 1.1 Selection

sequoia-openpgp 2.3.0. Rust. RFC 9580 + RFC 4880 complete. Licensed under LGPL-2.0-or-later.

Current stable app-build release ordering and the shared source/compliance asset contract are documented in [RELEASE.md](RELEASE.md). This section records the current technical library selection, not a final legal conclusion about distribution compatibility.

| Library | Lang | RFC 9580 | Argon2id | iOS | Decision |
|---------|------|----------|----------|-----|----------|
| Sequoia 2.3.0 | Rust | Full | Native | Excellent | **SELECTED** |
| OpenPGP.js | JS | Partial | Yes | Uncertain | Rejected |
| PGPainless | Java/Kotlin | Partial | Bouncy Castle | KMP bridge | Rejected |
| rPGP | Rust | No | No | Excellent | Rejected |
| Swift native | Swift | N/A | Manual | Native | Rejected |

### 1.2 Backend: crypto-openssl (Vendored)

```toml
sequoia-openpgp = { version = "2.3", default-features = false, features = [
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

### 1.3 Software Profile Configuration

The App uses Sequoia's `Profile` and `CipherSuite` enums to implement three software encryption profiles. The third, Post-Quantum (RFC 9980), is implemented end-to-end and product-selectable in the key-generation surface (campaign #567; [POST_QUANTUM](POST_QUANTUM.md)). The same composite suite backs two key families: the **Portable Post-Quantum** software key described by the table below, and **Device-Bound Post-Quantum** split custody (the PQ components in the Secure Enclave, the classical Ed25519/X25519 components under the fixed-access envelope) — see [SECURE_ENCLAVE_CUSTODY](SECURE_ENCLAVE_CUSTODY.md) §4.1.

| Setting | Profile A (Universal) | Profile B (Advanced) | Post-Quantum |
|---------|----------------------|---------------------|--------------|
| `Profile` | `Profile::RFC4880` | `Profile::RFC9580` | `Profile::RFC9580` |
| `CipherSuite` | `CipherSuite::Cv25519` | `CipherSuite::Cv448` | `CipherSuite::MLDSA65_Ed25519` |
| Key version | v4 | v6 | v6 |
| Signing algo | Ed25519 (legacy EdDSA) | Ed448 | ML-DSA-65+Ed25519 (composite, algo 30) |
| Encryption algo | X25519 (legacy ECDH) | X448 | ML-KEM-768+X25519 (composite, algo 35) |
| Hash | SHA-512 (accepts SHA-256 for legacy verification) | SHA-512 | SHA-512 |
| Symmetric | AES-256 | AES-256 | AES-256 (RFC 9980 floor) |
| Message format | SEIPDv1 (MDC) | SEIPDv2 (AEAD OCB) | SEIPDv2 (AEAD OCB) |
| S2K (export) | Iterated+Salted (mode 3) | Argon2id (512 MB / p=4 / ~3s) | Argon2id (512 MB / p=4 / ~3s) |
| Compression | DEFLATE (read-only) | DEFLATE (read-only) | DEFLATE (read-only) |
| Security level | ~128 bit | ~224 bit | ~192 bit, quantum-resistant |

**Profile classification is algorithm-aware, not version-only:** an RFC 9980 composite primary (ML-DSA-65+Ed25519 or ML-DSA-87+Ed448) classifies as Post-Quantum; any other v6 primary is Profile B; v4 is Profile A. SLH-DSA primaries currently fall back to the Profile B bucket (an under-claim, never an over-claim). The rule lives in one shared function (`classify_profile`) used by `detect_profile`, `parse_key_info`, and the export profile-mismatch guard.

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

**Profile A `set_features` rationale:** Sequoia 2.3.0 defaults to advertising SEIPDv2 support in the Features subpacket (because the library itself supports it). For Profile A (GnuPG-compatible), we must explicitly set `Features::empty().set_seipdv1()` so that other implementations send SEIPDv1 messages to this key. Without this, a GnuPG sender would see SEIPDv2 advertised and attempt to send an AEAD-encrypted message, which GnuPG cannot produce correctly — resulting in interoperability failure. `set_profile(Profile::RFC4880)` is also set explicitly rather than relying on defaults, for clarity and forward-compatibility.

**Swift key metadata vocabulary:** ProtectedData `key-metadata` schema v2 stores each `PGPKeyIdentity` with an app-owned OpenPGP configuration identity and private-key custody kind. Profile A/B identities normalize to software custody; P-256 Secure Enclave custody identities persist the device-bound custody kind. Committed key metadata opens fail closed unless the readable `current.plist` generation matches the per-domain bootstrap `expectedCurrentGenerationIdentifier`. Key operation resolution adds non-persistent sanitized failure categories so resolver, future router, Security, Rust/UniFFI, workflow-service, and UI mapping plans can distinguish unsupported, unavailable, not-yet-implemented, local-authentication, handle, binding, OpenPGP semantic, payload-authentication, migration/recovery, fallback, and cleanup failures without storing private-operation state.

**Contacts protected storage:** The `contacts` ProtectedData domain uses SQLCipher schema v2 at `Application Support/ProtectedData/contacts/contacts.sqlite` as the only Contacts payload authority. `ContactService` remains the app/UI facade; `ContactsDomainStore` opens the domain after app authentication, unwraps the existing `contacts` domain master key, and keys SQLCipher with raw-key syntax rather than creating a separate database-key record. Bootstrap metadata retains schema version and wrapped-DMK record version, with `expectedCurrentGenerationIdentifier == nil`; legacy snapshot-envelope artifacts are reset/recovery cleanup inputs, not fallback state.

**External P-256 private-operation seam:** Secure Enclave custody (the
device-bound key families — see [SECURITY.md](SECURITY.md) §3) delegates only the private
scalar operation to an external callback through Sequoia's `Signer`/`Decryptor`
traits. External signing builds v4/v6 public-only certificates and signs
cleartext/detached/encrypt/expiry/revocation/certification data through the shared
Sequoia signing stream; the callback receives a public key plus SHA-256 digest and
returns a fixed-width nonzero ECDSA `r/s` that Rust verifies against that key and
digest. External ECDH decrypts SEIPDv1/MDC and SEIPDv2/AEAD messages; the callback
returns only a raw 32-byte shared secret, while Sequoia retains the OpenPGP ECDH
KDF, AES Key Wrap unwrap, session-key validation, payload authentication, and
signature verification. The seam never stores Security handles or secret-certificate
material, never bridges response files, and never falls back to secret-certificate
signing or decryption. The hidden generation callback boundary uses
callback-specific UniFFI errors with typed sanitized categories so cancellation and
handle/auth/hardware failures do not cross Sequoia as free-form strings. The
negative matrix rejects wrong roles, wrong public bindings, wrong or unverified
`r/s`, unsupported key/ciphertext shapes, wrong (or shape-valid-but-wrong) shared
secrets, and tampered payloads — which must hard-fail after session-key acceptance
without releasing plaintext.

**Secure Enclave custody handle store and generation:** A Swift Security-layer
store owns two distinct permanent P-256 Secure Enclave `SecKey` handles (`.signing`
and `.keyAgreement`) plus their lifecycle, public-binding/role load checks,
partial-creation rollback, inventory, idempotent delete, Reset All Local Data
cleanup (including malformed app-owned rows), and sanitized failure classification;
the access-control flags, application-tag format, and non-disclosure red lines are
owned by [SECURITY.md](SECURITY.md) §3. Custody generation creates the handle
pair and asks Rust/Sequoia to build a public-only v4/v6 certificate plus key-level
revocation artifact through the external signer callback, persisting only
`PGPKeyIdentity` metadata with P-256 configuration and Secure Enclave custody — no
secret cert, handle locator, or access-control policy. Recovery classification
inspects stored public certificates, locates handles by public binding, and keeps
only a sanitized in-memory metadata/handle report without persisting locators or
deleting startup orphan handles. Public-key and revocation export use stored public
artifacts; missing revocation fails closed and private-key backup/export is
unsupported.

### 1.4 Encryption Format Auto-Selection

When encrypting, the message format is determined by the recipient's key version, not the sender's profile:

- **All recipients have v4 keys** → SEIPDv1 (MDC). No AEAD.
- **All recipients have v6 keys** → SEIPDv2 (AEAD OCB, with GCM as secondary preference).
- **Mixed v4 + v6 recipients** → SEIPDv1 (lowest common denominator).
- **Encrypt-to-self** adds the sender's own key. If sender has v6 and recipient has v4, the mixed rule applies → SEIPDv1.

Sequoia handles this automatically when the recipient certificates are passed to the encryption API. The Rust wrapper does not need to implement format selection logic manually.

Post-quantum recipients ride the same version-driven rule (they are v6): PQ-only → SEIPDv2; mixed PQ + v4 → SEIPDv1, in which case the RFC 9980 **AES-256 floor** still holds inside the SEIPDv1 container (verified by decrypt-time cipher assertions in `portable_pq_message_tests.rs`). The engine additionally classifies any produced message's quantum-safety from its PKESK algorithms (`message_quantum_safety`: fully post-quantum / mixed / none) — the compose surface derives its quantum-safe badge from that artifact-level classification, never from the live recipient selection.

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

The current release pipeline includes native visionOS support. `build-xcframework.sh` builds and validates the visionOS device and simulator archives, packages all Apple slices into `PgpMobile.xcframework`, and the Xcode project links that XCFramework. The native app path is probed locally with `xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS'`.

To keep vendored OpenSSL reproducible across the current Apple `arm64e`
build chain, `pgp-mobile/Cargo.toml` patches `openssl-src` through
`[patch.crates-io]` to the CypherAir fork
`https://github.com/cypherair/openssl-src-rs` on branch
`carry/apple-arm64e-openssl-fork`. That branch is expected to track the
CypherAir OpenSSL fork branch `carry/apple-arm64e-targets`. `Cargo.toml`
intentionally tracks the branch so local branch status/docs updates are not
left behind; `pgp-mobile/Cargo.lock` records the resolved git commit for
repeatable builds.

The current deployment baseline for the app targets is `iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+`.

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
    fn decrypt_detailed(&self, ciphertext: Vec<u8>, secret_keys: Vec<Vec<u8>>,
                        verification_keys: Vec<Vec<u8>>) -> Result<DecryptDetailedResult, PgpError>;
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
2. `./build-xcframework.sh --release` is the packaging entrypoint; for local app-side validation, run it with the pinned force-download environment from [CLAUDE.md](../CLAUDE.md) Build Commands so it refreshes stable `arm64` and patched `arm64e` release archives from the pinned attested stage1, generates UniFFI Swift bindings and headers from an `arm64e-apple-darwin` host dylib, validates host-dylib cleanup, produces the packaged `PgpMobile.xcframework` output, and writes `PgpMobile.arm64e-build-manifest.json`
3. The current Xcode project links `PgpMobile.xcframework` and imports the generated headers through `bindings/module.modulemap`
4. Local Swift / FFI validation runs through the `CypherAir-UnitTests` plan ([TESTING.md](TESTING.md) Section 2.4)

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

- **API evolution is additive during migration.** New semantics should first land as parallel methods, result records, or enums. Once migration gates pass, superseded surfaces can be deleted intentionally instead of kept as permanent compatibility APIs.
- **Payload input classes must stay explicit.** Byte-oriented OpenPGP payload inputs are classified as `binary-only`, `armored-only`, or `dual-format`; new APIs must document which class they accept instead of relying on implicit parser behavior.
- **Cryptographic selectors use bytes, not display strings.** Selector-bearing User ID operations use raw `userIdData + occurrenceIndex`, and cryptographically significant payloads stay as `Vec<u8>` / `Data`.
- **Discovery helpers are part of the contract when needed.** If a downstream Swift service cannot safely discover required selectors or metadata from the current exported surface, the Rust / FFI boundary must grow a bounded helper rather than pushing string inference into Swift callers.
- **Parse/setup failure stays distinct from cryptographic invalidity.** Parse, type, and precondition failures return `Err(PgpError)`. Successful parsing followed by crypto failure should stay in family-specific result or graded-status types.
- **`PgpError` remains the cross-family fatal boundary.** UniFFI-visible error changes must preserve the Rust/Swift 1:1 mapping and should be reserved for fatal semantics that cannot be modeled as a family-local result.
- **Signer fingerprint meaning must stay explicit.** Detailed verify/decrypt summaries expose the signer certificate primary fingerprint, not the signing subkey fingerprint. New APIs must either preserve that meaning or add a separate explicit subkey field.
- **Any UniFFI-visible surface change is a multi-layer change.** Follow the sync-and-validate workflow in [TESTING.md](TESTING.md) Section 2.4.
- **Plaintext-bearing results still inherit Swift-side zeroization expectations** (CLAUDE.md hard constraint 5).

### 2.9 Current FFI Capability Families

The capability-family inventory — Rust/FFI role, Swift service owner, current app owner, and shipped state per family — is maintained in [ARCHITECTURE.md](ARCHITECTURE.md) Section 2 ("Current Rust / FFI Capability Ownership").

All current app-surface workflows continue to call Swift service owners rather than `PgpEngine` directly.

---

## 3. Secure Enclave Key Wrapping

### 3.1 Constraint

SE supports P-256 only. Ed25519/X25519/Ed448/X448 keys all require indirect wrapping. The wrapping scheme is identical for both profiles — the SE protects the raw private key bytes regardless of the key algorithm.

### 3.2 Wrapping Flow

An ephemeral-static ECDH (a fresh software-ephemeral P-256 key agreed against the persistent per-key SE public key) feeds HKDF-SHA256 with a random salt and a domain-separated `sharedInfo` to derive an AES-256 key, which seals the raw private key bytes via AES-GCM whose AAD binds every public parameter (fingerprint, SE key blob, both public keys, plaintext length). The result is a single self-contained `CAPKEV1` envelope (`PrivateKeyEnvelope`) — SE key `dataRepresentation`, ephemeral public key, salt, nonce, ciphertext, and tag — stored as one Keychain row; the raw key bytes are zeroized only after the write is confirmed. Authoritative step-by-step flow, binding details, and ordering rationale: [SECURITY.md](SECURITY.md) Section 3.

### 3.3 Unwrapping Flow

The stored envelope is decoded and validated, then reconstructing the SE key from its `dataRepresentation` triggers device authentication (per auth mode); after a fail-closed bound-public-key check, the symmetric key is re-derived from `ECDH(SE private × envelope ephemeral public)` plus HKDF with the stored salt and the same binding, and the AAD-checked AES-GCM open yields raw private key bytes that are zeroized immediately after the PGP operation completes. Full flow and security analysis: [SECURITY.md](SECURITY.md) Section 3.

### 3.4 Access Control (Dual Mode)

| Mode | Flags | Behavior |
|------|-------|----------|
| Standard (default) | `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]` | Face ID / Touch ID with passcode fallback. Equivalent to `deviceOwnerAuthentication`. |
| High Security | `[.privateKeyUsage, .biometryAny]` | Face ID / Touch ID only. No passcode fallback. If biometrics unavailable, private key is inaccessible. |

**Mode switching:** Changing the authentication mode re-wraps all SE-protected private keys with the new access control flags under a single authentication, atomically — original keys stay intact until the complete pending envelope row is verified, and crash recovery uses the post-unlock `private-key-control.recoveryJournal`. Authoritative procedure, atomicity ordering, and recovery rules: [SECURITY.md](SECURITY.md) Section 4.

### 3.5 Keychain Layout

Per identity (fingerprint = lowercase hex, no spaces) — one self-contained envelope row, plus a transient pending row during mode-switch / modify-expiry:
```
com.cypherair.v1.privkey-envelope.<fingerprint>
com.cypherair.v1.pending-privkey-envelope.<fingerprint>
```

**Keychain item configuration:**

| Item | kSecClass | kSecAttrAccessible | Access Control |
|------|-----------|-------------------|----------------|
| SE key `dataRepresentation` | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | Per auth mode |
| Salt | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |
| Encrypted private key | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |
| ProtectedData committed wrapped-DMK record | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |
| ProtectedData staged wrapped-DMK record | `kSecClassGenericPassword` | `WhenUnlockedThisDeviceOnly` | None |

ProtectedData uses this device-binding key only to open the app-data
root-secret envelope after the existing Keychain / `LAContext` gate succeeds. Its
Secure Enclave `dataRepresentation` is folded into that envelope (a single
self-contained row) and reconstructed at open time; it is not a separate Keychain
item and is not part of the private-key envelope model. Open fails closed unless
the Secure Enclave can reconstruct the folded key and its public key matches the
envelope's bound public key.

### 3.6 Security Properties

See [SECURITY.md](SECURITY.md) Section 3 ("Security Properties"): Keychain extraction without the SE hardware yields a useless encrypted blob, and the raw private key exists in application memory only briefly during use — an inherent tradeoff of the P-256-only SE constraint.

### 3.7 Key Loss & Recovery

SE keys destroyed by: device erase, iCloud restore, backup restore. App detects → prompts restore from backup → generates new SE key → re-wraps.

---

## 4. Argon2id Configuration (Profile B Only)

| Parameter | Value | RFC 9580 Encoding | Rationale |
|-----------|-------|-------------------|-----------|
| Memory | 512 MB | encoded_m = 19 | ~6% of 8 GB min RAM |
| Parallelism | 4 | p = 4 | 128 MB per lane |
| Time | Fixed at 3 passes (~3s target on contemporary hardware) | t = 3 | Stable, explicit export profile |

**Not used by Profile A.** Profile A uses Iterated+Salted S2K (mode 3) for key export, which is universally supported by GnuPG. Canonical parameter set, scope, and refusal message: [SECURITY.md](SECURITY.md) Section 7.

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

Detailed storage locations, target classes, current status, and migration readiness live in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). This TDD owns the technical contracts for ProtectedData behavior, migration safety, relock, and recovery; it does not duplicate the full persisted-state inventory.

Protected app-data planning covers all CypherAir-owned local data, not only preferences. Permanent exceptions remain limited to documented boot-authentication, private-key material, framework bootstrap, test-only, temporary, and out-of-app-custody export surfaces as classified in the inventory.

### 6.1 ProtectedData Current Contract

ProtectedData is the current shared framework for app-owned local state that opens only after app privacy authentication. It is separate from the private-key material domain and does not store OpenPGP secret key bytes.

Current framework contracts:

- `ProtectedDataRegistry` is the plaintext bootstrap authority for committed domain membership, shared-resource lifecycle state, and a single pending create/delete mutation.
- Pre-auth startup may classify the registry and per-domain bootstrap metadata, but must not load the shared app-data root secret, unwrap any domain master key, or open protected payload generations.
- The shared app-data root secret is stored in the Keychain as a single self-contained v3 `CAPDSEV3` envelope and is loaded with an authenticated `LAContext` handoff. The ProtectedData-only Secure Enclave device-binding key is folded into that envelope (no separate row) and reconstructed to silently unwrap it under the same app-session gate.
- `ProtectedDomainKeyManager` derives a wrapping root key from the raw root secret, zeroizes the raw root secret, then unwraps per-domain 256-bit domain master keys from Keychain-backed wrapped-DMK records.
- Protected domain files live under the inventory's protected app-data storage root; registry, bootstrap metadata, scratch writes, and domain payload generations verify explicit file protection where available. Wrapped-DMK records live in Keychain staged/committed rows under `com.cypherair.v1.protected-data.domain-key.*`.
- Relock clears the wrapping root key, unwrapped DMKs, and registered domain-local decrypted state. A relock participant failure latches runtime-only `restartRequired`.

Current production domain families and their row-level payload classification are tracked in [PERSISTED_STATE_INVENTORY](PERSISTED_STATE_INVENTORY.md). At the technical-contract level, each production domain must open through the post-auth handoff, decode strictly, enter recovery instead of silently resetting unreadable committed state, and clear decrypted domain-local state on relock.

The current `contacts` domain is the authoritative protected source for Contacts data. Person-centered key modeling and merge behavior, certification projection and saved certification artifacts, search, tags, and Encrypt tag batch selection are implemented over the unlocked protected `contacts` snapshot. Search indexes, screen filters, tag-applied recipient selections, and manual recipient selections are runtime state only, not persisted state. Contacts package exchange is not implemented; any future complete Contacts backup must be designed separately as mandatory encrypted backup.

### 6.2 Contacts Domain Contract

The protected Contacts payload is schema v2 `ContactsDomainSnapshot` with `ContactIdentity`, `ContactKeyRecord`, `ContactTag`, and `ContactCertificationArtifactReference` records. Contact identities own display name, primary email, tag membership, notes, and timestamps. Key records own public certificate bytes, fingerprint/User ID/profile/algorithm metadata, manual verification state, preferred/additional/historical usage state, certification projection, and certification artifact references.

At most one encryptable key per contact may be preferred. Additional active keys remain usable as contact-owned key material but are not selected for encryption recipient resolution unless made preferred. Historical keys are excluded from encryption recipient resolution while remaining available for signer recognition and history. Merge operations preserve per-key manual verification and certification state, union tags, and keep certification artifacts attached to their original key records.

Tags normalize display text for case-insensitive uniqueness. In Encrypt, applying a tag is a one-way batch selection action: it adds the tag's currently encryptable contacts to `selectedRecipients`, reports any tagged contacts skipped for lacking a preferred encryptable key, and leaves the final send target as explicit selected contact IDs that users may edit or clear. Contacts search indexes, screen filters, pending route state, recipient selection, signer lookup caches, and other derived projections are runtime-only and must be cleared on relock or content clear rather than persisted outside the protected `contacts` payload.

Migration and exception rules:

- `private-key-control` settings and recovery-journal state are created and mutated only inside the protected payload.
- Key metadata persists only in the protected `key-metadata` domain.
- Permanent and pending private-key envelope rows remain in the existing Keychain / Secure Enclave private-key material domain.
- Self-test reports are in-memory export-only data.
- Temporary/export/tutorial artifacts are centralized through `AppTemporaryArtifactStore`; streaming/decrypted outputs, export handoff files, tutorial sandbox directories, startup cleanup, and reset cleanup keep the ephemeral-with-cleanup behavior classified in the inventory.
- Contacts production data remains in the protected `contacts` domain. Legacy flat Contacts files under `Documents/contacts` are outside supported app state and are not read, migrated, quarantined, or reset-cleaned.
- Contacts payloads with an unsupported schema version fail closed and route the Contacts domain to recovery.
- Future protected-domain migrations must preserve readable source state until the protected destination is created/opened and verified through the normal post-auth path.
- Unsupported legacy flat Contacts files must not become fallback sources of truth.
- Protected-after-unlock settings must not add pre-unlock shadow copies; `appSessionAuthenticationPolicy` is the only ordinary settings boot-authentication exception.
- Documentation updates for storage or migration changes follow the documentation contract in [WORKFLOW.md](WORKFLOW.md), with [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md) as the row-level inventory.

---

## 7. UI Framework

SwiftUI (iOS 26.5+). UIKit: UIActivityViewController, UIDocumentPickerViewController, PHPickerViewController, beginBackgroundTask.

---

## 8. Memory Integrity Enforcement (MIE)

Memory Integrity Enforcement is Apple's hardware-level memory safety system (Enhanced Memory Tagging Extension, secure typed allocators, Tag Confidentiality Enforcement). It matters for CypherAir because vendored OpenSSL is C code — memory corruption is the primary attack vector against C cryptographic libraries — and Apple explicitly recommends MIE for apps that are "likely entry points for attackers — such as social networks, messaging apps, or any other app where a specific user can be targeted." Protection is always on with no user-visible performance cost on supported hardware, and the capability is additive: unsupported devices simply run without hardware tagging.

Enablement: in Xcode 26.5, add the Enhanced Security capability and enable Hardware Memory Tagging. Xcode manages this via `ENABLE_ENHANCED_SECURITY = YES` and writes the required entitlement keys into `CypherAir.entitlements`; those keys must stay committed to source control. No code changes are required.

Canonical entitlement-key list, supported-device examples, and the MIE testing workflow: [SECURITY.md](SECURITY.md) Section 8.
