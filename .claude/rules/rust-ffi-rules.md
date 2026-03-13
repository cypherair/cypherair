---
paths:
  - "pgp-mobile/**"
  - "bindings/**"
---

# Rust FFI (pgp-mobile) Rules

This crate bridges Sequoia PGP to Swift via UniFFI. It handles all OpenPGP cryptographic
operations. Changes here affect the FFI boundary, Swift bindings, and XCFramework.

## Architecture Constraints

- Accept and return `Vec<u8>` for all cryptographic material (keys, ciphertext, plaintext, signatures). Never expose Sequoia internal types across the FFI boundary.
- All `#[uniffi::Object]` types must be `Send + Sync`. Use `Mutex` or `RwLock` for interior mutability. Methods take `&self`, never `&mut self`.
- All `#[uniffi::Record]` types are copied by value across FFI. Keep them small.
- Every fallible operation returns `Result<T, PgpError>`. Never `unwrap()` or `panic!()` in any code path reachable from Swift. A panic across FFI is undefined behavior.

## Error Handling

- Map all Sequoia `anyhow::Error` types to the `PgpError` enum. Each variant must have a `reason: String` field with a user-understandable message.
- Never add catch-all error variants. Each failure mode gets its own variant.
- When adding a new `PgpError` variant, update the corresponding Swift error handling in `Sources/Services/` to display the correct user message per PRD Section 4.7.

## Sensitive Data

- Use the `zeroize` crate on all buffers that held private keys or passphrases. Derive `Zeroize` and `ZeroizeOnDrop` where possible.
- Private key bytes must not persist in Rust memory after the FFI call returns. Zeroize before returning. This is critical because UniFFI's `Vec<u8>` transfer uses copy semantics — the Rust-side buffer is NOT consumed by the transfer and will remain in memory unless explicitly zeroed.
- Never log or `dbg!()` any cryptographic material.

## Sequoia API Usage — Dual Profile

### Profile A (Universal Compatible)

```rust
CertBuilder::general_purpose(Some(uid))
    .set_cipher_suite(CipherSuite::Cv25519)
    // Profile::RFC4880 is default — no explicit set needed
    .generate()?;
```

- Keys: v4 format, Ed25519 + X25519.
- Encryption: SEIPDv1 (MDC). No AEAD.
- S2K export: Iterated+Salted (mode 3).
- Compression: `compression-deflate` enabled for **reading** compatibility only (decompressing messages from other OpenPGP implementations). Outgoing messages must NOT enable compression. Bzip2 excluded (extra C dependency).

### Profile B (Advanced Security)

```rust
CertBuilder::general_purpose(Some(uid))
    .set_cipher_suite(CipherSuite::Cv448)
    .set_profile(Profile::RFC9580)
    .generate()?;
```

- Keys: v6 format, Ed448 + X448.
- Encryption: SEIPDv2, AEAD OCB primary, GCM secondary. Preferred AEAD subpacket: `[AES-256+OCB, AES-256+GCM]`. (AES-128+OCB is implicitly appended per RFC 9580 and does not need to be explicitly specified in the subpacket.)
- S2K export: Argon2id (512 MB / p=4 / ~3s calibrated).
- AEAD hard-fail on auth error — never return partial plaintext.

### Encryption Format Auto-Selection

The `encrypt` function does **not** take a profile parameter. It inspects recipient certificates:
- All v4 → SEIPDv1. All v6 → SEIPDv2. Mixed → SEIPDv1.
- Sequoia handles this automatically. Do not add manual format selection logic.

### Decryption

Accept all: SEIPDv1, SEIPDv2 (OCB), SEIPDv2 (GCM). Reject legacy SEIPD without MDC.

### Common

- Support reading v4 keys, v6 keys, Iterated+Salted S2K, Argon2id S2K.
- Never generate v4 keys from Profile B or v6 keys from Profile A.
- The `KeyProfile` enum (`Universal` / `Advanced`) is passed from Swift and determines CipherSuite + Profile + S2K method.

## Build & Compatibility

- Cargo.toml: `sequoia-openpgp = "2.2"` with `default-features = false` and explicit features: `crypto-openssl`, `compression-deflate`. The `"2.2"` version spec allows 2.2.x patch updates per semver. The exact version is locked via `Cargo.lock` — do not run `cargo update` without testing the new version against the full test suite.
- The `openssl-src` crate handles vendored OpenSSL. Do not add system OpenSSL dependencies. First build compiles OpenSSL from source (~3-5 min); subsequent builds are cached.
- Do not add any crate that makes network calls or requires network at build time beyond crates.io.
- Binary size budget: < 10 MB delta in release build with LTO + strip + opt-level "z".
- After any change, verify BOTH targets build successfully:
  - `cargo build --release --target aarch64-apple-ios`
  - `cargo build --release --target aarch64-apple-ios-sim`
  Vendored OpenSSL cross-compilation may behave differently between these two targets.

## Changing the Public API

Any change to the public API surface of `pgp-mobile` (new functions, changed signatures, new types) requires:
1. Rebuilding the host (macOS) dylib: `cargo build --release`.
2. Regenerating Swift bindings via `uniffi-bindgen`.
3. Rebuilding and updating the XCFramework.
4. Updating the corresponding Swift call sites in `Sources/Services/`.
5. Adding or updating FFI round-trip tests in both Rust (`pgp-mobile/tests/`) and Swift test targets, covering both profiles.

## License

Sequoia PGP is licensed under LGPL-2.0-or-later. The App is GPLv3, which is compatible (GPLv3 satisfies LGPL requirements). Since the App is fully open-source, LGPL compliance is inherently met — the LGPL'd source is available alongside all other source code.

## Definition of Done

- `cargo test --manifest-path pgp-mobile/Cargo.toml` passes
- `cargo clippy --all-targets --manifest-path pgp-mobile/Cargo.toml -- -D warnings` is clean
- Both iOS targets compile: `aarch64-apple-ios` and `aarch64-apple-ios-sim`
- FFI bindings regenerated if public API changed (see "Changing the Public API" above)
- Tests cover both Profile A and Profile B unless explicitly scoped to one
