# CypherAir

**Fully offline OpenPGP encryption for iOS — zero network, zero permissions.**

CypherAir is an open-source OpenPGP encryption tool for iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+. It enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties. The app operates with absolutely zero network access and requests no system permissions — data leakage is eliminated at the architectural level.

## Key Features

- **Truly Offline** — No HTTP(S), no networked SDKs, no update checks. Works fully in airplane mode.
- **Zero Permissions** — No camera, photo library, or any other system permission requested. All I/O goes through system-provided pickers and the Share Sheet.
- **Dual Encryption Profiles** — Profile A (Universal Compatible) for GnuPG interoperability; Profile B (Advanced Security) using the latest RFC 9580 standard with stronger algorithms.
- **Secure Enclave Protection** — Private keys are hardware-bound via P-256 key wrapping (CryptoKit ECDH + AES-GCM) with biometric authentication.
- **Usable by Anyone** — No cryptographic knowledge required. Clean, accessible UI built with iOS 26 Liquid Glass design language.

## Encryption Profiles

### Profile A — Universal Compatible (Default)

Designed for maximum interoperability with all major PGP implementations including GnuPG 2.1+.

| Component | Spec |
|-----------|------|
| Key format | v4 (RFC 4880) |
| Signing / Encryption | Ed25519 / X25519 |
| Message format | SEIPDv1 (MDC) |
| S2K (key export) | Iterated+Salted |
| Security level | ~128 bit |

### Profile B — Advanced Security

Designed for maximum security using RFC 9580. Not compatible with GnuPG.

| Component | Spec |
|-----------|------|
| Key format | v6 (RFC 9580) |
| Signing / Encryption | Ed448 / X448 |
| Message format | SEIPDv2 (AEAD OCB) |
| S2K (key export) | Argon2id (512 MB / p=4 / t=3) |
| Security level | ~224 bit |

Compatible with Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+, Bouncy Castle 1.82+.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Platform | iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+, minimum 8 GB RAM |
| Language | Swift 6.2, SwiftUI (Liquid Glass), UIKit for system pickers |
| OpenPGP Engine | Sequoia PGP 2.2.0 (Rust), `crypto-openssl` backend (vendored) |
| FFI Bridge | Mozilla UniFFI 0.31.x |
| Security | CryptoKit (Secure Enclave), Security.framework (Keychain) |
| Build | Xcode 26, Rust stable, targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` |
| Localization | English + Simplified Chinese (.xcstrings) |

## Architecture

CypherAir is a three-layer application: a SwiftUI presentation layer, a Swift services layer, and a Rust cryptographic engine bridged via UniFFI.

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE wrapping, Keychain, auth modes, memory zeroing
├── Models/           # Data types, PGP key representations, error types
├── Extensions/       # Swift/Foundation extensions
└── Resources/        # Assets, String Catalog, Info.plist

pgp-mobile/           # Rust wrapper crate (Sequoia PGP + UniFFI)
├── src/
│   ├── lib.rs        # UniFFI proc-macros, public API surface
│   ├── keys.rs       # Profile-aware key generation
│   ├── encrypt.rs    # Auto format selection by recipient key version
│   ├── decrypt.rs    # SEIPDv1 + SEIPDv2, AEAD hard-fail
│   ├── sign.rs       # Cleartext + detached signatures
│   ├── verify.rs     # Graded signature verification
│   ├── streaming.rs  # File-path-based streaming I/O with progress reporting
│   ├── armor.rs      # ASCII armor encode/decode
│   └── error.rs      # Error enum (maps 1:1 to Swift)
└── tests/

docs/                 # Design documents
```

## Recent Internal Improvements

Recent refactors focused on maintainability and safety without changing the app's user-facing cryptographic behavior:

- **Shared recovery infrastructure** — Secure Enclave / Keychain migration and crash-recovery logic now runs through shared transaction helpers instead of being duplicated across services.
- **Safer recovery semantics** — Crash recovery now explicitly prefers complete bundles over partial ones, distinguishes retryable vs unrecoverable recovery failures, and feeds generic startup diagnostics into the existing warning surface.
- **Shared operation controllers** — Encrypt, decrypt, sign, and verify flows now reuse common helpers for security-scoped file access, export, cancellation, progress, and clipboard behavior.
- **Cleaner startup wiring** — App dependency construction and startup recovery live in a dedicated container/coordinator instead of the app entry point.
- **Shared identity presentation helpers** — Fingerprint formatting and accessibility labels are defined once and reused across the UI.
- **Expanded validation** — Recovery-specific tests now cover stale pending cleanup, partial permanent replacement, retryable Keychain failures, startup diagnostics, and generalized warning hygiene.

## Build

### Prerequisites

- macOS (Apple Silicon) with Xcode 26
- Rust stable (latest) with targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin`

### Commands

```bash
# Cross-compile Rust for iOS device
# First build compiles vendored OpenSSL from source (~3-5 min)
cargo build --release --target aarch64-apple-ios \
    --manifest-path pgp-mobile/Cargo.toml

# Cross-compile for Apple Silicon simulator
cargo build --release --target aarch64-apple-ios-sim \
    --manifest-path pgp-mobile/Cargo.toml

# Cross-compile for macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin \
    --manifest-path pgp-mobile/Cargo.toml

# Build the host-only dylib used by UniFFI bindgen
cargo rustc --release --manifest-path pgp-mobile/Cargo.toml \
    --lib -- --crate-type cdylib

# Generate Swift bindings
cargo run --release --manifest-path pgp-mobile/Cargo.toml \
    --bin uniffi-bindgen generate \
    --library pgp-mobile/target/release/libpgp_mobile.dylib \
    --language swift --out-dir bindings/

# Create XCFramework (all three platform slices)
xcodebuild -create-xcframework \
    -library pgp-mobile/target/aarch64-apple-ios/release/libpgp_mobile.a -headers bindings/ \
    -library pgp-mobile/target/aarch64-apple-ios-sim/release/libpgp_mobile.a -headers bindings/ \
    -library pgp-mobile/target/aarch64-apple-darwin/release/libpgp_mobile.a -headers bindings/ \
    -output PgpMobile.xcframework

# Run Rust tests
cargo test --manifest-path pgp-mobile/Cargo.toml
```

Then open the Xcode project and build normally.

### CI Note

The GitHub Actions workflows in this repository currently target `macos-26`, but GitHub's hosted runner image may still lag the project's minimum deployment target. At the time of writing, the hosted image reports **macOS 26.3**, while the project and test targets require **macOS 26.4**. In that situation:

- Rust CI can still pass normally.
- The hosted Swift unit-test job may fail before tests start because the runner OS is older than the app's deployment target.
- Local validation using `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` should be treated as the source of truth until GitHub's hosted macOS image catches up.

## Security Model

CypherAir's security design centers around several layers of protection:

- **Private Key Storage** — Keys are wrapped by a Secure Enclave P-256 key via self-ECDH + HKDF + AES-GCM, then stored in the iOS Keychain. Keys are device-bound and never leave the hardware.
- **Two-Phase Decryption** — Phase 1 parses the message header and matches recipient keys without authentication. Phase 2 requires biometric/passcode auth before decryption proceeds.
- **Authentication Modes** — Standard Mode (Face ID / Touch ID with passcode fallback) or High Security Mode (biometric only, inspired by Apple's Stolen Device Protection).
- **Memory Safety** — Sensitive data is zeroed from memory after use. MIE (Memory Integrity Enforcement) is enabled via Xcode's Enhanced Security capability, providing hardware memory tagging on A19+ devices.
- **Privacy Screen** — Blur overlay when the app enters background. Configurable re-authentication grace period.
- **AEAD Hard-Fail** — Authentication failures in encrypted messages result in immediate failure with no plaintext fragments exposed.

For the complete security specification, see [docs/SECURITY.md](docs/SECURITY.md).

## User Workflows

- **Key Exchange** — QR code (via system Camera + URL scheme), Share Sheet (.asc file), or clipboard paste.
- **Text Encryption** — Select recipients, toggle encrypt-to-self and signature, encrypt, then copy or share the ciphertext.
- **File Encryption** — Pick a file, same flow as text. Produces binary `.gpg` output. Streaming I/O with progress reporting. Cancellable. File size validated against available disk space at runtime.
- **Decryption** — Paste or import ciphertext → two-phase flow → biometric auth → plaintext displayed in memory only, cleared on dismiss.
- **Signing & Verification** — Cleartext signatures for text, detached `.sig` for files. Auto-verification during decryption with graded results.
- **Backup & Restore** — Export passphrase-protected private key via Share Sheet (S2K protection matches the key's profile). Import from `.asc` file.

## Documentation

| Document | Description |
|----------|-------------|
| [PRD](docs/PRD.md) | Product requirements, workflows, and acceptance criteria |
| [TDD](docs/TDD.md) | Technical design — library selection, FFI, SE wrapping |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Module breakdown, data flows, storage layout |
| [SECURITY](docs/SECURITY.md) | Encryption scheme, key lifecycle, threat model |
| [TESTING](docs/TESTING.md) | Test strategy and coverage |
| [POC](docs/archive/POC.md) | Proof-of-concept test plan (archived) |
| [CONVENTIONS](docs/CONVENTIONS.md) | Swift coding standards and SwiftUI patterns |
| [LIQUID_GLASS](docs/LIQUID_GLASS.md) | iOS 26 Liquid Glass design adoption guide |
| [CODE_REVIEW](docs/CODE_REVIEW.md) | Code review checklist by change type |
| [CHANGELOG](docs/CHANGELOG.md) | PRD revision history |

## License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

The OpenPGP engine uses [Sequoia PGP](https://sequoia-pgp.org/) (LGPL-2.0-or-later), which is compatible with GPLv3.
