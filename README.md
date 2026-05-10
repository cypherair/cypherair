# CypherAir

**Fully offline OpenPGP encryption for Apple platforms — zero network, zero permissions.**

CypherAir is an open-source OpenPGP encryption tool for iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+. It enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties. The app operates with absolutely zero network access and requests no system permissions — data leakage is eliminated at the architectural level.

## Key Features

- **Truly Offline** — No HTTP(S), no networked SDKs, no update checks. Works fully in airplane mode.
- **Zero Permissions** — No camera, photo library, or any other system permission requested. All I/O goes through system-provided pickers and the Share Sheet.
- **Dual Encryption Profiles** — Profile A (Universal Compatible) for GnuPG interoperability; Profile B (Advanced Security) using the latest RFC 9580 standard with stronger algorithms.
- **Secure Enclave Protection** — Private keys are hardware-bound via P-256 key wrapping (CryptoKit ECDH + AES-GCM) with biometric authentication.
- **Usable by Anyone** — No cryptographic knowledge required. Clean, accessible UI built with SwiftUI, using iOS 26 Liquid Glass conventions where applicable and native platform chrome elsewhere.

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
| Platform | iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+ / visionOS 26.4+, minimum 8 GB RAM |
| Language | Apple Swift 6.3.1, SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere), UIKit for system pickers |
| OpenPGP Engine | Sequoia PGP 2.2.0 (Rust), `crypto-openssl` backend (vendored) |
| FFI Bridge | Mozilla UniFFI 0.31.x; Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap` |
| Security | CryptoKit (Secure Enclave), Security.framework (Keychain) |
| Build | Xcode 26.4.1, Rust stable, targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`; `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release |
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
└── Resources/        # Assets, String Catalog

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
CypherAir-Info.plist  # Root-level app Info.plist source
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

- macOS (Apple Silicon) with Xcode 26.4.1
- Rust stable (latest) with targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-visionos aarch64-apple-visionos-sim`

### Commands

```bash
# 1. Validate Rust behavior
cargo test --manifest-path pgp-mobile/Cargo.toml

# 2. Refresh the XCFramework artifact and generated bindings used by Xcode
./build-xcframework.sh --release

# 3. Validate Swift unit + FFI behavior locally
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# 4. Probe the native visionOS app build
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

For Secure Enclave, biometrics, and MIE coverage on hardware:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'
```

For route, tutorial, and other macOS UI changes, also run:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'
```

There is currently no dedicated visionOS XCTest test plan. Native visionOS validation uses the build probe above together with the existing Rust, macOS-local, and iOS-device validation paths.

For the full Rust / UniFFI / Xcode workflow, including XCFramework artifact refresh details and stale-output troubleshooting, see [docs/TESTING.md](docs/TESTING.md) and [CLAUDE.md](CLAUDE.md).

### CI Note

The GitHub Actions workflows in this repository currently target `macos-26`, but GitHub's hosted runner image may still lag the project's minimum deployment target. At the time of writing, the hosted image reports **macOS 26.3**, while the project and test targets require **macOS 26.4**. In that situation:

- Rust CI can still pass normally.
- The hosted Swift unit-test preview job may fail before tests start because the runner OS is older than the app's deployment target.
- That preview remains observational / non-blocking until GitHub's hosted macOS image catches up or the repository adopts a self-hosted macOS runner.
- Local validation using `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` should be treated as the source of truth until GitHub's hosted macOS image catches up.

### XCFramework Prerelease

CypherAir publishes unique edge prerelease XCFrameworks for the current `main` branch using `pgpmobile-edge-` release tags. For discovery, asset names, download commands, verification steps, and the current stable-release channel contract, see [docs/XCFRAMEWORK_RELEASES.md](docs/XCFRAMEWORK_RELEASES.md).

## Security Model

CypherAir's security design centers around several layers of protection:

- **Private Key Storage** — Keys are wrapped by a Secure Enclave P-256 key via self-ECDH + HKDF + AES-GCM, then stored in Keychain. Keys are device-bound and never leave the hardware.
- **Protected App Data** — Implemented app-data domains open after app privacy authentication through a shared Keychain root-secret gate plus Secure Enclave device binding. Current protected domains cover private-key control state, key metadata, protected settings schema v2, Contacts flat compatibility state, and the framework sentinel.
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
| [CONTACTS_PRD](docs/CONTACTS_PRD.md) | Contacts product requirements and package/backup boundaries pending consolidation into long-term docs |
| [CONTACTS_TDD](docs/CONTACTS_TDD.md) | Contacts technical design pending consolidation into long-term docs |
| [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](docs/CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) | Contacts implementation-history and expansion-planning reference pending consolidation |
| [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](docs/CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md) | Contacts access, mutation, and enrichment checklist |
| [CONTACTS_DOC_BRIDGE](docs/CONTACTS_DOC_BRIDGE.md) | Temporary bridge for moving durable Contacts content into long-term docs before archiving Contacts-specific docs |
| [APP_RELEASE_PROCESS](docs/APP_RELEASE_PROCESS.md) | Current app-build release modes, stable asset contract, and App Store candidate ordering |
| [DOCUMENTATION_GOVERNANCE](docs/DOCUMENTATION_GOVERNANCE.md) | Documentation classes, metadata rules, archive rules, and update triggers |
| [COMPLIANCE_REMEDIATION_PLAN (Archive)](docs/archive/COMPLIANCE_REMEDIATION_PLAN.md) | Archived remediation plan and close-out history for the licensing/distribution rollout |
| [POC](docs/archive/POC.md) | Proof-of-concept test plan (archived) |
| [CONVENTIONS](docs/CONVENTIONS.md) | Swift coding standards, SwiftUI patterns, and current Liquid Glass rules |
| [CODE_REVIEW](docs/CODE_REVIEW.md) | Code review checklist by change type |
| [XCFRAMEWORK_RELEASES](docs/XCFRAMEWORK_RELEASES.md) | Current edge, drill, and stable XCFramework release channels and verification |

## License

Unless otherwise noted, first-party CypherAir source code in this repository is
made available under either of the following licenses, at your option:

- GNU General Public License, version 3 or any later version
- Mozilla Public License, version 2.0

SPDX expression for first-party code: **`GPL-3.0-or-later OR MPL-2.0`**.

Full license texts are provided in [LICENSE-GPL](LICENSE-GPL) and
[LICENSE-MPL](LICENSE-MPL).

The OpenPGP engine uses [Sequoia PGP](https://sequoia-pgp.org/) (`LGPL-2.0-or-later`).

Third-party components remain under their own licenses. See the bundled notices
and repository documentation for third-party license details and distribution
compliance materials.

Current stable app-build release ordering and exact source/compliance asset expectations are documented in [docs/APP_RELEASE_PROCESS.md](docs/APP_RELEASE_PROCESS.md) and [docs/XCFRAMEWORK_RELEASES.md](docs/XCFRAMEWORK_RELEASES.md). The historical rollout record is preserved in [docs/archive/COMPLIANCE_REMEDIATION_PLAN.md](docs/archive/COMPLIANCE_REMEDIATION_PLAN.md).
