# CypherAir

**Fully offline OpenPGP encryption for Apple platforms — zero network, minimal permissions.**

CypherAir is an open-source OpenPGP encryption tool for iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+. It enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties. The app operates with absolutely zero network access and uses only the biometric usage description needed for local authentication — data leakage is eliminated at the architectural level.

## Key Features

- **Truly Offline** — No HTTP(S), no networked SDKs, no update checks. Works fully in airplane mode.
- **Minimal Permissions** — Only the biometric usage description is configured for local authentication. No camera, photo library, contacts, or network permissions. All I/O goes through system-provided pickers and the Share Sheet.
- **Nine Key Families** — Five portable software tiers (Legacy, Modern, Modern · High, Post-Quantum, Post-Quantum · High) and four device-bound Secure Enclave tiers (Legacy, Modern, Post-Quantum, Post-Quantum · High). Legacy is GnuPG-compatible (RFC 4880); the Modern tiers follow RFC 9580 and the Post-Quantum tiers RFC 9980. Modern · High (Ed448/X448) is portable-only.
- **Secure Enclave Custody** — Device-bound keys perform signing and decryption inside the Secure Enclave and can never be exported; portable software keys are wrapped at rest via Secure Enclave P-256 ECDH + AES-GCM with biometric authentication.
- **Usable by Anyone** — No cryptographic knowledge required. Clean, accessible UI built with SwiftUI, using iOS 26 Liquid Glass conventions where applicable and native platform chrome elsewhere.

## Key Families

| Family | Standard | Algorithms | Custody | GnuPG |
|--------|----------|-----------|---------|-------|
| Portable Legacy | RFC 4880 (v4) | Ed25519 / X25519, SEIPDv1 | Software, exportable | Compatible |
| Portable Modern | RFC 9580 (v6) | Ed25519 / X25519, SEIPDv2 AEAD | Software, exportable | Not compatible |
| Portable Modern · High | RFC 9580 (v6) | Ed448 / X448, SEIPDv2 AEAD | Software, exportable | Not compatible |
| Portable Post-Quantum | RFC 9980 (v6) | ML-DSA-65+Ed25519 / ML-KEM-768+X25519 | Software, exportable | Not compatible |
| Portable Post-Quantum · High | RFC 9980 (v6) | ML-DSA-87+Ed448 / ML-KEM-1024+X448 | Software, exportable | Not compatible |
| Device-Bound Legacy | RFC 4880 (v4) | P-256 / P-256 | Secure Enclave, non-exportable | Compatible |
| Device-Bound Modern | RFC 9580 (v6) | P-256 / P-256 | Secure Enclave, non-exportable | Not compatible |
| Device-Bound Post-Quantum | RFC 9980 (v6) | ML-DSA-65+Ed25519 / ML-KEM-768+X25519 | Split custody: post-quantum in Secure Enclave, classical sealed to device | Not compatible |
| Device-Bound Post-Quantum · High | RFC 9980 (v6) | ML-DSA-87+Ed448 / ML-KEM-1024+X448 | Split custody: post-quantum in Secure Enclave, classical sealed to device | Not compatible |

Message format is selected automatically by recipient key version; any post-quantum recipient enforces an AES-256 floor. Full family and format canon: [docs/PRD.md](docs/PRD.md) §3 and [docs/TDD.md](docs/TDD.md) §1.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Platform | iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+, minimum 8 GB RAM |
| Language | Apple Swift (6.4 beta development toolchain; 6.3.3 release toolchain), SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere), UIKit for system pickers |
| OpenPGP Engine | Sequoia PGP 2.4.1 (Rust), `crypto-openssl` backend (vendored) |
| FFI Bridge | Mozilla UniFFI 0.31.x; Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap` |
| SQLCipher | Pinned external `SQLCipher.xcframework` from `cypherair/sqlcipher-xcframework`, restored as a git-ignored artifact and verified against `third_party/sqlcipher-xcframework.pin.json` |
| Security | CryptoKit (Secure Enclave), Security.framework (Keychain) |
| Build | Xcode 27.0 beta (development) / Xcode 26.6 (release toolchain), Rust stable, targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`; `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release |
| Localization | English + Simplified Chinese (.xcstrings) |

## Architecture

CypherAir is a three-layer application: a SwiftUI presentation layer, a Swift services layer, and a Rust cryptographic engine bridged via UniFFI.

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE custody, Keychain, auth modes, ProtectedData, memory zeroing
├── Models/           # Data types, PGP key representations, error types
├── Extensions/       # Swift/Foundation extensions
├── PgpMobile/        # Generated UniFFI Swift bindings (do not hand-edit)
└── Resources/        # Assets, String Catalog

pgp-mobile/           # Rust wrapper crate (Sequoia PGP + UniFFI)
docs/                 # Canonical project documents
CypherAir-Info.plist  # Root-level app Info.plist source
```

Module breakdown: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Build

### Prerequisites

- macOS (Apple Silicon) with Xcode 26.6 or newer (development currently tracks the Xcode 27.0 beta)
- Rust stable (latest) with targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-visionos aarch64-apple-visionos-sim`

### Xcode MCP

The repository ships a project-level `.mcp.json` configuring an `xcode` MCP server (`/usr/bin/xcrun mcpbridge`, Xcode 26.3+), which gives agent sessions Apple Developer Documentation search and build/diagnostic tools. Enable Xcode Settings → Intelligence → Xcode Tools → Model Context Protocol and keep Xcode running; other MCP-capable agents configure the equivalent server command.

### Commands

```bash
# 1. Validate Rust behavior
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# 2. Refresh the XCFramework artifact and generated bindings used by Xcode.
# build-xcframework.sh consumes a pinned arm64e stage1 prerelease; `latest` is
# rejected. Use the pinned ARM64E_STAGE1_RELEASE_TAG value from CLAUDE.md
# (Build Commands) or docs/ARM64E_STATUS.md (the arm64e source of truth).
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=<pinned-tag> \
    ./build-xcframework.sh --release

# 3. Restore the pinned SQLCipher external dependency (git-ignored artifact;
# backs the protected Contacts database).
scripts/restore_sqlcipher_xcframework.sh

# 4. Validate Swift unit + FFI behavior locally
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# 5. Probe the native visionOS app build
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS'
```

Secure Enclave / biometrics / MIE coverage runs on real hardware (an Apple Silicon Mac or a physical device) via the `CypherAir-DeviceTests` plan; macOS UI smoke coverage via `CypherAir-MacUITests`. There is no dedicated visionOS test plan — the build probe above plus the Rust and macOS lanes cover it. Full workflow, CI lanes, hosted-runner caveats, and stale-artifact troubleshooting: [docs/TESTING.md](docs/TESTING.md) and [CLAUDE.md](CLAUDE.md).

Prebuilt `PgpMobile.xcframework` binaries are published on edge and stable channels, and the SQLCipher dependency is refreshed by re-pinning a release of `cypherair/sqlcipher-xcframework` — see [docs/RELEASE.md](docs/RELEASE.md) for channels, verification, and the stable asset contract.

## Security Model

CypherAir's security design centers around several layers of protection:

- **Private Key Custody** — Portable software keys are sealed in an authenticated envelope using ephemeral-static P-256 ECDH against a per-key Secure Enclave key (HKDF + AES-GCM, public-parameter AAD binding) and stored as a single Keychain row. Device-bound keys never exist outside the Secure Enclave: signing and decryption run inside the enclave, and the post-quantum family uses split custody (post-quantum components enclave-resident, classical components sealed to the device — neither half works alone).
- **Protected App Data** — App-data domains open after app privacy authentication through a shared Keychain root-secret gate plus Secure Enclave device binding: private-key control state, key metadata, protected settings, the protected Contacts database (SQLCipher), and the framework sentinel.
- **Two-Phase Decryption** — Phase 1 parses the message header and matches recipient keys without authentication. Phase 2 requires biometric/passcode auth before decryption proceeds.
- **Authentication Modes** — Standard Mode (Face ID / Touch ID with passcode fallback) or High Security Mode (biometric only, inspired by Apple's Stolen Device Protection).
- **Memory Safety** — Sensitive data is zeroed from memory after use. MIE (Memory Integrity Enforcement) is enabled via Xcode's Enhanced Security capability, providing hardware memory tagging on supported devices.
- **Privacy Screen** — Blur overlay when the app enters background. Configurable re-authentication grace period.
- **AEAD Hard-Fail** — Authentication failures in encrypted messages result in immediate failure with no plaintext fragments exposed.

For the complete security specification, see [docs/SECURITY.md](docs/SECURITY.md).

## User Workflows

- **Key Exchange** — QR code (via system Camera + URL scheme), Share Sheet (.asc file), or clipboard paste. Post-quantum public keys are too large for QR (~30 KB armored) and exchange via file, share sheet, or clipboard.
- **Text Encryption** — Select recipients, toggle encrypt-to-self and signature, encrypt, then copy or share the ciphertext.
- **File Encryption** — Pick a file, same flow as text. Produces binary `.gpg` output. Streaming I/O with progress reporting. Cancellable. File size validated against available disk space at runtime.
- **Decryption** — Paste or import ciphertext → two-phase flow → biometric auth → plaintext displayed in memory only, cleared on dismiss.
- **Signing & Verification** — Cleartext signatures for text, detached `.sig` for files. Auto-verification during decryption with graded results.
- **Backup & Restore** — Export passphrase-protected private key via Share Sheet (S2K protection matches the key's profile); device-bound keys are never exportable. Import from `.asc` file.

## Documentation

| Document | Description |
|----------|-------------|
| [PRD](docs/PRD.md) | Product requirements, key families, and workflows |
| [TDD](docs/TDD.md) | Technical design — profiles, formats, FFI, SE wrapping |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Module breakdown, data flows, storage layout |
| [SECURITY](docs/SECURITY.md) | Encryption scheme, key lifecycle, threat model |
| [SECURE_ENCLAVE_CUSTODY](docs/SECURE_ENCLAVE_CUSTODY.md) | Device-bound custody model, split custody, hardware evidence |
| [PERSISTED_STATE_INVENTORY](docs/PERSISTED_STATE_INVENTORY.md) | Row-level classification of all persisted state |
| [POST_QUANTUM](docs/POST_QUANTUM.md) | RFC 9980 design rationale and remaining scope |
| [TESTING](docs/TESTING.md) | Test lanes, commands, and validation workflow |
| [WORKFLOW](docs/WORKFLOW.md) | Development loop, "done" requirements, security gate, documentation contract |
| [RELEASE](docs/RELEASE.md) | Stable releases, Xcode Cloud flow, asset contract, SDK channels |
| [ARM64E_STATUS](docs/ARM64E_STATUS.md) | Pinned arm64e stage1 toolchain and re-pin rule |

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
