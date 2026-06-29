# CypherAir

**Fully offline OpenPGP encryption for Apple platforms — zero network, minimal permissions.**

CypherAir is an open-source OpenPGP encryption tool for iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+. It enables everyday users to communicate securely with friends, preventing message content from being monitored by third parties. The app operates with absolutely zero network access and uses only the biometric usage description needed for local authentication — data leakage is eliminated at the architectural level.

## Key Features

- **Truly Offline** — No HTTP(S), no networked SDKs, no update checks. Works fully in airplane mode.
- **Minimal Permissions** — Only the biometric usage description is configured for local authentication. No camera, photo library, contacts, or network permissions. All I/O goes through system-provided pickers and the Share Sheet.
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
| Platform | iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+, minimum 8 GB RAM |
| Language | Apple Swift 6.3.2, SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere), UIKit for system pickers |
| OpenPGP Engine | Sequoia PGP 2.3.0 (Rust), `crypto-openssl` backend (vendored) |
| FFI Bridge | Mozilla UniFFI 0.31.x; Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap` |
| SQLCipher | Formal pinned external `SQLCipher.xcframework` 4.16.0 static library from `cypherair/sqlcipher-xcframework`; restored as an ignored artifact and linked by the app target |
| Security | CryptoKit (Secure Enclave), Security.framework (Keychain) |
| Build | Xcode 26.5, Rust stable, targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`; `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release |
| Localization | English + Simplified Chinese (.xcstrings) |

## Architecture

CypherAir is a three-layer application: a SwiftUI presentation layer, a Swift services layer, and a Rust cryptographic engine bridged via UniFFI.

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE wrapping, Keychain, auth modes, ProtectedData, memory zeroing
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

## Current Internal Architecture

The current app structure keeps maintainability and safety work behind stable user-facing cryptographic behavior:

- **Shared recovery infrastructure** — Secure Enclave / Keychain migration and crash-recovery logic now runs through shared transaction helpers instead of being duplicated across services.
- **Safer recovery semantics** — Crash recovery now explicitly prefers authoritative envelope rows over stale pending rows, distinguishes retryable vs unrecoverable recovery failures, and feeds generic startup diagnostics into the existing warning surface.
- **Shared operation controllers** — Encrypt, decrypt, sign, and verify flows now reuse common helpers for security-scoped file access, export, cancellation, progress, and clipboard behavior.
- **Cleaner startup wiring** — App dependency construction and startup recovery live in a dedicated container/coordinator instead of the app entry point.
- **Shared identity presentation helpers** — Fingerprint formatting and accessibility labels are defined once and reused across the UI.
- **Focused validation** — Recovery, tutorial, routing, protected-data, and warning-hygiene tests cover the current safety-critical app workflows.

## Build

### Prerequisites

- macOS (Apple Silicon) with Xcode 26.5
- Rust stable (latest) with targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-visionos aarch64-apple-visionos-sim`

### Xcode MCP

Xcode's MCP server can provide Apple Developer Documentation search and
build/diagnostic tools to agent sessions. This repository ships a project-level
`.mcp.json` that configures an `xcode` server running `/usr/bin/xcrun mcpbridge`;
Claude Code picks it up automatically. To use it, open this project in Xcode
(26.3 or newer), enable Xcode Settings → Intelligence → Xcode Tools under Model
Context Protocol, and keep Xcode running. For other MCP-capable agents,
configure the equivalent server:

```json
{
  "mcpServers": {
    "xcode": {
      "command": "/usr/bin/xcrun",
      "args": ["mcpbridge"]
    }
  }
}
```

Restart the agent session after changing MCP configuration and confirm that
`DocumentationSearch` is available.

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

# 3. Restore the pinned SQLCipher external dependency used by Xcode.
# The artifact is ignored by git; Contacts storage is not yet SQLCipher-backed.
scripts/restore_sqlcipher_xcframework.sh

# 4. Validate Swift unit + FFI behavior locally
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# 5. Probe the native visionOS app build
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS'
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

The GitHub Actions workflows in this repository currently target `macos-26`, but GitHub's hosted runner image may still lag the project's minimum deployment target or expose Xcode before all matching platform runtimes are usable. In that situation:

- Rust CI can still pass normally.
- The hosted Swift unit-test preview and Apple platform probes use repository preflight scripts to skip known hosted-image/runtime mismatches with explicit warnings.
- Project, build, link, or test failures after preflight readiness remain real failure signals.
- Local validation using `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` should be treated as the source of truth until GitHub's hosted macOS image catches up.

### XCFramework Prerelease

CypherAir publishes unique edge prerelease XCFrameworks for the current `main` branch using `pgpmobile-edge-` release tags. For discovery, asset names, download commands, verification steps, and the current stable-release channel contract, see [docs/XCFRAMEWORK_RELEASES.md](docs/XCFRAMEWORK_RELEASES.md).

### SQLCipher External Dependency

CypherAir also consumes a pinned stable SQLCipher static framework-shaped
XCFramework from the separate public build-wrapper repository
`cypherair/sqlcipher-xcframework`. The main repository does not commit
`SQLCipher.xcframework` or downloaded release assets; local and CI builds
restore them with `scripts/restore_sqlcipher_xcframework.sh`, verify the pinned
immutable release, checksum, manifest, asset attestations, and restored static
framework slices before Xcode builds. The app consumes SQLCipher through Xcode's
normal Frameworks phase, not slice-specific linker paths. Refreshes must be
published in `cypherair/sqlcipher-xcframework` first, then re-pinned in
`third_party/sqlcipher-xcframework.pin.json`. Contacts storage still uses the
current ProtectedData domain until the later issue #540 implementation.

## Security Model

CypherAir's security design centers around several layers of protection:

- **Private Key Storage** — Keys are sealed in an authenticated envelope using ephemeral-static P-256 ECDH against a per-key Secure Enclave key, with HKDF + AES-GCM and public-parameter AAD binding, then stored as a single Keychain row. Keys are device-bound and never leave the hardware.
- **Protected App Data** — Implemented app-data domains open after app privacy authentication through a shared Keychain root-secret gate plus Secure Enclave device binding. Current protected domains cover private-key control state, key metadata, protected settings schema v2, protected Contacts domain data, and the framework sentinel.
- **Two-Phase Decryption** — Phase 1 parses the message header and matches recipient keys without authentication. Phase 2 requires biometric/passcode auth before decryption proceeds.
- **Authentication Modes** — Standard Mode (Face ID / Touch ID with passcode fallback) or High Security Mode (biometric only, inspired by Apple's Stolen Device Protection).
- **Memory Safety** — Sensitive data is zeroed from memory after use. MIE (Memory Integrity Enforcement) is enabled via Xcode's Enhanced Security capability, providing hardware memory tagging on supported A19/A19 Pro-or-newer devices.
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
| [APP_RELEASE_PROCESS](docs/APP_RELEASE_PROCESS.md) | Current app-build release modes, stable asset contract, and App Store candidate ordering |
| [DOCUMENTATION_GOVERNANCE](docs/DOCUMENTATION_GOVERNANCE.md) | Documentation classes, metadata rules, archive rules, and update triggers |
| [POC](docs/archive/POC.md) | Proof-of-concept test plan (archived) |
| [CONVENTIONS](docs/CONVENTIONS.md) | Swift coding standards, SwiftUI patterns, and current Liquid Glass rules |
| [CODE_REVIEW](docs/CODE_REVIEW.md) | Code review checklist by change type |
| [XCFRAMEWORK_RELEASES](docs/XCFRAMEWORK_RELEASES.md) | Current edge, drill, and stable XCFramework release channels and verification |
| [SQLCIPHER_XCFRAMEWORK_DEPENDENCY](docs/SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md) | Formal pinned external SQLCipher XCFramework dependency and refresh flow |

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

Current stable app-build release ordering and exact source/compliance asset expectations are documented in [docs/APP_RELEASE_PROCESS.md](docs/APP_RELEASE_PROCESS.md) and [docs/XCFRAMEWORK_RELEASES.md](docs/XCFRAMEWORK_RELEASES.md).
