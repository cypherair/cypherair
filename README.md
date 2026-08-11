# CypherAir X

**Fully offline OpenPGP encryption for Apple platforms — zero network, minimal permissions.** CypherAir X is an open-source OpenPGP tool for people who want to communicate securely without cryptographic knowledge: encrypt, decrypt, sign, and verify, with keys and contacts managed entirely on device. It is a SwiftUI app over a Rust OpenPGP engine (Sequoia PGP) bridged through UniFFI.

- **Platforms** — iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+; 8 GB RAM minimum.
- **Zero network access** — no HTTP(S), no networked SDKs, no telemetry, no update checks; the app works in airplane mode. The evidence chain lives in [docs/SECURITY.md](docs/SECURITY.md).
- **One usage description** — `NSFaceIDUsageDescription`, for local biometric authentication, injected from the `INFOPLIST_KEY_NSFaceIDUsageDescription` build setting in `CypherAir.xcodeproj` (`CypherAir-Info.plist` declares none). No camera, photo library, contacts, or network permission; any other entitlement in the project is a resource, sandbox, or hardening entitlement, not a privacy permission.
- **Nine key families** — five portable (software custody, exportable) and four device-bound (Secure Enclave custody, never exportable), chosen at key generation and immutable per key. Canon: `Sources/Models/Keys/PGPKeyFamily.swift`; promises: [docs/PRODUCT.md](docs/PRODUCT.md); custody: [docs/CUSTODY.md](docs/CUSTODY.md).

## Build

### Prerequisites

- macOS on Apple Silicon with Xcode; pinned development and release toolchain versions are in [CLAUDE.md](CLAUDE.md) "Tech Stack".
- Rust stable with the five Apple targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin aarch64-apple-visionos aarch64-apple-visionos-sim`
- **Steps 2 and 3 need network access** — they download and verify pinned prebuilt artifacts. Zero-network is a property of the shipped app, not of its build toolchain.

### Xcode MCP

The repository ships a project-level `.mcp.json` configuring an `xcode` MCP server (`/usr/bin/xcrun mcpbridge`), which gives agent sessions Apple Developer Documentation search and build/diagnostic tools. Other MCP-capable agents configure the equivalent server command.

### Commands

```bash
# 1. Validate Rust behavior
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# 2. Refresh the XCFramework and generated bindings that Xcode links (git-ignored
# build outputs; a fresh clone cannot build until this runs). The script defaults
# to the current arm64e stage1 pin (docs/ARM64E_STATUS.md), never `latest`.
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release

# 3. Restore the pinned SQLCipher dependency (git-ignored artifact, attested on fetch)
scripts/restore_sqlcipher_xcframework.sh

# 4. Validate Swift unit + FFI behavior locally
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# 5. Probe the native visionOS app build
xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS'
```

Secure Enclave, biometric, and MIE coverage runs on real hardware — an Apple Silicon Mac or a physical device — via the `CypherAir-DeviceTests` plan; macOS UI smoke coverage via `CypherAir-MacUITests`. There is no dedicated visionOS test plan; the build probe above plus the Rust and macOS lanes cover it. Lanes and plans: [docs/TESTING.md](docs/TESTING.md). Release flow, published artifacts, and stale-artifact troubleshooting: [docs/BUILD.md](docs/BUILD.md).

## Documentation

- [PRODUCT](docs/PRODUCT.md) — product promises, deliberate non-features, consent gates, compatibility
- [SECURITY](docs/SECURITY.md) — threat model, fail-closed rules, authentication, coding red lines
- [CUSTODY](docs/CUSTODY.md) — per-family custody, access control, split custody, interop position
- [STORAGE](docs/STORAGE.md) — storage posture, protected domains, documented exceptions, envelope version map
- [ARCHITECTURE](docs/ARCHITECTURE.md) — layer boundaries and the Rust/FFI contract rules
- [BUILD](docs/BUILD.md) — stable release flow, published artifacts, arm64e toolchain contract, carry chains, and the Rust↔Xcode sync contract
- [TESTING](docs/TESTING.md) — test layers, plans, and CI lanes
- [WORKFLOW](docs/WORKFLOW.md) — development loop, "done" requirements, security gate, documentation contract
- [ARM64E_STATUS](docs/ARM64E_STATUS.md) — the machine-parsed arm64e stage1 pin

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
