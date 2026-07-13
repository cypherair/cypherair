# CypherAir Agent Guide

CypherAir is an offline OpenPGP encryption app for Apple platforms.

This file is the Codex-facing agent guide. `CLAUDE.md` is maintained separately
for Claude-facing sessions; keep shared project constraints semantically
aligned, but do not force the two files to be identical. Canonical project docs
live under `docs/`. `docs/ARM64E_STATUS.md` owns Apple arm64e support and pinned
stage1 toolchain policy.

## Project Snapshot

- **Platforms:** iOS 26.5+, iPadOS 26.5+, macOS 26.5+, visionOS 26.5+. Minimum
  device: 8 GB RAM.
- **Language:** Apple Swift 6.3.2, SwiftUI, and Rust stable. `SWIFT_VERSION =
  6.0` is the Swift language mode, not the compiler release.
- **OpenPGP:** Sequoia PGP 2.4.0 through the Rust `pgp-mobile` wrapper and
  Mozilla UniFFI 0.31.x.
- **Key families:** Nine families combining message compatibility with
  private-key custody — Portable Legacy (Ed25519 v4, GnuPG-compatible), Portable
  Modern (Ed25519+X25519 v6), Portable Modern · High (Ed448+X448 v6), Portable
  Post-Quantum (RFC 9980 ML-DSA-65/ML-KEM-768), Portable Post-Quantum · High (RFC
  9980 ML-DSA-87/ML-KEM-1024), Device-Bound Legacy (Secure Enclave P-256 v4),
  Device-Bound Modern (Secure Enclave P-256 v6), Device-Bound Post-Quantum (RFC
  9980 split custody), and Device-Bound Post-Quantum · High (RFC 9980 split
  custody). The descriptive family names are the technical vocabulary; the retired
  "Profile A"/"Profile B" labels mapped onto Portable Legacy (universal) and
  Portable Modern · High (advanced).
- **Security:** CryptoKit Secure Enclave P-256 key wrapping, Keychain, local
  authentication modes, ProtectedData app-data domains, Argon2id memory guard,
  and explicit memory zeroing.
- **Localization:** English and Simplified Chinese via `.xcstrings` String
  Catalog.

Architecture is Rust (`pgp-mobile`) -> UniFFI scaffolding -> Swift app:

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE wrapping, Keychain, auth modes, ProtectedData
├── Models/           # Data types, PGP key representations, error types
├── Extensions/       # Swift/Foundation extensions
├── PgpMobile/        # Generated UniFFI Swift bindings; do not hand-edit
└── Resources/        # Assets, String Catalog
pgp-mobile/           # Rust wrapper crate
docs/                 # PRD, TDD, architecture, security, testing, workflow, release
CypherAir-Info.plist  # Root-level app Info.plist source
```

Detailed module breakdown: `docs/ARCHITECTURE.md`.

## Build And Validation

```bash
# Full Rust + UniFFI + packaged-artifact sync; matches GitHub Actions.
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260618T140657Z-abeb845-r27765229620-a1 \
    ./build-xcframework.sh --release

# Run Rust tests.
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests locally.
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Run device-only tests (Secure Enclave, biometrics, MIE). These need a real
# Secure Enclave, not a specific iPhone: an Apple Silicon Mac runs the whole lane
# locally (the `platform=macOS` host has a Secure Enclave), and so does a physical
# iPhone/iPad. Only the iOS Simulator cannot run them. Biometric steps use Touch ID
# / the system auth prompt; biometric-gated tests skip when no biometric is enrolled.
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=macOS,arch=arm64e'          # Apple Silicon Mac (full lane, local)
# or a physical iOS device:
#   -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'

# Run targeted macOS UI smoke coverage.
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Run the native visionOS build probe.
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS'
```

For Rust changes under `pgp-mobile/src` that can affect Swift-visible behavior,
refresh the XCFramework and generated UniFFI bindings before Xcode validation.
Per-target cargo commands, stale-artifact troubleshooting, CI lanes, and docs-only
validation rules live in `docs/TESTING.md`. The pinned
`ARM64E_STAGE1_RELEASE_TAG` value is owned by `docs/ARM64E_STATUS.md` and rotates
with each stage1 re-pin.

Use your judgment on tests — you don't need to justify each one or test
everything. A test worth writing guards behavior a later change could quietly
break; an empty one just restates the code or exists because a test felt
expected. Write the first kind freely, skip the second; most changes need none.
Secure Enclave and biometric code must guard with `SecureEnclave.isAvailable`
and skip in simulator.

When Xcode MCP or Apple documentation tools are available, prefer live Apple
documentation lookup for API behavior instead of relying on memory.

## Hard Constraints - Never Violate

1. **Zero network access.** No HTTP(S), networked SDKs, telemetry, URL loading,
   `NWConnection`, or `URLSession`.
2. **Minimal permissions.** The app configures only `NSFaceIDUsageDescription`
   for LocalAuthentication-backed biometric flows. No camera, photo library,
   contacts, or network entitlements. All I/O goes through system pickers, Share
   Sheet, or URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort
   immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or
   `NSLog()` key material, passphrases, or decrypted content.
5. **Memory zeroing.** Sensitive `Data` buffers containing keys, passphrases, or
   plaintext must be overwritten when no longer needed. Rust uses `zeroize`;
   Swift uses `resetBytes(in:)`.
6. **Secure random only.** Swift uses `SecRandomCopyBytes` or CryptoKit; Rust
   uses `getrandom`.
7. **MIE enabled.** Enhanced Security with Hardware Memory Tagging must remain
   enabled. Never remove the entitlements.
8. **Profile-correct message format.** Format is selected by recipient key
   version; never send SEIPDv2 to a v4 key holder.

## Security-Sensitive Work

You may edit security-critical areas directly, but the summary and PR description
must call out the file, what changed, and why. Security changes get human
review before merge. The authoritative
security-critical file list, rationale, and invariants live in
`docs/SECURITY.md` Section 10. Review gates live in `docs/WORKFLOW.md`.

## Code Style And Scope

Standard Swift/SwiftUI idiom applies (use live Apple documentation for current
API and Liquid Glass specifics). The project-specific rules — not inferable from
the code alone:

- Errors: `CypherAirError` is the app vocabulary; generated `PgpError` is
  normalized at the `Services/FFI/` adapter boundary before app/service code.
- Never edit generated `Sources/PgpMobile/pgp_mobile.swift`; where strict
  concurrency trips on it, `@preconcurrency import PgpMobile` at call sites.
- Views stay thin; workflow-heavy screens move async orchestration, cleanup, and
  transient state into an owning `@Observable` ScreenModel (`SignView` +
  `SignScreenModel` baseline).
- Design identity is quiet and system-native — system accent only, no brand
  tint. Reuse the `Sources/App/DesignSystem/` primitives instead of per-view
  literals.
- One type per file, grouped by feature; mocks under `Security/Mocks/`; all user
  strings in the String Catalog.
- Prefer architecturally correct fixes while keeping scope limited to the user
  request. Do not normalize, revert, or clean up unrelated local changes.

## Releases, Git, And Workflow

- Stable releases are tag-first per `docs/RELEASE.md`. Never treat
  `workflow_dispatch` alone as a substitute for the stable tag. Ask before
  publishing any release or tag.
- Bumping `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` is a normal in-scope
  part of preparing a release (`docs/RELEASE.md` Section 1); confirm the
  intended version with the maintainer before creating the release tag.
- Work on a topic branch and submit a PR. Do not commit directly to `main`
  unless the user explicitly asks.
- Do not set `autoResolutionMs` on `request_user_input` and wait for an
  explicit user response.
- Prefer regular merge commits over squash or rebase merges.
- Commits are SSH-signed and use conventional prefixes (`feat:`, `fix:`,
  `refactor:`, `test:`, `docs:`). If the agent has no signing identity, run
  `ssh-add --apple-load-keychain` and retry; never create an unsigned commit.
- Do not run destructive git operations on project files (`*.pbxproj`,
  `*.entitlements`, `*.xctestplan`, `*.xcscheme`) without explicit user
  approval.
