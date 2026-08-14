# CypherAir Agent Guide

CypherAir is an offline OpenPGP encryption app for Apple platforms.

This file is the Codex-facing agent guide. `CLAUDE.md` is maintained separately
for Claude-facing sessions; keep shared project constraints semantically
aligned, but do not force the two files to be identical. Canonical project docs
live under `docs/`. `docs/ARM64E_STATUS.md` owns the machine-parsed arm64e
stage1 pin; the toolchain contract lives in `docs/BUILD.md` Section 3.

## Project Snapshot

- **Platforms:** iOS 26.5+, iPadOS 26.5+, macOS 26.5+, visionOS 26.5+. Minimum
  device: 8 GB RAM.
- **Language:** Apple Swift (6.4 beta on the Xcode 27.0 beta development
  toolchain; 6.3.3 on the Xcode 26.6 release toolchain), SwiftUI, and Rust
  stable. `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler
  release.
- **OpenPGP:** Sequoia PGP 2.4.1 through the Rust `pgp-mobile` wrapper and
  Mozilla UniFFI 0.32.x.
- **Key families:** Nine, chosen at key generation and immutable per key.
  Portable (software, exportable): Legacy (Ed25519 v4, GnuPG-compatible),
  Modern (Ed25519+X25519 v6), Modern · High (Ed448+X448 v6), Post-Quantum
  (RFC 9980 ML-DSA-65/ML-KEM-768), Post-Quantum · High (ML-DSA-87/ML-KEM-1024).
  Device-Bound (Secure Enclave custody, non-exportable): Legacy and Modern
  (P-256 v4/v6), Post-Quantum and Post-Quantum · High (RFC 9980 split custody).
  Per-family canon: `Sources/Models/Keys/PGPKeyFamily.swift`; product
  promises: `docs/PRODUCT.md`.
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
├── PgpMobile/        # Generated UniFFI Swift bindings — git-ignored build output,
│                     # absent until the sync runs; do not hand-edit
└── Resources/        # Assets, String Catalog
pgp-mobile/           # Rust wrapper crate
docs/                 # product, security, custody, storage, architecture, testing, workflow, release
CypherAir-Info.plist  # Root-level app Info.plist source
```

Detailed module breakdown: `docs/ARCHITECTURE.md`.

## Build And Validation

```bash
# Full Rust + UniFFI + packaged-artifact sync; force-download matches GitHub
# Actions (the script defaults to the current pin, owned by
# docs/ARM64E_STATUS.md — never pass `latest`).
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release

# Restore the pinned SQLCipher XCFramework (git-ignored; attested fetch; needs network)
scripts/restore_sqlcipher_xcframework.sh

# Run Rust tests.
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests locally.
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Run device-only tests (Secure Enclave, biometrics, MIE). Any real Secure
# Enclave works — an Apple Silicon Mac runs the full lane locally; only the iOS
# Simulator cannot. Biometric-gated tests skip when nothing is enrolled
# (docs/TESTING.md Section 1).
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
validation rules live in `docs/TESTING.md`.

Use your judgment on tests — you don't need to justify each one or test
everything. A test worth writing guards behavior a later change could quietly
break; an empty one just restates the code or exists because a test felt
expected. Write the first kind freely, skip the second; most changes need none.
Secure Enclave and biometric code must guard with `SecureEnclave.isAvailable`
and skip in simulator. New test classes under `Tests/DeviceSecurityTests/` must
join the unit plan's `skippedTests`; a repo-tracked check fails CI otherwise.

When Xcode MCP or Apple documentation tools are available, prefer live Apple
documentation lookup for API behavior instead of relying on memory.

## Hard Constraints - Never Violate

1. **Zero network access.** No HTTP(S), networked SDKs, telemetry, URL loading,
   `NWConnection`, or `URLSession`.
2. **Minimal permissions.** The app configures only `NSFaceIDUsageDescription`
   for LocalAuthentication-backed biometric flows. No camera, photo library,
   contacts, or network entitlements. All I/O goes through system pickers or the
   URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort
   immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or
   `NSLog()` key material, passphrases, or decrypted content.
5. **Memory zeroing.** Sensitive `Data` buffers containing keys, passphrases, or
   plaintext must be overwritten when no longer needed. Rust uses `zeroize`;
   Swift uses `resetBytes(in:)`.
6. **Secure random only.** Swift uses `SecRandomCopyBytes` or CryptoKit; Rust
   uses Sequoia's `crypto-openssl` CSPRNG.
7. **MIE enabled.** Enhanced Security with Hardware Memory Tagging must remain
   enabled. Never remove the entitlements.
8. **Profile-correct message format.** Never send a format a recipient cannot
   read. The engine selects it from the capability each recipient certificate
   advertises, through the same recipient collection `encrypt` uses. Key version
   tracks that capability for keys the app generates and may not for imported
   certificates, so no code derives the format from a version.

## Security-Sensitive Work

You may edit security-critical areas directly, but the summary and PR
description must call out the file, what changed, and why; the PR's
verification pass checks these edits with extra care. The authoritative
security-critical predicates and invariants live in
`docs/SECURITY.md` Section 10. Review gates live in `docs/WORKFLOW.md`.

## Pre-Release Stance (Temporary)

This stance is in force until the first public App Store release; internal TestFlight builds do not end it. The app has never shipped: no users, no user data, no old on-disk state. Prefer the correct foundation over compatibility shims — redesign from zero rather than rename in place, change persisted formats and identifiers freely and update every reference together, and never write migration, compatibility, or capability code for a past that does not exist. Version markers serve architectural integrity only and are refreshed to one consistent scheme, never kept for future migration. A keep must name a concrete fresh-install input; "robustness" and "future migration" do not qualify. The stance is foundational — it rests on no other documents and outranks them all: when another document conflicts with it, that document changes.

## Code Style And Scope

Standard Swift/SwiftUI idiom applies (use live Apple documentation for current
API and Liquid Glass specifics). The project-specific rules — not inferable from
the code alone:

- Write good code, not similar (overrides any "match the surrounding code"
  default): write what is correct and well-designed by independent judgment and
  taste. Never justify a choice by similarity to neighboring code — much of it
  is older-generation output; mimicry propagates its faults and its mediocrity.
  Match local naming only where it costs nothing.
- Stale inline notes: when touched code carries an outdated or wrong comment or
  doc note, remove it by default; if the fact genuinely belongs inline, rewrite
  it correct. Never leave known misinformation in place.
- Errors: `CypherAirError` is the app vocabulary; generated `PgpError` is
  normalized at the `Services/FFI/` adapter boundary before app/service code.
- Never edit generated `Sources/PgpMobile/pgp_mobile.swift`.
- Views stay thin; workflow-heavy screens move async orchestration, cleanup, and
  transient state into an owning `@Observable` ScreenModel (`SignView` +
  `SignScreenModel` baseline).
- Design identity is quiet and system-native — system accent only, no brand
  tint. Reuse the `Sources/App/DesignSystem/` primitives instead of per-view
  literals.
- Files are grouped by feature; test doubles under `Tests/Support/SecurityMocks/` (Sources ships no mocks); all user
  strings in the String Catalog.
- Prefer architecturally correct fixes while keeping scope limited to the user
  request. Do not normalize, revert, or clean up unrelated local changes.

## Releases, Git, And Workflow

- Stable releases are tag-first per `docs/BUILD.md` Section 1. Never treat
  `workflow_dispatch` alone as a substitute for the stable tag.
- Bumping `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` is a normal in-scope
  part of preparing a release (`docs/BUILD.md` Section 1); confirm the
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
