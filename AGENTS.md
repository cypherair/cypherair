# CypherAir Agent Guide

This file is the agent-oriented companion to `CLAUDE.md`. It exists so coding agents can quickly understand the project, constraints, sensitive boundaries, and required validation steps before making changes.

## Arm64e Experiment Context

- Local path: `/Users/tianren/coding/cypherair-apple-arm64e-unified-experiment`
- Git shape: this directory is a **git worktree**, not a standalone clone.
- Owning repository path: `/Users/tianren/coding/cypherair-main`
- Local experiment branch in this worktree: `codex/apple-arm64e-unified-experiment`
- Remote repository: `cypherair/cypherair`
- Remote experiment branch: `origin/codex/apple-arm64e-unified-experiment`
- Current purpose: this worktree is the app-side integration branch for the Apple `arm64e` effort. The app-side adaptation is basically working here; the remaining work is keeping the experiment branch current with `main`, maintaining the dependency chain, and upstreaming the supporting forks, especially Rust.
- Detailed arm64e status belongs in [docs/ARM64E_STATUS.md](docs/ARM64E_STATUS.md). Keep that file current whenever the branch topology, carry chain, toolchain pin, or progress changes.

## Related Forks

- Rust fork: `/Users/tianren/coding/rust` (`cypherair/rust`, experiment branch `codex/arm64e-darwin-ptrauth-spike`)
- OpenSSL glue fork: `/Users/tianren/coding/openssl-src-rs` (`cypherair/openssl-src-rs`, carry branch `carry/apple-arm64e-openssl-fork`)
- OpenSSL target-definition fork: `/Users/tianren/coding/openssl` (`cypherair/openssl`, carry branch `carry/apple-arm64e-targets`, prep branch `prep/apple-arm64e-targets`)
- Related but currently unconfirmed arm64e role: `/Users/tianren/coding/rust-openssl` (`cypherair/rust-openssl`)

## Documentation Scope

- Update experiment-specific arm64e documentation in this worktree, not in `/Users/tianren/coding/cypherair-main`.
- Prefer additive edits and clarified wording over large deletions in this worktree so future experiment-to-main reconciliation stays manageable.

## Project Overview

CypherAir is a fully offline OpenPGP encryption app for iOS, iPadOS, macOS, and visionOS.

- License: `GPL-3.0-or-later OR MPL-2.0` for first-party code
- Privacy model: zero network access
- Permissions model: minimal permissions, only biometric usage description
- Cryptography: Sequoia PGP via Rust + UniFFI + Swift
- Platforms: iOS 26.4+, iPadOS 26.4+, macOS 26.4+, visionOS 26.4+

## Tech Stack

- Swift 6.2
- SwiftUI with iOS 26 Liquid Glass conventions where applicable and native platform chrome elsewhere
- Rust stable
- `sequoia-openpgp` 2.2.0 with `crypto-openssl`
- UniFFI 0.31.x
- CryptoKit + Security.framework

## Repository Layout

```text
Sources/
├── App/              # SwiftUI views, onboarding, navigation, app wiring
├── Services/         # Encryption, signing, keys, contacts, QR, self-test
├── Security/         # Secure Enclave wrapping, Keychain, auth mode logic
├── Models/           # Data models and error types
├── Extensions/       # Small Foundation/Swift helpers
└── Resources/        # String catalogs, previews

pgp-mobile/           # Rust wrapper crate
docs/                 # PRD, architecture, testing, conventions, security
CypherAir-Info.plist  # Root-level app Info.plist source
```

Start with `docs/ARCHITECTURE.md` and `docs/SECURITY.md` when working in unfamiliar areas.

## Build Commands

```bash
# Rust builds
cargo build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-visionos --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-visionos-sim --manifest-path pgp-mobile/Cargo.toml

# Full Rust + UniFFI + packaged-artifact sync
./build-xcframework.sh --release

# Rust tests
cargo test --manifest-path pgp-mobile/Cargo.toml

# macOS-local Swift unit + FFI validation
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Device-only tests
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'

# Targeted macOS UI smoke coverage for routes, settings, and tutorial flows
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Native visionOS build probe
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

There is currently no dedicated visionOS XCTest test plan. Native visionOS validation uses the build probe above together with the existing Rust, macOS-local, and iOS-device validation paths.

For the full Rust artifact refresh, UniFFI/bindings sync, XCFramework linkage details, and Xcode validation workflow, see `docs/TESTING.md`.

## Non-Negotiable Constraints

Never violate these:

1. Zero network access.
   No `URLSession`, HTTP(S), telemetry, update checks, sockets, or network SDKs.
2. Minimal permissions.
   Only biometric usage description is allowed. No camera/photo/contact/network permissions.
3. AEAD hard-fail.
   Decryption authentication failure must abort without exposing partial plaintext.
4. No plaintext/private-key logging.
   No `print`, `os_log`, `NSLog`, or debug logging of secrets or decrypted data.
5. Memory zeroing for sensitive buffers.
   Swift: `Data.resetBytes(in:)`. Rust: `zeroize`.
6. Secure randomness only.
   Swift: `SecRandomCopyBytes` or CryptoKit. Rust: `getrandom`/Sequoia crypto randomness.
7. Keep MIE/Enhanced Security capability enabled.
8. Preserve profile-correct message format selection.
   v4 recipient -> SEIPDv1, v6 recipient -> SEIPDv2, mixed -> SEIPDv1.

## Sensitive Boundaries

Pause and explicitly call out the intended change before editing these areas:

- `Sources/Security/` — SE wrapping, Keychain access, auth mode logic
- `Sources/Security/SecureEnclaveManager.swift` — wrapping/unwrapping flow
- `Sources/Security/KeychainManager.swift` — access control flags
- `Sources/Security/AuthenticationManager.swift` — Standard/High Security mode switching
- `Sources/Services/DecryptionService.swift` — Phase 1/Phase 2 authentication boundary
- `Sources/Services/QRService.swift` — external URL input parsing (untrusted data)
- `pgp-mobile/src/` — any Rust cryptographic code
- `CypherAir.xcodeproj/project.pbxproj` and other Xcode project files — adding files, targets, build settings, or test wiring
- `CypherAir.entitlements` — capability entitlements
- `CypherAirMacOS.entitlements` — macOS capability entitlements
- `CypherAir-Info.plist` — permission descriptions (only `NSFaceIDUsageDescription` permitted)

These areas define security invariants and failure behavior.

## Crypto / Product Model

### Profiles

- Profile A, Universal
  v4, Ed25519 + X25519, SEIPDv1, Iterated+Salted S2K, broad interoperability
- Profile B, Advanced
  v6, Ed448 + X448, SEIPDv2 AEAD, Argon2id S2K, not GnuPG compatible

### Authentication Modes

- Standard
  Biometrics with passcode fallback
- High Security
  Biometrics only, no passcode fallback

Mode switching requires re-wrapping all Secure Enclave protected keys.

## Working Style

- Read relevant files before editing.
- Keep changes scoped to the user request.
  This means only make changes that are directly required to complete the requested task; it is not permission to normalize, revert, or clean up unrelated local changes that are already in the worktree.
- Do not add “nice to have” refactors unless they directly support the requested work.
- In Plan mode only, for build-system, Xcode-project, packaging, or other high-coupling changes where toolchain behavior is a material risk, prefer validating the approach first in an isolated temporary copy or other disposable prototype environment before editing the real workspace.
- Prefer small, reviewable diffs.
- Maintain existing user-visible behavior unless the task explicitly changes it.
- Treat `pgp_mobile.swift` as generated code. Do not hand-edit it.

## Release Metadata / Build Numbers

Treat Xcode release metadata as user-owned state. Do not modify, normalize, revert, or lower `CURRENT_PROJECT_VERSION` or `MARKETING_VERSION` unless the user explicitly asks for a version or build-number change.

If the user asks to increment the build number, first read the current `CURRENT_PROJECT_VERSION`, then increment it by 1 unless the user specifies an exact value. Never decrease `CURRENT_PROJECT_VERSION` or `MARKETING_VERSION`. If these fields already have uncommitted changes, treat them as user edits; do not revert, overwrite, or reinterpret them unless the user explicitly asks.

## Coding Conventions

- Swift API Design Guidelines. `guard` early exits over force unwraps. `async/await` over Combine.
- `@Observable` for state. `NavigationStack` with typed paths. No `NavigationView`.
- Use iOS 26 Liquid Glass conventions where applicable, and prefer platform-native SwiftUI chrome on macOS and visionOS. Custom controls use `.glassEffect()` only when the API is available and matches platform conventions.
- One type per file. Group by feature. All user strings in the String Catalog.
- Full conventions: `docs/CONVENTIONS.md`.

## Testing Expectations

- Every change should preserve both Rust and Swift validation where relevant.
- Crypto behavior changes must be tested for both profiles.
- Add negative tests for failure paths, not only happy paths.
- Secure Enclave / biometric tests must be guarded for real hardware availability.
- Rust changes under `pgp-mobile/src` do **not** automatically refresh the `PgpMobile.xcframework` artifact or generated UniFFI outputs that Xcode uses for Swift/FFI tests.
- If a Rust change can affect Swift-visible behavior, run `./build-xcframework.sh --release` before running `xcodebuild test`.
- See `docs/TESTING.md` for the full Rust↔Xcode validation workflow and stale-artifact troubleshooting.
- For route ownership, launch, tutorial-host, or macOS UI workflow changes, also run `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` or an equivalent targeted smoke subset.

At minimum after meaningful code changes:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
```

### GitHub Actions Note

The repository workflows target `macos-26`, but GitHub-hosted runner images may temporarily lag the project's minimum deployment target. At the moment, hosted Swift CI can still fail before tests start because the runner image reports **macOS 26.3** while the project targets **macOS 26.4**. Local `xcodebuild test ... -destination 'platform=macOS'` remains the source of truth until the hosted image catches up or a self-hosted runner is used.

## Agent Checklist

Before editing:

- Read the relevant implementation files
- Check `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/TESTING.md` when touching core flows
- Confirm whether the change crosses a sensitive boundary
- In Plan mode, if the task changes build/link/package topology or Xcode wiring, consider a disposable prototype run first to prove feasibility before touching the real project files

After editing:

- Run the relevant tests
- Verify no generated file was unintentionally hand-modified
- Check `git diff --stat` and `git diff`
- Update `docs/ARM64E_STATUS.md` if the arm64e toolchain chain, branch relationships, or progress changed

## Workflow Reminders

- Do not use destructive git operations on project files without explicit approval.
- Before string replacement, verify match counts.
- After revert operations, verify with `git diff`.
- Build success is not enough; run tests.
- When merging pull requests for this repository, prefer a regular merge commit by default. Do not squash-merge or rebase-merge unless the user explicitly asks for it.
- Conventional commit prefixes are preferred:
  `feat:`, `fix:`, `refactor:`, `test:`, `docs:`
- Keep `docs/ARM64E_STATUS.md` synchronized with the current patched Rust toolchain pin, the OpenSSL carry-chain pin, and the experiment-vs-main branch posture.

## Key References

- `CLAUDE.md`
- `docs/ARM64E_STATUS.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/TESTING.md`
- `docs/CONVENTIONS.md`
- `docs/CODE_REVIEW.md`
