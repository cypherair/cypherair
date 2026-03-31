# CypherAir Agent Guide

This file is the agent-oriented companion to `CLAUDE.md`. It exists so coding agents can quickly understand the project, constraints, sensitive boundaries, and required validation steps before making changes.

## Project Overview

CypherAir is a fully offline OpenPGP encryption app for iOS, iPadOS, and macOS.

- License: GPLv3
- Privacy model: zero network access
- Permissions model: minimal permissions, only biometric usage description
- Cryptography: Sequoia PGP via Rust + UniFFI + Swift
- Platforms: iOS 26.4+, iPadOS 26.4+, macOS 26.4+

## Tech Stack

- Swift 6.2
- SwiftUI with iOS 26 Liquid Glass conventions
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
└── Resources/        # String catalogs, previews, Info.plist resources

pgp-mobile/           # Rust wrapper crate
docs/                 # PRD, architecture, testing, conventions, security
```

Start with `docs/ARCHITECTURE.md` and `docs/SECURITY.md` when working in unfamiliar areas.

## Build Commands

```bash
# Rust builds
cargo build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml
cargo build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml

# Recommended XCFramework build path
./build-xcframework.sh --release

# Rust tests
cargo test --manifest-path pgp-mobile/Cargo.toml

# Swift unit + FFI tests
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'

# macOS-local validation often used in this repo
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Device-only tests
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'
```

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

- `Sources/Security/`
- `Sources/Security/SecureEnclaveManager.swift`
- `Sources/Security/KeychainManager.swift`
- `Sources/Security/AuthenticationManager.swift`
- `Sources/Services/DecryptionService.swift`
- `Sources/Services/QRService.swift`
- `pgp-mobile/src/`
- `CypherAir.entitlements`
- `CypherAirMacOS.entitlements`
- permission-related plist settings

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
- Do not add “nice to have” refactors unless they directly support the requested work.
- Prefer small, reviewable diffs.
- Maintain existing user-visible behavior unless the task explicitly changes it.
- Treat `pgp_mobile.swift` as generated code. Do not hand-edit it.

## Coding Conventions

- Follow Swift API Design Guidelines.
- Prefer `guard` early exits.
- No force unwraps in production paths.
- Use `async/await`.
- Use `@Observable` for app state models/services.
- Use `NavigationStack`, not deprecated `NavigationView`.
- Put user-facing strings in the String Catalog.
- Respect `docs/CONVENTIONS.md` for full project rules.

## Testing Expectations

- Every change should preserve both Rust and Swift validation where relevant.
- Crypto behavior changes must be tested for both profiles.
- Add negative tests for failure paths, not only happy paths.
- Secure Enclave / biometric tests must be guarded for real hardware availability.

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

After editing:

- Run the relevant tests
- Verify no generated file was unintentionally hand-modified
- Check `git diff --stat` and `git diff`

## Workflow Reminders

- Do not use destructive git operations on project files without explicit approval.
- Before string replacement, verify match counts.
- After revert operations, verify with `git diff`.
- Build success is not enough; run tests.
- Conventional commit prefixes are preferred:
  `feat:`, `fix:`, `refactor:`, `test:`, `docs:`

## Key References

- `CLAUDE.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/TESTING.md`
- `docs/CONVENTIONS.md`
- `docs/CODE_REVIEW.md`
