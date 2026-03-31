# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, and macOS. GPLv3. Zero network access. Minimal permissions (Face ID / Touch ID usage description only).

## Tech Stack

- **Platform:** iOS 26.4+ / iPadOS 26.4+ / macOS 26.4+. Minimum device: 8 GB RAM.
- **Language:** Swift 6.2, SwiftUI (iOS 26 Liquid Glass design). UIKit only for system pickers.
- **OpenPGP:** Sequoia PGP 2.2.0 (Rust, LGPL-2.0-or-later, compatible with App's GPLv3) with `crypto-openssl` backend (vendored static linking).
- **Profiles:** Profile A (Universal): v4 keys, Ed25519+X25519, SEIPDv1. Profile B (Advanced): v6 keys, Ed448+X448, SEIPDv2 AEAD. See @docs/PRD.md Section 3.
- **FFI:** Mozilla UniFFI 0.31.x. Rust wrapper crate `pgp-mobile` → generated Swift bindings → XCFramework.
- **Security:** CryptoKit (Secure Enclave P-256 key wrapping), Security framework (Keychain).
- **Build:** Xcode 26, Rust stable (latest, MSRV follows sequoia-openpgp requirements), targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin`.
- **Localization:** English + Simplified Chinese via `.xcstrings` String Catalog.

## Architecture

Three-layer bridge: Rust (`pgp-mobile`) → UniFFI scaffolding → Swift app.

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE wrapping, Keychain, auth modes, Argon2id memory guard, memory zeroing
├── Models/           # Data types, PGP key representations, error types
├── Extensions/       # Swift/Foundation extensions
└── Resources/        # Assets, String Catalog, Info.plist
pgp-mobile/           # Rust wrapper crate (Sequoia + UniFFI)
PgpMobile.xcframework # Built artifact (not in source)
docs/                 # PRD, TDD, POC, architecture, security, testing, conventions
```

Detailed module breakdown: @docs/ARCHITECTURE.md

## Build Commands

```bash
# Rust: cross-compile for iOS device
# Note: First build compiles vendored OpenSSL from source (~3-5 min). Subsequent builds are cached.
cargo build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for Apple Silicon simulator
cargo build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml

# Generate Swift bindings (via build-xcframework.sh, which uses a host macOS dylib for bindgen)
cargo run --release --manifest-path pgp-mobile/Cargo.toml \
    --bin uniffi-bindgen generate \
    --library target/release/libpgp_mobile.dylib \
    --language swift --out-dir bindings/

# Create XCFramework (all three platform slices)
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libpgp_mobile.a -headers bindings/ \
    -library target/aarch64-apple-ios-sim/release/libpgp_mobile.a -headers bindings/ \
    -library target/aarch64-apple-darwin/release/libpgp_mobile.a -headers bindings/ \
    -output PgpMobile.xcframework

# Recommended: use the automated build script (handles all of the above)
./build-xcframework.sh --release

# Run Rust tests
cargo test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests (simulator, uses CypherAir-UnitTests test plan)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'

# Run device-only tests (SE, biometrics, MIE — uses CypherAir-DeviceTests test plan)
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'
```

## Hard Constraints — NEVER Violate

1. **Zero network access.** No HTTP(S), no networked SDKs, no telemetry. Code audit must confirm zero network code paths. No network URL loading (http/https). No NWConnection. No URLSession. Custom app URL scheme handling (`cypherair://`) is permitted — it is local IPC, not network access.
2. **Minimal permissions.** The only Info.plist usage description is `NSFaceIDUsageDescription` (required by iOS for Face ID / Touch ID authentication via `LAContext`). No camera, photo library, contacts, or network entitlements. All I/O through system pickers, Share Sheet, URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or `NSLog()` any key material, passphrase, or decrypted content. Not even in DEBUG builds.
5. **Memory zeroing.** All sensitive data (`Data` buffers containing keys, passphrases, plaintext) must be overwritten with zeros when no longer needed. Rust side: `zeroize` crate. Swift side: `resetBytes(in:)` on `Data`.
6. **Secure random only.** Swift side: `SecRandomCopyBytes` or CryptoKit (which uses it internally). Rust side: `getrandom` crate (delegates to `SecRandomCopyBytes` on iOS). No `arc4random`, no `Int.random`.
7. **MIE enabled.** Enhanced Security capability with Hardware Memory Tagging must remain enabled. Never remove the entitlements. See @docs/SECURITY.md Section 6.
8. **Profile-correct message format.** v4 recipient → SEIPDv1. v6 recipient → SEIPDv2. Mixed → SEIPDv1. Never send SEIPDv2 to a v4 key holder. See @docs/TDD.md Section 1.4.

## Security Boundaries — Ask Before Modifying

STOP and describe proposed changes before editing any file in these areas:

- `Sources/Security/` — SE wrapping, Keychain access, auth mode logic
- `Sources/Security/SecureEnclaveManager.swift` — wrapping/unwrapping flow
- `Sources/Security/KeychainManager.swift` — access control flags
- `Sources/Security/AuthenticationManager.swift` — Standard/High Security mode switching
- `Sources/Services/DecryptionService.swift` — Phase 1/Phase 2 authentication boundary
- `Sources/Services/QRService.swift` — external URL input parsing (untrusted data)
- `pgp-mobile/src/` — any Rust cryptographic code
- `CypherAir.entitlements` — capability entitlements
- `Info.plist` — permission descriptions (only `NSFaceIDUsageDescription` permitted)

Full security model and red lines: @docs/SECURITY.md

## Encryption Profiles

- **Profile A (Universal, default):** v4, Ed25519+X25519, SEIPDv1, Iterated+Salted S2K. Works with GnuPG 2.1+ and all PGP tools.
- **Profile B (Advanced):** v6, Ed448+X448, SEIPDv2 AEAD OCB, Argon2id. Works with Sequoia 2.0+, OpenPGP.js 6.0+, GopenPGP 3.0+. **Not GnuPG compatible.**

Profile selected at key generation, immutable. Multiple keys of different profiles allowed. See @docs/PRD.md Section 3.

## Authentication Modes

- **Standard Mode (default):** Face ID / Touch ID with passcode fallback. Flags: `[.privateKeyUsage, .biometryAny, .or, .devicePasscode]`.
- **High Security Mode:** Face ID / Touch ID only. No passcode fallback. Flags: `[.privateKeyUsage, .biometryAny]`. If biometrics unavailable, all private-key operations are blocked.

Switching modes requires re-wrapping all SE-protected keys. See @docs/SECURITY.md Section 4.

## Code Style (Summary)

- Swift API Design Guidelines. `guard let` over force-unwrap. `async/await` over Combine.
- `@Observable` for state. `NavigationStack` with typed paths. No `NavigationView`.
- iOS 26 Liquid Glass: standard components auto-adopt. Custom controls use `.glassEffect()`. See @docs/LIQUID_GLASS.md.
- One type per file. Group by feature. All user strings in String Catalog.
- Full conventions: @docs/CONVENTIONS.md

## Testing Requirements

- Every PR must include tests. Security changes require both positive and negative tests.
- Crypto tests: run for **both profiles**. Round-trip tests (encrypt→decrypt, sign→verify), tamper tests (1-bit flip → failure).
- SE/biometric code: guard with `SecureEnclave.isAvailable`, skip in simulator.
- MIE: test on iPhone 17 or iPhone Air (A19/A19 Pro) with Hardware Memory Tagging diagnostics enabled.
- Test plans: `CypherAir-UnitTests.xctestplan` (simulator/CI), `CypherAir-DeviceTests.xctestplan` (physical device).
- **GitHub Actions caveat:** the hosted `macos-26` runner image may still report macOS 26.3, which is older than the project's current 26.4 deployment target. When that happens, hosted Swift tests can fail before execution even though local macOS validation passes.
- Full testing guide: @docs/TESTING.md
- Code review checklist: @docs/CODE_REVIEW.md

## Workflow Reminders

- Read and understand relevant source files before proposing edits.
- Do not add features, refactor, or "improve" beyond what was asked.
- Do not add error handling for impossible scenarios.
- Run `cargo test` and `xcodebuild test` before considering a task complete.
- Commit messages: conventional format — `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.
- **Never modify code without explicit user approval.** When asked to investigate, diagnose, or review an issue, only analyze and report findings. Do not edit any files until the user explicitly approves a specific modification plan.
- **Before text replacement, verify match count.** Before executing any string replacement, check how many matches exist in the file. If multiple matches exist, handle each one individually to avoid unintended changes to other locations.
- **After reverting changes, verify with `git diff`.** Never rely on memory to confirm a revert is complete. Always run `git diff` (or `git diff origin/main`) to confirm the file matches the expected state.
- **After code changes, run tests — not just build.** A successful build does not guarantee correctness. Always run the relevant test suite to verify no regressions were introduced.
- **Never run destructive git operations (checkout, reset, restore) on project files (*.pbxproj, *.entitlements, *.xctestplan, *.xcscheme) without explicit user approval.** These files are difficult to manually reconstruct if changes are lost.
