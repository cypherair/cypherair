# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access. Minimal permissions (Face ID / Touch ID usage description only).

## Tech Stack

- **Platform:** iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+. Minimum device: 8 GB RAM.
- **Language:** Apple Swift 6.3.2, SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere). UIKit only for system pickers. `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release.
- **OpenPGP:** Sequoia PGP 2.3.0 (Rust, LGPL-2.0-or-later) with `crypto-openssl` backend (vendored static linking). Stable build release ordering and the current source/compliance asset contract are documented in @docs/APP_RELEASE_PROCESS.md and @docs/XCFRAMEWORK_RELEASES.md.
- **Profiles:** Profile A (Universal, GnuPG-compatible) and Profile B (Advanced, RFC 9580), selected at key generation. See @docs/PRD.md Section 3.
- **FFI:** Mozilla UniFFI 0.31.x. Rust wrapper crate `pgp-mobile` generates Swift bindings and packaged outputs, while Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap`.
- **Security:** CryptoKit (Secure Enclave P-256 key wrapping), Security framework (Keychain), ProtectedData app-data domains opened after app privacy authentication.
- **Build:** Xcode 26.5, Rust stable (latest, MSRV follows sequoia-openpgp requirements), targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`.
- **Localization:** English + Simplified Chinese via `.xcstrings` String Catalog.

## Architecture

Three-layer bridge: Rust (`pgp-mobile`) → UniFFI scaffolding → Swift app.

```
Sources/
├── App/              # SwiftUI views, navigation, onboarding
├── Services/         # Encryption, signing, key management, contacts, QR
├── Security/         # SE wrapping, Keychain, auth modes, ProtectedData, Argon2id memory guard, memory zeroing
├── Models/           # Data types, PGP key representations, error types
├── Extensions/       # Swift/Foundation extensions
├── PgpMobile/        # Generated UniFFI Swift bindings (do not hand-edit)
└── Resources/        # Assets, String Catalog
pgp-mobile/           # Rust wrapper crate (Sequoia + UniFFI)
docs/                 # PRD, TDD, architecture, security, testing, conventions
CypherAir-Info.plist  # Root-level app Info.plist source
```

Detailed module breakdown: @docs/ARCHITECTURE.md

## Build Commands

```bash
# Rust: cross-compile for iOS device
# Note: First build compiles vendored OpenSSL from source (~3-5 min). Subsequent builds are cached.
cargo +stable build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for Apple Silicon simulator
cargo +stable build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for macOS Apple Silicon
cargo +stable build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for visionOS device
cargo +stable build --release --target aarch64-apple-visionos --manifest-path pgp-mobile/Cargo.toml

# Rust: cross-compile for visionOS simulator
cargo +stable build --release --target aarch64-apple-visionos-sim --manifest-path pgp-mobile/Cargo.toml

# Full Rust + UniFFI + packaged-artifact sync
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
    ./build-xcframework.sh --release

# Run Rust tests
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests locally (source of truth for Swift validation)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Run device-only tests (SE, biometrics, MIE — uses CypherAir-DeviceTests test plan)
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'

# Run targeted macOS UI smoke coverage for routes, settings, and tutorial flows
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Run the native visionOS build probe
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

There is currently no dedicated visionOS XCTest test plan. Native visionOS validation uses the build probe above together with the existing Rust, macOS-local, and iOS-device validation paths.

For the full Rust artifact refresh, UniFFI/bindings sync, and Xcode validation workflow, see @docs/TESTING.md.

## Hard Constraints — NEVER Violate

1. **Zero network access.** No HTTP(S), no networked SDKs, no telemetry. Code audit must confirm zero network code paths. No network URL loading (http/https). No NWConnection. No URLSession.
2. **Minimal permissions.** The app configures only `NSFaceIDUsageDescription` as a usage description for LocalAuthentication-backed biometric flows. No camera, photo library, contacts, or network entitlements. All I/O through system pickers, Share Sheet, URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or `NSLog()` any key material, passphrase, or decrypted content.
5. **Memory zeroing.** All sensitive data (`Data` buffers containing keys, passphrases, plaintext) must be overwritten with zeros when no longer needed. Rust side: `zeroize` crate. Swift side: `resetBytes(in:)` on `Data`.
6. **Secure random only.** Swift side: `SecRandomCopyBytes` or CryptoKit (which uses it internally). Rust side: `getrandom` crate.
7. **MIE enabled.** Enhanced Security capability with Hardware Memory Tagging must remain enabled. Never remove the entitlements. See @docs/SECURITY.md Section 8.
8. **Profile-correct message format.** Format is chosen automatically by recipient key version; never send SEIPDv2 to a v4 key holder. See @docs/TDD.md Section 1.4.

## Security Boundaries — Ask Before Modifying

STOP and describe proposed changes before editing any file in these areas:

- `Sources/Security/` — SE wrapping, Keychain access, auth mode logic
- `Sources/Security/SecureEnclaveManager.swift` — wrapping/unwrapping flow
- `Sources/Security/KeychainManager.swift` — access control flags
- `Sources/Security/AuthenticationManager.swift` — Standard/High Security mode switching
- `Sources/Security/ProtectedData/` — app-data root-secret authorization, registry/recovery, wrapped-DMK lifecycle, relock semantics
- `Sources/Services/DecryptionService.swift` — Phase 1/Phase 2 authentication boundary
- `Sources/Services/QRService.swift` — external URL input parsing (untrusted data)
- `pgp-mobile/src/` — any Rust cryptographic code
- `CypherAir.xcodeproj/project.pbxproj` and other Xcode project files
- `CypherAir.entitlements`
- `CypherAirMacOS.entitlements`
- `CypherAir-Info.plist`

Full security model and red lines: @docs/SECURITY.md

## Encryption Profiles

Two profiles, selected at key generation and immutable; multiple keys of different profiles are allowed. For profile behavior, algorithm suites, and interoperability, see @docs/PRD.md Section 3 and @docs/SECURITY.md Section 1.

## Authentication Modes

Standard Mode (default) and High Security Mode, selectable in Settings; switching modes re-wraps all SE-protected keys. For access-control flags and mode-switching details, see @docs/SECURITY.md Section 4.

## Code Style (Summary)

- Swift API Design Guidelines. `guard let` over force-unwrap. `async/await` over Combine.
- `@Observable` for state. `NavigationStack` with typed paths. No `NavigationView`.
- Use iOS 26 Liquid Glass conventions where applicable, and prefer platform-native SwiftUI chrome on macOS and visionOS. Custom controls use `.glassEffect()` only when the API is available and matches platform conventions. See @docs/CONVENTIONS.md.
- One type per file. Group by feature. All user strings in String Catalog.
- Full conventions: @docs/CONVENTIONS.md

## Testing Requirements

- Every functional PR must include tests. Security changes require both positive and negative tests. Docs-only PRs may use the documentation consistency path instead of Rust/Xcode runs (see @docs/TESTING.md and @docs/CODE_REVIEW.md).
- Crypto tests: run for **both profiles**. Round-trip tests (encrypt→decrypt, sign→verify), tamper tests (1-bit flip → failure).
- SE/biometric code: guard with `SecureEnclave.isAvailable`, skip in simulator.
- MIE: test on supported A19/A19 Pro-or-newer hardware with Hardware Memory Tagging diagnostics enabled; current device examples live in `docs/SECURITY.md`.
- Test plans: `CypherAir-UnitTests.xctestplan` (local macOS validation / simulator / CI), `CypherAir-DeviceTests.xctestplan` (physical device), `CypherAir-MacUITests.xctestplan` (targeted macOS UI smoke coverage for route, launch, settings, and tutorial flows), `CypherAir-DangerousDeviceTests.xctestplan` (manual destructive physical-device lane for the Secure Enclave custody Reset All Local Data cleanup proof).
- Rust changes under `pgp-mobile/src` do **not** automatically refresh the `PgpMobile.xcframework` artifact or generated UniFFI outputs that Xcode uses for Swift/FFI tests.
- If a Rust change can affect Swift-visible behavior, run `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 ./build-xcframework.sh --release` before running `xcodebuild test`. This matches GitHub Actions by consuming the pinned `cypherair/rust` stage1 prerelease; use a local `ARM64E_RUSTC`, `ARM64E_STAGE1_DIR`, or rustup-linked `stage1-arm64e-patch` only when deliberately testing a local Rust fork build.
- See `docs/TESTING.md` for the full Rust↔Xcode validation workflow and stale-artifact troubleshooting.
- **GitHub Actions caveat:** the hosted `macos-26` runner image may still lag the project's current 26.5 deployment target or expose Xcode before all matching platform runtimes are usable. When that happens, hosted Swift tests or app probes can be warning-skipped by preflight even though local validation passes.
- Full testing guide: @docs/TESTING.md
- Code review checklist: @docs/CODE_REVIEW.md

## Workflow Reminders

- Read and understand relevant source files before proposing edits.
- Do not add features, refactor, or "improve" beyond what was asked.
- Run `cargo +stable test` and the relevant `xcodebuild test` plan before considering a code task complete.
- **Git/PR discipline.** Default to a topic branch, not `main`; submit work through a pull request. Commits should be signed; if the signing key is unavailable, ask the user rather than creating an unsigned commit. When merging PRs, prefer a regular merge commit unless the user asks otherwise. Commit messages use conventional prefixes — `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.
- **Release metadata is user-owned.** Do not proactively modify `CURRENT_PROJECT_VERSION` or `MARKETING_VERSION`; read them from the project, never invent/increment/reset them, and treat any such change already present as a user edit to keep. For formal stable releases / App Store candidates, follow @docs/APP_RELEASE_PROCESS.md (tag-first; do not rely on `workflow_dispatch` alone).
- Keep changes scoped to the user request. Only make changes directly required to complete the requested task; do not normalize, revert, or clean up unrelated local changes already in the worktree.
- **Before text replacement, verify match count.** Before executing any string replacement, check how many matches exist in the file. If multiple matches exist, handle each one individually to avoid unintended changes to other locations.
- **After reverting changes, verify with `git diff`.** Never rely on memory to confirm a revert is complete. Always run `git diff` (or `git diff origin/main`) to confirm the file matches the expected state.
- **After code changes, run tests — not just build.** A successful build does not guarantee correctness. Always run the relevant test suite to verify no regressions were introduced.
- **Never run destructive git operations (checkout, reset, restore) on project files (*.pbxproj, *.entitlements, *.xctestplan, *.xcscheme) without explicit user approval.** These files are difficult to manually reconstruct if changes are lost.
- **Keep CLAUDE.md and AGENTS.md in substance-sync.** AGENTS.md is the agent-oriented companion read by Codex and other tools. The two must carry identical substance (hard constraints, sensitive boundaries, testing/release/Git policy) and differ only in reference syntax — `@docs/...` here (auto-embedded into Claude Code's context) vs plain `docs/...` pointers in AGENTS.md. When you change the substance of one, mirror it to the other.
