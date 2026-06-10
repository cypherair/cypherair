# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access. Minimal permissions (Face ID / Touch ID usage description only).

This file is the single agent-facing source of truth; `AGENTS.md` defers here. Agent skills under `.claude/skills/` carry workflow choreography and defer to the canonical documents they cite. `docs/ARM64E_STATUS.md` is the source of truth for Apple arm64e support. Documentation classes and precedence are defined in docs/DOCUMENTATION_GOVERNANCE.md; archived docs under `docs/archive/` are historical context only.

## Tech Stack

- **Platform:** iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+. Minimum device: 8 GB RAM.
- **Language:** Apple Swift 6.3.2, SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere). UIKit only for system pickers. `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release.
- **OpenPGP:** Sequoia PGP 2.3.0 (Rust, LGPL-2.0-or-later) with `crypto-openssl` backend (vendored static linking). Stable build release ordering and the current source/compliance asset contract are documented in docs/APP_RELEASE_PROCESS.md and docs/XCFRAMEWORK_RELEASES.md.
- **Profiles:** Profile A (Universal, GnuPG-compatible) and Profile B (Advanced, RFC 9580), selected at key generation. See docs/PRD.md Section 3.
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

Detailed module breakdown: docs/ARCHITECTURE.md

## Build Commands

```bash
# Full Rust + UniFFI + packaged-artifact sync; matches the GitHub Actions
# pinned stage1 path. When it is required: .claude/skills/rust-sync.
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
    ./build-xcframework.sh --release

# Run Rust tests
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests locally (source of truth for Swift validation)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Run device-only tests (SE, biometrics, MIE)
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'

# Run targeted macOS UI smoke coverage for routes, settings, and tutorial flows
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Run the native visionOS build probe (there is no dedicated visionOS test plan)
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

Per-target `cargo build` commands, the full Rust↔Xcode validation workflow, and stale-artifact troubleshooting live in docs/TESTING.md Section 2.4. The pinned `ARM64E_STAGE1_RELEASE_TAG` value is owned by docs/ARM64E_STATUS.md and rotates with each stage1 re-pin.

## Xcode MCP

Xcode's MCP server (`xcrun mcpbridge`, Xcode 26.3+) provides Apple Developer Documentation search plus build/diagnostic tools, and the repository's `.mcp.json` configures it as the `xcode` server. When it is available in the current agent session, use `DocumentationSearch` to query Apple documentation rather than relying on memory for Apple API behavior. Setup: README.md "Xcode MCP".

## Hard Constraints — NEVER Violate

1. **Zero network access.** No HTTP(S), no networked SDKs, no telemetry. Code audit must confirm zero network code paths. No network URL loading (http/https). No NWConnection. No URLSession.
2. **Minimal permissions.** The app configures only `NSFaceIDUsageDescription` as a usage description for LocalAuthentication-backed biometric flows. No camera, photo library, contacts, or network entitlements. All I/O through system pickers, Share Sheet, URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or `NSLog()` any key material, passphrase, or decrypted content.
5. **Memory zeroing.** All sensitive data (`Data` buffers containing keys, passphrases, plaintext) must be overwritten with zeros when no longer needed. Rust side: `zeroize` crate. Swift side: `resetBytes(in:)` on `Data`.
6. **Secure random only.** Swift side: `SecRandomCopyBytes` or CryptoKit (which uses it internally). Rust side: `getrandom` crate.
7. **MIE enabled.** Enhanced Security capability with Hardware Memory Tagging must remain enabled. Never remove the entitlements. See docs/SECURITY.md Section 8.
8. **Profile-correct message format.** Format is chosen automatically by recipient key version; never send SEIPDv2 to a v4 key holder. See docs/TDD.md Section 1.4.

## Security-Sensitive Code — Edit, Then Explain

You may edit security-critical areas directly, but every such edit must be explicitly called out — file, what changed, and why — in your summary and the PR description, must include both positive and negative tests, and receives human review before merge (docs/CODE_REVIEW.md). Security-critical areas:

- `Sources/Security/` — SE wrapping, Keychain access control, auth modes, ProtectedData, custody boundaries
- `Sources/Services/DecryptionService.swift` — Phase 1/Phase 2 authentication boundary
- `Sources/Services/QRService.swift` — parses untrusted `cypherair://` input
- `Sources/Extensions/Data+Zeroing.swift` and `Sources/Security/MemoryZeroingUtility.swift` — memory-zeroing barriers
- `Sources/Services/DiskSpaceChecker.swift` — disk-space threshold guarding file operations
- `pgp-mobile/src/` — all Rust cryptographic code
- `CypherAir.entitlements`, `CypherAirMacOS.entitlements`, `CypherAir-Info.plist`, and Xcode project files

The authoritative per-file rationale, function-level review list, and coding invariants: docs/SECURITY.md Section 10. Full security model: docs/SECURITY.md.

## Encryption Profiles & Authentication Modes

Profiles are selected at key generation and immutable per key; multiple keys of different profiles are allowed, and message format is auto-selected by recipient key version (docs/TDD.md Section 1.4). Standard Mode and High Security Mode are selectable in Settings; switching modes re-wraps all SE-protected keys. Details: docs/PRD.md Section 3 and docs/SECURITY.md Sections 1 and 4.

## Code Style (Summary)

- Swift API Design Guidelines. `guard let` over force-unwrap. `async/await` over Combine.
- `@Observable` for state. `NavigationStack` with typed paths. No `NavigationView`.
- Use iOS 26 Liquid Glass conventions where applicable, and prefer platform-native SwiftUI chrome on macOS and visionOS. Custom controls use `.glassEffect()` only when the API is available and matches platform conventions.
- One type per file. Group by feature. All user strings in String Catalog.
- Full conventions: docs/CONVENTIONS.md

## Testing

- Every functional PR must include tests. Security changes require both positive and negative tests. Crypto tests run for **both profiles**.
- Rust changes under `pgp-mobile/src` do **not** automatically refresh the `PgpMobile.xcframework` artifact or generated UniFFI outputs that Xcode links; when Swift-visible behavior can change, run the full sync first (choreography: `.claude/skills/rust-sync`).
- SE/biometric code: guard with `SecureEnclave.isAvailable`, skip in simulator.
- Docs-only PRs may use the documentation consistency path in docs/TESTING.md Section 2 instead of Rust/Xcode runs.
- Test plans, CI lanes, the hosted-runner caveat, and the full guide: docs/TESTING.md. Review checklist: docs/CODE_REVIEW.md.

## Releases & Versioning

- Stable releases are tag-first per docs/APP_RELEASE_PROCESS.md; never treat `workflow_dispatch` alone as a substitute for the stable tag. Ask before publishing any release or tag.
- Xcode release metadata (`MARKETING_VERSION`, `CURRENT_PROJECT_VERSION`) is user-owned: read it from the project, and never invent, increment, or reset it. If the user changed it, treat that change as in-scope work, not something to revert.

## Git & Workflow

- Keep changes scoped to the user request. Only make changes directly required to complete the requested task; do not normalize, revert, or clean up unrelated local changes already in the worktree.
- Prefer the architecturally-correct solution over the smallest patch — this sets the *depth* of a change, not its *scope*. See docs/CONVENTIONS.md "Engineering Principle".
- Prefer small, reviewable diffs. Maintain existing user-visible behavior unless the task explicitly changes it.
- Run `cargo +stable test` and the relevant `xcodebuild test` plan before considering a code task complete.
- Work on a topic branch and submit a PR; do not commit directly to `main` unless the user explicitly asks. Prefer regular merge commits over squash or rebase merges.
- Commits are signed and use conventional prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`). If the signing key is unavailable, ask the user to unlock it; never create an unsigned commit.
- Never run destructive git operations (checkout, reset, restore) on project files (`*.pbxproj`, `*.entitlements`, `*.xctestplan`, `*.xcscheme`) without explicit user approval — they are difficult to reconstruct if lost.
