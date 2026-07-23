# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access. Minimal permissions (Face ID / Touch ID usage description only).

This file is the Claude-facing agent guide. `AGENTS.md` is maintained separately for Codex; keep shared project constraints semantically aligned, but do not force the two files to be identical. Agent skills under `.claude/skills/` carry workflow choreography and defer to the canonical documents they cite. `docs/ARM64E_STATUS.md` is the source of truth for Apple arm64e support. Documentation classes and precedence are defined in docs/WORKFLOW.md.

## Tech Stack

- **Platform:** iOS 26.5+ / iPadOS 26.5+ / macOS 26.5+ / visionOS 26.5+. Minimum device: 8 GB RAM.
- **Language:** Apple Swift — 6.4 beta on the development toolchain, 6.3.3 on the release toolchain (see Build) — SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere). UIKit only for system pickers and the app-lock shield window bridge (`Sources/App/Shell/AppLockShieldWindow.swift`, which hosts the SwiftUI lock surface above all presentations). `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release.
- **OpenPGP:** Sequoia PGP 2.4.1 (Rust, LGPL-2.0-or-later) with `crypto-openssl` backend (vendored static linking). Stable build release ordering, the source/compliance asset contract, and the XCFramework SDK channels are documented in docs/RELEASE.md.
- **Key families:** nine, chosen at key generation and immutable per key. Portable (software, exportable): Legacy (Ed25519 v4, GnuPG-compatible), Modern (Ed25519+X25519 v6), Modern · High (Ed448+X448 v6), Post-Quantum (RFC 9980 ML-DSA-65/ML-KEM-768), Post-Quantum · High (ML-DSA-87/ML-KEM-1024). Device-Bound (Secure Enclave custody, non-exportable): Legacy and Modern (P-256 v4/v6), Post-Quantum and Post-Quantum · High (RFC 9980 split custody). Per-family specs: docs/TDD.md Section 1.3; product exposure: docs/PRD.md Section 3; custody: docs/SECURE_ENCLAVE_CUSTODY.md; post-quantum design: docs/POST_QUANTUM.md.
- **FFI:** Mozilla UniFFI 0.32.x. Rust wrapper crate `pgp-mobile` generates Swift bindings and packaged outputs, while Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap`.
- **Security:** CryptoKit (Secure Enclave P-256 key wrapping), Security framework (Keychain), ProtectedData app-data domains opened after app privacy authentication.
- **Build:** development on Xcode 27.0 beta (27A5218g, `/Applications/Xcode-beta 2.app` — quote the space in shell commands); release toolchain Xcode 26.6 / Swift 6.3.3 for stable and App Store builds; CI runs on the hosted `xcode-27` preview image, pinning Xcode 27.0 beta while separately requiring its bundled 27.0 SDKs and simulator runtimes via `scripts/ci_xcode_platform_preflight.sh`. Rust stable (latest, MSRV follows sequoia-openpgp requirements), targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`.
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
docs/                 # PRD, TDD, architecture, security, testing, workflow, release
CypherAir-Info.plist  # Root-level app Info.plist source
```

Detailed module breakdown: docs/ARCHITECTURE.md

## Build Commands

```bash
# Full Rust + UniFFI + packaged-artifact sync; force-download matches the
# GitHub Actions pinned stage1 path (the script defaults to the current pin,
# owned by docs/ARM64E_STATUS.md — never pass `latest`). When it is required:
# .claude/skills/rust-sync.
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release

# Run Rust tests
cargo +stable test --manifest-path pgp-mobile/Cargo.toml

# Run Swift unit + FFI tests locally (source of truth for Swift validation)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Run device-only tests (SE, biometrics, MIE). Any real Secure Enclave works —
# an Apple Silicon Mac runs the full lane locally; only the iOS Simulator
# cannot. Biometric-gated tests skip when nothing is enrolled (docs/TESTING.md §1).
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=macOS,arch=arm64e'          # Apple Silicon Mac (full lane, local)
# or a physical iOS device:
#   -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'

# Run targeted macOS UI smoke coverage for routes, settings, and tutorial flows
xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests \
    -destination 'platform=macOS'

# Run the native visionOS build probe (there is no dedicated visionOS test plan)
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS'
```

Per-target `cargo build` commands, the full Rust↔Xcode validation workflow, and stale-artifact troubleshooting live in docs/TESTING.md Section 2.4. When the `xcode` MCP server is available (setup: README.md "Xcode MCP"), use `DocumentationSearch` for Apple API behavior instead of memory.

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

You may edit security-critical areas directly, but every such edit must be explicitly called out — file, what changed, and why — in your summary and the PR description; the PR's verification pass must check these edits with extra care, and the maintainer reviews and merges (docs/WORKFLOW.md §3). The authoritative security-critical file list, per-file rationale, and coding invariants: docs/SECURITY.md Section 10. Full security model: docs/SECURITY.md.

## Encryption Profiles & Authentication Modes

Multiple keys of different families are allowed; message format is auto-selected by recipient key version (docs/TDD.md Section 1.4). Standard Mode and High Security Mode are selectable in Settings; switching modes re-wraps all software-custody keys (device-bound keys are exempt). Details: docs/PRD.md Section 3 and docs/SECURITY.md Section 4.

## Code Style

Standard Swift/SwiftUI idiom applies. The rules below are the project-specific ones — the things not inferable from the code alone:

- **Errors:** the app vocabulary is `CypherAirError`; generated `PgpError` is normalized at the `Services/FFI/` adapter boundary before reaching Models/ScreenModels/Views.
- **Generated bindings:** never edit `Sources/PgpMobile/pgp_mobile.swift` (regenerated by UniFFI); where strict concurrency trips on it, `@preconcurrency import PgpMobile` at call sites.
- **Screens:** views stay thin (no crypto/Keychain/business logic in `body`); workflow-heavy screens move async orchestration, importer/exporter, cleanup, and transient state into an owning `@Observable` ScreenModel (baseline: `SignView` + `SignScreenModel`).
- **Design identity:** quiet and system-native — system accent only, no brand tint. Reuse the `Sources/App/DesignSystem/` primitives (`CypherSpacing`, `CypherRadius`, `View.cypherSurface(_:)`, `CypherToolScreenLayout`) instead of per-view literals; prefer removing one-off styling over adding tiers.
- **Structure:** files grouped by feature; test doubles under `Tests/Support/SecurityMocks/` with `Mock*` names (Sources ships no mocks); all user strings in the String Catalog (remove `stale` keys, don't just unmark them).

## Testing

- Use your judgment on tests — you don't need to justify each one, and you don't need to test everything. A test worth writing guards behavior a later change could quietly break; an empty one just restates the code, or exists because a test felt expected. Write the first kind freely; skip the second. Most changes need none — but when something genuinely deserves a test, don't talk yourself out of it.
- Rust changes under `pgp-mobile/src` do **not** automatically refresh the `PgpMobile.xcframework` artifact or generated UniFFI outputs that Xcode links; when Swift-visible behavior can change, run the full sync first (choreography: `.claude/skills/rust-sync`).
- SE/biometric code: guard with `SecureEnclave.isAvailable`, skip in simulator.
- Docs-only PRs may use the documentation path in docs/WORKFLOW.md Section 2 instead of Rust/Xcode runs.
- Test plans, CI lanes, the hosted-runner caveat, and the full guide: docs/TESTING.md. Review gates: docs/WORKFLOW.md.

## Releases & Versioning

- Stable releases are tag-first per docs/RELEASE.md; never treat `workflow_dispatch` alone as a substitute for the stable tag.
- Bumping `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` is a normal in-scope part of preparing a release — read the current values, choose the next pair, and commit them (docs/RELEASE.md §1). Releases are maintainer-initiated; confirm the intended version pair while preparing one.

## Git & Workflow

- Keep changes scoped to the user request. Only make changes directly required to complete the requested task; do not normalize, revert, or clean up unrelated local changes already in the worktree.
- Prefer the architecturally-correct solution over the smallest patch — this sets the *depth* of a change, not its *scope*. See docs/WORKFLOW.md "The development loop".
- Run `cargo +stable test` and the relevant `xcodebuild test` plan before considering a code task complete.
- Changes land through PRs. The **main session** — the session the maintainer works with directly, which spawns and directs agents — manages branches, worktrees, and delegation (topic branch, topic worktree, or a delegated agent worktree). Do not commit directly to `main` unless the maintainer explicitly asks. Prefer regular merge commits over squash or rebase merges.
- A PR's verification is its stage-verify (docs/WORKFLOW.md §1–2 — the validation lanes pass as part of it; §1 defines when a change may skip the independent pass). Once verification has passed and both the authoring agent and the main session hold high confidence, the PR may be merged without waiting for the maintainer; every agent merge leaves a note naming the merging model (e.g. "Merged-By: Claude Fable 5"). Security-critical changes (docs/SECURITY.md §10) and the governance documents themselves (CLAUDE.md, AGENTS.md, docs/WORKFLOW.md) always receive the maintainer's own independent review and merge.
- Commits are SSH-signed and use conventional prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`). If the agent has no signing identity, run `ssh-add --apple-load-keychain` and retry; never create an unsigned commit.
- Do not run destructive git operations (checkout, reset, restore) on project files (`*.pbxproj`, `*.entitlements`, `*.xctestplan`, `*.xcscheme`) without explicit user approval — they are difficult to reconstruct if lost.
