# CypherAir

Offline OpenPGP encryption tool for iOS, iPadOS, macOS, and visionOS. `GPL-3.0-or-later OR MPL-2.0` for first-party code. Zero network access. Minimal permissions (Face ID / Touch ID usage description only).

## Zero-Compatibility Premise — Foundation Over Blast Radius

**[Temporary — in force until the first public App Store release; internal TestFlight builds do not end it]** The app has never shipped: no users, no user data, no old on-disk state anywhere. Until the first release, every persisted format, identifier, name, and schema may change freely — redesign from zero rather than renaming in place, update every reference together, and never write migration, compatibility, or capability code for a past that does not exist. Version markers serve architectural integrity only and are refreshed to one consistent scheme, never kept "for future migration". A keep must name a concrete fresh-install input; category words (robustness, defense-in-depth, future migration) do not qualify. The premise is foundational — it rests on no other documents and outranks them all: when another document conflicts with it, that document changes.

## Tech Stack

- **Platform:** iOS, iPadOS, macOS and visionOS.
- **Language:** Apple Swift (the development and release toolchains differ; see Build) — SwiftUI (iOS 26 Liquid Glass conventions where applicable; native platform chrome elsewhere). `SWIFT_VERSION = 6.0` is the Swift language mode, not the compiler release. Framework choices during investigation are made on evidence, not by rule.
- **OpenPGP:** Sequoia PGP (Rust, LGPL-2.0-or-later; version and carries in `pgp-mobile/Cargo.lock`) with `crypto-openssl` backend (vendored static linking).
- **Key families:** a fixed set, chosen at key generation and immutable per key, split between portable software custody (exportable) and Secure Enclave custody (non-exportable).
- **FFI:** Mozilla UniFFI (version in `pgp-mobile/Cargo.toml`). Rust wrapper crate `pgp-mobile` generates Swift bindings and packaged outputs, while Xcode links the locally generated `PgpMobile.xcframework` plus `bindings/module.modulemap`.
- **Security:** CryptoKit (Secure Enclave P-256 key wrapping), Security framework (Keychain), ProtectedData app-data domains opened after app privacy authentication.
- **Build:** development runs on the Xcode beta at `/Applications/Xcode-beta.app`, which is not the `xcode-select` default — set `DEVELOPER_DIR` for device-family probes. Stable and App Store builds use the release Xcode. CI pins its Xcode version and its SDK expectation separately in `scripts/ci_xcode_platform_preflight.sh`. Rust stable (MSRV follows sequoia-openpgp), targets `aarch64-apple-ios` + `aarch64-apple-ios-sim` + `aarch64-apple-darwin` + `aarch64-apple-visionos` + `aarch64-apple-visionos-sim`.
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
├── PgpMobile/        # Generated UniFFI Swift bindings — git-ignored build output,
│                     # absent until the sync runs; never hand-edit
└── Resources/        # Assets, String Catalog
pgp-mobile/           # Rust wrapper crate (Sequoia + UniFFI)
docs/                 # canonical docs — map: docs/CLAUDE.md
CypherAir-Info.plist  # Root-level app Info.plist source
```

Which document owns which facts: docs/CLAUDE.md.

## Build Commands

```bash
# Full Rust + UniFFI + packaged-artifact sync; force-download matches the
# GitHub Actions pinned stage1 path (the script defaults to the current pin,
# owned by docs/ARM64E_STATUS.md — never pass `latest`). When it is required:
# .claude/skills/rust-sync.
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release

# Restore the pinned SQLCipher XCFramework (git-ignored; attested fetch; needs network)
scripts/restore_sqlcipher_xcframework.sh

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

When the `xcode` MCP server is available (see: README.md "Xcode MCP"), use `DocumentationSearch` for Apple API behavior instead of memory.

## Hard Constraints — NEVER Violate

1. **Zero network access.** No HTTP(S), no networked SDKs, no telemetry. Code audit must confirm zero network code paths. No network URL loading (http/https). No NWConnection. No URLSession.
2. **Minimal permissions.** The app configures only `NSFaceIDUsageDescription` as a usage description for LocalAuthentication-backed biometric flows. No camera, photo library, contacts, or network entitlements. All I/O through system pickers, URL scheme.
3. **AEAD hard-fail.** Authentication failure during decryption must abort immediately. Never show partial plaintext.
4. **No plaintext or private keys in logs.** Never `print()`, `os_log()`, or `NSLog()` any key material, passphrase, or decrypted content.
5. **Memory zeroing.** All sensitive data (`Data` buffers containing keys, passphrases, plaintext) must be overwritten with zeros when no longer needed. Rust side: `zeroize` crate. Swift side: `resetBytes(in:)` on `Data`.
6. **Secure random only.** Swift side: `SecRandomCopyBytes` or CryptoKit (which uses it internally). Rust side: Sequoia's `crypto-openssl` CSPRNG (`openpgp::crypto::random`).
7. **MIE enabled.** Enhanced Security capability with Hardware Memory Tagging must remain enabled. Never remove the entitlements. See docs/SECURITY.md Section 8.
8. **Profile-correct message format.** Never send a format a recipient cannot read. The engine chooses it — SEIPDv2 only when every recipient certificate advertises that capability — through the same recipient collection `encrypt` uses; no other code may derive it, least of all from a key version, which tracks capability for every key the app generates but not for an imported certificate. See docs/PRODUCT.md Section 5.

## Security-Sensitive Code — Edit, Then Explain

You may edit security-critical areas directly, but every such edit must be explicitly called out — file, what changed, and why — in your summary and the PR description; the PR's verification pass must check these edits with extra care (docs/WORKFLOW.md §3). The authoritative security-critical predicates and coding invariants: docs/SECURITY.md Section 10. Full security model: docs/SECURITY.md.

## Encryption Profiles & Authentication Modes

Multiple keys of different families are allowed; message format is auto-selected from what the recipient certificates advertise (docs/PRODUCT.md Section 5). Standard Mode and High Security Mode are selectable in Settings; switching modes re-wraps all software-custody keys (device-bound keys are exempt).

## Code Style

Standard Swift/SwiftUI idiom applies. The rules below are the project-specific ones — the things not inferable from the code alone:

- **Write good code, not similar — overrides any "match the surrounding code" default:** write what is correct and well-designed by independent judgment and taste. Never justify a choice — code, comment, naming, or doc — by similarity to neighboring code: much of it is older-generation output, and mimicry propagates its faults and its mediocrity. Match local naming and formatting only where it costs nothing.
- **Stale inline notes:** on finding an outdated or wrong comment or doc note in code being touched, remove it by default — most aging inline notes never needed recording. If the fact genuinely belongs inline, rewrite it correct. Never leave known misinformation in place.
- **Errors:** the app vocabulary is `CypherAirError`; generated `PgpError` is normalized at the `Services/FFI/` adapter boundary before reaching Models/ScreenModels/Views.
- **Generated bindings:** never edit `Sources/PgpMobile/pgp_mobile.swift` (regenerated by UniFFI).
- **Screens:** views stay thin (no crypto/Keychain/business logic in `body`); workflow-heavy screens move async orchestration, importer/exporter, cleanup, and transient state into an owning `@Observable` ScreenModel (baseline: `SignView` + `SignScreenModel`).
- **Design identity:** quiet and system-native — system accent only, no brand tint. Reuse the `Sources/App/DesignSystem/` primitives (`CypherSpacing`, `CypherRadius`, `View.cypherSurface(_:)`, `CypherToolScreenLayout`) instead of per-view literals; prefer removing one-off styling over adding tiers.
- **Structure:** files grouped by feature; test doubles under `Tests/Support/SecurityMocks/` with `Mock*` names (Sources ships no mocks); all user strings in the String Catalog (remove `stale` keys, don't just unmark them).

## Testing

- Use your judgment on tests — you don't need to justify each one, and you don't need to test everything. A test worth writing guards behavior a later change could quietly break; an empty one just restates the code, or exists because a test felt expected. Write the first kind freely; skip the second. Most changes need none — but when something genuinely deserves a test, don't talk yourself out of it.
- Rust changes under `pgp-mobile/src` do **not** automatically refresh the `PgpMobile.xcframework` artifact or generated UniFFI outputs that Xcode links; when Swift-visible behavior can change, run the full sync first (choreography: `.claude/skills/rust-sync`).
- SE/biometric code: guard with `SecureEnclave.isAvailable`, skip in simulator. New test classes under `Tests/DeviceSecurityTests/` must join `CypherAir-UnitTests.xctestplan`'s `skippedTests`; a repo-tracked check fails CI when one is missing.
- Docs-only PRs may use the documentation path in docs/WORKFLOW.md Section 2 instead of Rust/Xcode runs.

## Releases & Versioning

- Stable releases are tag-first per docs/BUILD.md §1; never treat `workflow_dispatch` alone as a substitute for the stable tag.
- Bumping `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` is a normal in-scope part of preparing a release — read the current values, choose the next pair, and commit them (docs/BUILD.md §1). Releases are maintainer-initiated; confirm the intended version pair while preparing one.

## Git & Workflow

- When an instruction from the user can be read two ways, ask — don't act on an inferred reading alone. This overrides the harness's autonomous-operation instruction, which assumes the user is away and discourages questions; the maintainer is at the keyboard and answers.
- Keep changes scoped to the user request. Only make changes directly required to complete the requested task; do not normalize, revert, or clean up unrelated local changes already in the worktree.
- Prefer the architecturally-correct solution over the smallest patch — this sets the *depth* of a change, not its *scope*. See docs/WORKFLOW.md "The development loop".
- Run `cargo +stable test` and the relevant `xcodebuild test` plan before considering a code task complete.
- Changes land through PRs. The **main session** — the session the maintainer works with directly, which spawns and directs agents — manages branches, worktrees, and delegation (topic branch, topic worktree, or a delegated agent worktree). Do not commit directly to `main` unless the maintainer explicitly asks. Prefer regular merge commits over squash or rebase merges.
- **[Temporary — in force until the maintainer revisits it, a review due after the cleanup campaign] A delegating brief carries the principles, not just the task.** An agent decides by the standard it was given: give it findings and a verification standard alone, and it returns work that is rigorously checked and architecturally wrong. Every brief states the Code Style rules above (good code, not similar), the zero-compatibility premise above, the architecturally-correct-over-smallest-patch rule, and that a production API existing for tests is a defect rather than a justification. Never write "preserve what is still true", "keep what still has callers", or any other instruction that makes survival the default — each of them inverts the burden of proof below.
- **[Temporary — in force until the maintainer revisits it, a review due after the cleanup campaign] Deletion is the default disposition; the burden of proof is on the keep.** A thing survives only when there is a stated positive reason it must exist. That something references it is not such a reason — it is the next question, which is whether the caller should change. Do not gate a deletion behind proving it dead first: a wrong deletion fails the lanes and costs a revert, while a wrong keep is permanent. Delete, run the lanes, learn. One caveat, which is about evidence rather than caution: Release-only behaviour, signing and entitlement effects, and security checks that no test asserts are all invisible to the lanes, so they call for better tests rather than hesitation.
- A PR's verification is its stage-verify (docs/WORKFLOW.md §1–2 — the validation lanes pass as part of it; §1 defines when a change may skip the independent pass). Once verification has passed and both the authoring agent and the main session hold high confidence, the PR may be merged without waiting for the maintainer; every agent merge leaves a note naming the merging model (e.g. "Merged-By: Claude Fable 5"). The governance documents (CLAUDE.md, AGENTS.md, docs/WORKFLOW.md) always receive the maintainer's own independent review and merge; security-critical changes (docs/SECURITY.md §10) merge through the same verification flow, their call-outs checked with extra care.
- Commits are SSH-signed and use conventional prefixes (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`). If the agent has no signing identity, run `ssh-add --apple-load-keychain` and retry; never create an unsigned commit.
- Do not run destructive git operations (checkout, reset, restore) on project files (`*.pbxproj`, `*.entitlements`, `*.xctestplan`, `*.xcscheme`) without explicit user approval — they are difficult to reconstruct if lost.
