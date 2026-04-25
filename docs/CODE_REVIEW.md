# Code Review Checklist

> Purpose: Review criteria for PRs, organized by change type.
> Audience: Human reviewers and AI coding tools.

## All PRs

- [ ] Rust targets compile: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin`, `aarch64-apple-visionos`, and `aarch64-apple-visionos-sim`
- [ ] For Rust / UniFFI-visible behavior changes, `./build-xcframework.sh --release` has been run before any Xcode validation
- [ ] `cargo test`, local `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`, and the native visionOS build probe pass
- [ ] If `swift-unit-tests-hosted-preview` fails before tests start, confirm whether the hosted macOS image is still below the app deployment target before treating it as a code regression
- [ ] No new compiler warnings
- [ ] No hardcoded user-visible strings (all in String Catalog)
- [ ] No force-unwrap (`!`) in production code
- [ ] Commit messages follow conventional format (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)

## Security-Related PRs

Changes touching `Sources/Security/`, `Sources/Services/DecryptionService.swift`, `Sources/Services/QRService.swift`, `pgp-mobile/src/`, `CypherAir.entitlements`, or `CypherAir-Info.plist`.

- [ ] Both positive and negative tests included
- [ ] Memory zeroing verified: `resetBytes(in:)` (Swift) / `zeroize` (Rust) on all sensitive buffers
- [ ] No `print()` / `os_log()` / `NSLog()` of key material, passphrases, or decrypted content
- [ ] Access control flags correct for both Standard and High Security modes
- [ ] AEAD hard-fail enforced (no partial plaintext on auth failure)
- [ ] Only `NSFaceIDUsageDescription` in `CypherAir-Info.plist`
- [ ] No network APIs introduced (URLSession, NWConnection, HTTP)
- [ ] Secure random only (`SecRandomCopyBytes` / `getrandom`)
- [ ] Human review obtained for files listed in [SECURITY.md](SECURITY.md) §8
- [ ] Crash recovery distinguishes safe cleanup, retryable failure, and unrecoverable failure correctly
- [ ] Retryable recovery failures keep retry flags set; unrecoverable states clear flags and surface a generic warning
- [ ] Startup diagnostics remain generic and do not leak fingerprints or key identifiers

## Rust API Changes

Changes to `pgp-mobile/src/lib.rs` public API surface.

- [ ] UniFFI bindings regenerated
- [ ] Swift call sites in `Sources/Services/` updated
- [ ] `PgpError` enum stays 1:1 between Rust and Swift
- [ ] Both Profile A and Profile B tested
- [ ] FFI round-trip tests pass (generate in Rust → pass to Swift → pass back → verify)

## UI PRs

Changes to `Sources/App/`.

- [ ] VoiceOver labels on all interactive elements
- [ ] Dynamic Type respected (system text styles, no fixed font sizes)
- [ ] 44×44pt minimum touch targets
- [ ] Liquid Glass compliance (see [LIQUID_GLASS.md](LIQUID_GLASS.md))
- [ ] No business logic in views
- [ ] If a screen model is introduced, the view retains layout, bindings, and presentation wiring only; workflow state, async actions, importer/exporter state, and cleanup move into the model
