# Code Review Checklist

> Purpose: Review criteria for PRs, organized by change type.
> Audience: Human reviewers and AI coding tools.

## All Code PRs

- [ ] Rust targets compile: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin`, `aarch64-apple-visionos`, and `aarch64-apple-visionos-sim`
- [ ] For Rust / UniFFI-visible behavior changes, `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=latest ./build-xcframework.sh --release` has been run before any Xcode validation
- [ ] `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`, local `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`, and the native visionOS build probe pass
- [ ] If `swift-unit-tests-hosted-preview` is warning-skipped by hosted environment preflight, rely on local macOS validation for Swift test signal
- [ ] No new compiler warnings
- [ ] No hardcoded user-visible strings (all in String Catalog)
- [ ] No force-unwrap (`!`) in production code
- [ ] Commit messages follow conventional format (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)

Documentation-only PRs that do not touch code, generated files, project files, entitlements, release metadata, or build settings may use the documentation consistency checks described in [TESTING.md](TESTING.md) instead of Rust/Xcode test runs.

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
- [ ] Human review obtained for files listed in [SECURITY.md](SECURITY.md) Section 10
- [ ] Crash recovery distinguishes safe cleanup, retryable failure, and unrecoverable failure correctly
- [ ] Retryable recovery failures keep retry flags set; unrecoverable states clear flags and surface a generic warning
- [ ] Startup diagnostics remain generic and do not leak fingerprints or key identifiers
- [ ] Secure Enclave custody failure mapping uses shared key operation failure categories and does not leak plaintext, private material, session keys, KEKs, Keychain locators, fingerprints, or temporary capability paths
- [ ] Secure Enclave custody external private-operation callbacks use typed generated callback errors and sanitized categories, not free-form strings that later need to be parsed from Sequoia errors
- [ ] Recipient matching maps only a real generated `NoMatchingKey` to `.noMatchingKey`; file I/O, cancellation, corrupt data, unsupported algorithms, and infrastructure failures must not be collapsed into recipient mismatch
- [ ] Secure Enclave custody handle changes keep signing and key-agreement handles distinct, use `kSecClassKey`/`kSecAttrTokenIDSecureEnclave`, preserve biometrics-only private-key usage access control, and never reuse the legacy `se-key` / `salt` / `sealed-key` wrapping bundle
- [ ] Secure Enclave custody inventory, cleanup, and local reset paths delete only app-owned custody handles, treat missing handles as idempotent cleanup, fail closed on list/delete/remaining-row errors, and expose only sanitized role/category/count metadata
- [ ] Secure Enclave custody hardware-evidence changes remain guarded in the device-only test plan, skip when Secure Enclave or biometrics are unavailable, and do not make Secure Enclave custody product-selectable
- [ ] ProtectedData changes preserve the app-data/private-key-material boundary: no SE-wrapped private-key bundle bytes are copied into ProtectedData payloads
- [ ] ProtectedData changes preserve registry authority, explicit pending-mutation recovery, no-silent-reset behavior, relock zeroization, and `restartRequired` fail-closed semantics
- [ ] ProtectedData changes that migrate a persisted surface update `PERSISTED_STATE_INVENTORY.md`, `ARCHITECTURE.md`, `SECURITY.md`, `TDD.md`, `TESTING.md`, and `CODE_REVIEW.md` as needed
- [ ] Contacts changes preserve protected-domain-only production state, no legacy flat-file reads or fallback, runtime-only search/filter/tag-applied recipient selection state, per-key manual verification and certification state, relock cleanup, schema migrations that validate before writeback, and the no-package-exchange / mandatory-encrypted-future-backup boundary

## Rust API Changes

Changes to `pgp-mobile/src/lib.rs` public API surface.

- [ ] UniFFI bindings regenerated
- [ ] Swift call sites in `Sources/Services/` updated
- [ ] `PgpError` enum stays 1:1 between Rust and Swift
- [ ] Callback-specific UniFFI errors stay operation-specific and are normalized at the FFI adapter boundary before reaching app/service code
- [ ] Both Profile A and Profile B tested
- [ ] FFI round-trip tests pass (generate in Rust → pass to Swift → pass back → verify)

## UI PRs

Changes to `Sources/App/`.

- [ ] VoiceOver labels on all interactive elements
- [ ] Dynamic Type respected (system text styles, no fixed font sizes)
- [ ] 44×44pt minimum touch targets
- [ ] Liquid Glass compliance (see [CONVENTIONS.md](CONVENTIONS.md#liquid-glass))
- [ ] No business logic in views
- [ ] If a screen model is introduced, the view retains layout, bindings, and presentation wiring only; workflow state, async actions, importer/exporter state, and cleanup move into the model
