# Testing Guide

> Purpose: Test strategy, how to run and write tests, and expectations for AI-assisted development.
> Audience: Human developers and AI coding tools.
> Source of truth: validation commands, Rust artifact refresh, and UniFFI/bindings sync for the current workspace.

## 1. Test Layers

CypherAir has four test layers, each with different runtime requirements.

### Layer 1: Rust Unit Tests

**Run on:** macOS (host), CI.
**What they cover:** Sequoia PGP operations in isolation — key generation (both profiles), recipient-key encrypt/decrypt, password/SKESK encrypt/decrypt, sign/verify, armor encode/decode, error mapping, and S2K (Iterated+Salted and Argon2id) export/import.
**No device needed.** These test the `pgp-mobile` crate without any iOS dependency.

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
```

The local default command above skips tests marked `#[ignore = "slow"]`, including
`profile_b_slow_tests` and `large_payload_tests`.

The blocking automation lanes and the XCFramework edge-release workflow run the default suite plus the slow Rust targets explicitly:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml
cargo test --manifest-path pgp-mobile/Cargo.toml --test profile_b_slow_tests -- --ignored
cargo test --manifest-path pgp-mobile/Cargo.toml --test large_payload_tests -- --ignored
```

Fixture-dependent ignored tests in `gnupg_fixture_regression_tests.rs` remain manual and
are not part of the standard GitHub workflows.

### Layer 2: Swift Unit Tests

**Run on:** macOS local validation, iOS Simulator (Apple Silicon), CI.
**What they cover:** Services layer logic, model validation, error message mapping, QR URL parsing/generation, UserDefaults handling, memory zeroing utility, profile selection logic, dedicated password-message service behavior, and ProtectedData framework coverage such as registry bootstrap/classification, wrapped-DMK contract checks, session relock behavior, startup seam validation, bootstrap outcome shaping, protected-data access-gate decisions, storage-root containment, explicit file-protection verification, fail-closed unsupported-volume handling, local-data reset, key-metadata cold-load/migration, and protected-settings handoff-only auto-open behavior. Uses protocol-based mocks for Keychain and SE.

```bash
# Practical local path used in this repository
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Simulator path (also valid when the host/runtime supports it)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'
```

### Layer 3: FFI Integration Tests

**Run on:** iOS Simulator + Physical device.
**What they cover:** Round-trips across the Rust-Swift boundary (both profiles) — generate key in Rust, pass to Swift, pass back, verify identical. Unicode strings (Chinese, emoji) survive round-trip. Each `PgpError` variant maps to the correct Swift enum case. `KeyProfile`, password-message format/status enums, and password decrypt result records cross the FFI boundary.

These tests exist in the Swift test target but call through the UniFFI bindings into Rust.

**Memory leak detection:** Run 100 encrypt/decrypt cycles and monitor with Xcode Instruments (Allocations instrument). This is a **manual** test step — Instruments cannot be automated in CI. Document results in the test report.

### Layer 4: Device-Only Tests

**Run on:** Physical iOS device only. Cannot run in simulator.
**What they cover:** Secure Enclave operations (both profiles), biometric authentication, auth mode switching, crash recovery, MIE hardware memory tagging, and protected-data root-secret Keychain behavior through authenticated `LAContext` handoff.

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=iOS,name=<DEVICE_NAME>'
```

Guard all SE-dependent tests:
```swift
try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available on this device")
```

Guard MIE tests for A19:
```swift
// MIE tests only meaningful on A19/A19 Pro hardware
// Run on all models of iPhone 17 or iPhone Air with Hardware Memory Tagging diagnostics enabled
```

## 2. Test Plans

The workspace currently includes three Xcode Test Plans:

**CypherAir-UnitTests.xctestplan** — Layers 2–3 (Swift unit tests + FFI integration tests). Runs in macOS local validation, simulator, and CI. Excludes device-only tests. Layer 1 (Rust unit tests) runs independently via `cargo test` as a separate CI step. This is the default test plan bound to the `CypherAir` scheme.

Build-input audit tests such as `LocalizationCatalogTests` and the source-audit assertions in `TutorialSessionStoreTests` read a build-time `RepositoryAudit` snapshot bundled into `CypherAirTests.xctest`. This keeps the same static-audit semantics across macOS, iOS Simulator, and physical-device `CypherAir-UnitTests` runs.

`TutorialSessionStoreTests` are the canonical unit-level coverage for the guided tutorial contract. They verify sandbox storage and mocks, the seven-module artifact flow, completion-version persistence, onboarding-to-tutorial handoff, replay unlock rules, unsafe-route blocklisting, output interception, production-page configuration seams, guidance resolver behavior, and source-audit guards that keep tutorial output handling out of production page implementations.

**CypherAir-DeviceTests.xctestplan** — Layer 4 only. Runs on physical device. Includes SE wrapping/unwrapping, biometric auth modes, mode switching, crash recovery, MIE validation, and protected-data root-secret handoff validation.

ProtectedData device-test isolation rules:

- use test-only identifiers of the form `com.cypherair.tests.protected-data.<TestCase>.<UUID>`
- never use the production shared-right identifier in tests
- clean up by identifier before and after each device test
- do not call `removeAllRightsWithCompletion()`

ProtectedData Phase 1 unit-test expectations:

- verify that pre-auth bootstrap never touches the root-secret store or legacy right-store adapter
- verify that pre-auth key-metadata loading queries only the dedicated metadata account and does not touch private-key Keychain rows
- verify that bootstrap can return framework recovery without a trusted registry object
- verify that `.continuePendingMutation` is preserved as an explicit bootstrap outcome
- verify that the access gate distinguishes authorization-required, already-authorized, pending-mutation-recovery, framework-recovery, and no-protected-domain states
- verify that protected-settings refresh auto-opens with a valid handoff context and stays locked without starting interactive authorization when the handoff is absent or disappears
- verify that Reset All Local Data deletes default-account and metadata-account CypherAir Keychain items, treats missing items as success, clears in-memory state, and validates a clean empty ProtectedData state

ProtectedData Phase 2 file-protection expectations:

- verify that default and UI-test ProtectedData roots remain inside `Application Support`
- verify that registry, bootstrap metadata, staged wrapped-DMK files, and committed wrapped-DMK files read back with explicit `NSFileProtectionComplete`
- verify that protected-file promotion preserves explicit file protection on the committed path
- verify that macOS ProtectedData bootstrap fails closed when the storage root is outside `Application Support` or when the volume-capability probe reports that file protection is unavailable
- verify that fresh-install/reset validation uses the nearest existing parent for volume capability probing when `ProtectedData` does not yet exist, without creating the root during validation
- keep lock-state readability semantics as manual/device validation; do not treat repository automation as proof of locked-device behavior

**CypherAir-MacUITests.xctestplan** — Runs the `CypherAirMacUITests` target for targeted macOS UI automation and smoke validation. In the current repo, this lane is complemented by service-level routing and screen-model coverage such as `MacPresentationRoutingTests`, `SelectiveRevocationScreenModelTests`, and `ContactCertificateSignaturesScreenModelTests`. The macOS smoke suite also covers tutorial launch paths for generating Alice's sandbox key, opening key-detail follow-up surfaces, opening sandbox QR / backup surfaces, confirming that tutorial-disabled certificate and selective-revocation routes remain visible but unavailable, and tutorial lifecycle coverage for first-run start/skip, leave confirmation, completion finish, Settings replay, and auth-mode helper-modal automation markers.

There is currently no dedicated visionOS XCTest plan. Native visionOS validation uses a generic build probe together with the existing Rust, macOS-local, and iOS-device validation paths.

**All test commands in CLAUDE.md and CI configuration must use `-testPlan` to ensure consistent scope.**

## 2.1 Current GitHub Actions Lanes

The repository currently treats PR Checks as blocking release-readiness signal
in GitHub Actions.

These jobs must pass on pull requests and nightly validation:

- `rust-full-tests` runs the Rust default suite plus `profile_b_slow_tests` and `large_payload_tests`
- `xcframework-package` checks the arm64e OpenSSL carry-chain freshness, runs `./build-xcframework.sh --release`, uploads the `pgpmobile-xcframework` artifact plus `PgpMobile.arm64e-build-manifest.json` for 5 days, and validates the packaged output with `generic/platform=iOS` and `generic/platform=visionOS` build probes
- `swift-unit-tests-hosted-preview` downloads the `pgpmobile-xcframework` artifact, restores `PgpMobile.xcframework`, and runs hosted macOS `CypherAir-UnitTests`

The repository also publishes unique edge XCFramework prereleases:

- `XCFramework Edge Release` runs on `main` pushes and `workflow_dispatch`, rebuilds and validates the XCFramework, then publishes a unique `pgpmobile-edge-` prerelease for canonical `main` builds; non-main manual runs must use `pgpmobile-drill-*` prefixes
- The arm64e XCFramework path consumes the latest `cypherair/rust` `rust-arm64e-stage1-*` prerelease on GitHub Actions. Stable `arm64` slices are still built with stable Rust, while `arm64e` slices use nightly Cargo with `RUSTC` pointing at the downloaded stage1 compiler.

Toolchain contract:

- `stable` means the official Rust stable channel, not a CypherAir release channel or Rust fork branch.
- The repository root intentionally has no custom `rust-toolchain.toml` override. Use explicit `cargo +stable` / `rustc +stable` for ordinary Rust validation and metadata.
- App-side Rust or UniFFI changes do not require waiting for a new GitHub Rust stage1 prerelease beyond the currently published one. Local full packaging should force-download the latest attested Rust fork stage1 prerelease to match GitHub-hosted release jobs; use a linked `stage1-arm64e-patch` only when deliberately testing a local compiler build.
- Only changes to the Rust compiler fork itself require rebuilding the local stage1 or publishing a new Rust fork stage1 prerelease before app-side arm64e packaging can consume the new compiler.

## 2.2 GitHub Actions Hosted macOS Limitation

The repository workflows target `macos-26`, but GitHub's hosted runner image may still lag the app's minimum deployment target.

At the time of writing:

- Project deployment target: **macOS 26.4**
- Hosted GitHub runner image: **macOS 26.3**

Impact:

- Rust CI remains valid.
- The hosted Swift unit-test preview job can fail before test execution because the runner OS is older than the app/test deployment target.
- The hosted Swift unit-test preview runs as a regular blocking PR check. If it fails before tests start because of the runner OS, diagnose that as a hosted-image mismatch and confirm with local macOS validation.
- Local macOS validation remains the source of truth until GitHub's hosted image catches up or a self-hosted macOS runner is used.

## 2.3 Release Flows

CypherAir distinguishes between:

- internal / experimental TestFlight builds
- formal App Store candidate builds

The release steps and candidate gating rules live in [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md).

- Use the standard `CypherAir` scheme for internal or experimental TestFlight uploads.
- Use `CypherAir AppStore Candidate` only for the formal App Store candidate path.
- The candidate path now rejects tracked worktree or index changes and requires `HEAD` to match the remote stable tag commit exactly.

## 2.4 Rust Artifacts, UniFFI Outputs, and Xcode Validation

Rust changes under `pgp-mobile/src` do **not** automatically refresh the build products that Xcode uses for Swift and FFI validation.

Today, the Xcode project links:

- `PgpMobile.xcframework`
- `PgpMobile.arm64e-build-manifest.json`
- `bindings/module.modulemap`
- `Sources/PgpMobile/pgp_mobile.swift`

`PgpMobile.xcframework` is a local generated artifact. It is ignored by git and must be refreshed with the full sync path below after Rust or UniFFI changes that can affect Swift-visible behavior. The build also emits `PgpMobile.arm64e-build-manifest.json`, which records the Rust stage1 prerelease provenance, the OpenSSL carry-chain commits, and the verified XCFramework slice layout. The shared scheme and app target both check for the XCFramework artifact and fail with a clear error if it is missing.

GitHub Actions package jobs archive the generated `PgpMobile.xcframework` as the `pgpmobile-xcframework` artifact so downstream jobs can restore the exact build product on a clean runner.

The Rust static archives under `pgp-mobile/target/.../release` are intermediate inputs used to create the XCFramework, not Xcode link inputs. After a successful `./build-xcframework.sh --release`, you may reclaim Cargo target space with:

```bash
cargo clean --manifest-path pgp-mobile/Cargo.toml
```

Target-specific `libpgp_mobile.dylib` files must **not** exist next to those intermediate static archives. They are stale build state from older direct-link flows and can shadow the intended static archive if stale project settings or manual linker flags are used. The build script treats the host dylib used for UniFFI bindgen as a temporary artifact and removes it before exiting.

This means there are three distinct workflows:

### A. Rust behavior validation only

Use this when you want to validate Rust logic in isolation.

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

This is the default local path and skips `#[ignore = "slow"]` Rust tests.
It does **not** refresh the release archives or generated UniFFI outputs that Xcode consumes.

### B. Build Rust release archives only

Use this only when you want to refresh or inspect the platform-specific Rust release archives directly. This does **not** refresh the XCFramework artifact that Xcode consumes.

```bash
cargo +stable build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-visionos --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-visionos-sim --manifest-path pgp-mobile/Cargo.toml
```

### C. Full UniFFI / bindings / XCFramework sync

Use this when Rust implementation, the UniFFI surface, generated bindings, headers, or packaged XCFramework artifacts changed, or whenever you want the safest full refresh before Swift / FFI validation.

Recommended path:

```bash
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=latest \
    ./build-xcframework.sh --release
```

Prefer this path after Rust or UniFFI changes because it refreshes the stable `arm64` static archives, builds patched `arm64e` static archives with nightly Cargo plus explicit `RUSTC`, regenerates bindings from an `arm64e-apple-darwin` host dylib, recreates `PgpMobile.xcframework`, writes `PgpMobile.arm64e-build-manifest.json`, and enforces the dylib cleanup/validation that keeps Xcode linking deterministic.

For local packaging, prefer the same force-download mode used by GitHub Actions. It downloads the latest `cypherair/rust` `rust-arm64e-stage1-*` prerelease into `pgp-mobile/target/apple-arm64e-stage1/`, verifies the packaged checksum, and avoids depending on stale or incomplete local `stage1-arm64e-patch` rustup state. `ARM64E_RUSTC`, `ARM64E_STAGE1_DIR`, and the locally linked `stage1-arm64e-patch` toolchain remain supported for Rust-fork development and diagnostics, but release-candidate app artifact refreshes should use the force-download path unless you are deliberately testing a local compiler build.

If you must run the underlying bindgen step manually, run it from `pgp-mobile/`, not from the repo root:

```bash
cd pgp-mobile
cargo +nightly run --release --bin uniffi-bindgen generate \
    --library target/release/libpgp_mobile.dylib \
    --language swift --out-dir ../bindings
```

The repo-root form of this command is not valid in the current workspace because the root directory does not contain a `Cargo.toml`.

### Local Xcode validation

After refreshing the artifacts that apply to your change, validate Swift / FFI behavior locally with:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
```

Treat this macOS-local path as the source of truth for Swift validation until GitHub's hosted macOS image catches up to the project's deployment target.

For native visionOS validation, use a build probe rather than a dedicated XCTest plan:

```bash
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

Treat this as build/linkage and platform-availability validation, not as a substitute for the existing Rust, macOS-local, and iOS-device test matrix.

Recommended flows:

```bash
# Rust-backed behavior change
cargo test --manifest-path pgp-mobile/Cargo.toml
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=latest \
    ./build-xcframework.sh --release
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO

# UniFFI surface / bindings / packaged artifact change
cargo test --manifest-path pgp-mobile/Cargo.toml
ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=latest \
    ./build-xcframework.sh --release
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

Typical stale-artifact symptoms:

- Rust tests reflect the new behavior, but Swift unit tests or FFI integration tests still show the old behavior.
- The app links against an older `PgpMobile.xcframework`, but new UniFFI symbols or generated Swift types are missing.

If that happens, first suspect a stale `PgpMobile.xcframework` or generated UniFFI output rather than stale Swift source.

If a Rust / UniFFI change affects contact import validation, validation must also prove the
stable public-only contract end to end:

- secret-bearing contact-import input is rejected before inspection and persistence
- the Rust surface returns `InvalidKeyData` with the stable contact-import reason token
- Swift maps that stable token to the explicit contact-import public-certificate error

Sections 2.5-2.8 below are the canonical family-level Rust / FFI validation minima after archival of the former Rust/FFI rollout documents.

## 2.5 Revocation Construction Coverage

When changing revocation-construction behavior, validation must cover:

- key-level generation for both profiles
- subkey and User ID revocation construction on the Rust / FFI surface
- if Swift FFI tests reuse armored secret-key fixtures, dearmor them first so the tests exercise the documented `binary-only` revocation-construction contract
- case-insensitive subkey fingerprint acceptance plus selector-miss rejection for subkey fingerprint and `userIdData + occurrenceIndex` selector inputs
- duplicate same-bytes User ID discovery preserving per-occurrence `primary` / `revoked` state
- public-only / unusable-secret rejection returning `InvalidKeyData`
- imported-key availability parity: import immediately stores a key-level revocation signature
- lazy backfill for legacy imported keys with empty `revocationCert`
- revocation export still succeeds when legacy backfill metadata persistence fails, while a fresh service still observes the old persisted state
- export of existing revocation without Secure Enclave unwrap
- ASCII-armored revocation export matching the stored binary signature after `dearmor`
- selective revocation remaining export-on-demand: subkey and User ID revocation export must not mutate `PGPKeyIdentity.revocationCert` or assume a new persisted selective-revocation store

## 2.6 Password / SKESK Coverage

When changing password-message behavior, validation must cover:

- armored and binary round-trip coverage for `seipdv1` and `seipdv2`
- signed and unsigned password-message round-trips
- `noSkesk` classification for recipient-only messages
- deterministic `passwordRejected` coverage only for `SKESK6` / `SEIPDv2`; do not freeze `SKESK4` wrong-password behavior into a cross-layer contract
- mixed `PKESK + SKESK` decrypt through the password path
- packet assertions for `AES-256`, `AEADAlgorithm::OCB` on `seipdv2`, and the pinned `S2K::default()` baseline
- targeted auth/integrity tamper coverage that flips bytes in the encrypted payload/tag area
- generic bit-flip coverage may still return `CorruptData` / `NoMatchingKey`; keep those expectations separate from the targeted auth/integrity tests

## 2.7 Certification / Binding Verification Coverage

When changing certificate-signature verification or User ID certification behavior, validation must cover:

- direct-key verification with `Valid`, `Invalid`, and `SignerMissing` outcomes
- User ID binding verification with `Valid`, `Invalid`, and `SignerMissing` outcomes
- issuer-guided success plus a missing-issuer fallback success path
- parse/type/precondition failure returning `Err(...)` instead of a family-local invalid result
- third-party certification generation followed by successful crypto verification
- contact-scoped screen-model coverage for selector loading, retry/cancel behavior, export orchestration, and result presentation
- app-level coverage that the contact-scoped workflow accepts both `.asc` and `.sig` signature files and that generated armored certification output can be verified through the same workflow
- all four OpenPGP certification kinds: `Generic`, `Persona`, `Casual`, and `Positive`
- selector-based User ID operations using `userIdData + occurrenceIndex`, including out-of-range and bytes-mismatch rejection
- verify-result `certificationKind` matching the signature type for User ID certification signatures
- signer fingerprint contract coverage:
- `Valid` + primary signer path returns the signer certificate primary fingerprint and no subkey fingerprint
- `Valid` + certification-subkey signer path returns the signer certificate primary fingerprint plus the selected subkey fingerprint
- `Invalid` clears both fingerprint fields
- `SignerMissing` clears both fingerprint fields
- public-only certification input rejection and secret-cert-with-no-usable-certifier rejection
- generated certification output being treated as exported artifact bytes, not as an implicit contact mutation or trust-state update

## 2.8 Richer Signature Result Coverage

When changing the richer-signature-result family, validation must cover:

- additive `verify_*_detailed`, `decrypt_detailed`, and file detailed APIs without changing legacy record shapes
- collector preservation of every observed signature result in global parser order, including repeated signers
- compatibility assertions proving `legacy_status` and `legacy_signer_fingerprint` exactly match the corresponding legacy API on the same input
- mixed `valid + unknown`, `expired + bad`, and `expired + unknown` fold behavior
- `UnknownSigner` detailed entries carrying no fingerprint
- unsigned coverage only on detailed APIs that already support unsigned input (`decrypt_detailed` / `decrypt_file_detailed`)
- detached verify setup-failure and payload-failure paths, including `signatures = []` when no per-signature result was observed
- `verify_detached_file_detailed` cancellation returning `OperationCancelled`
- fixed multi-signer Swift FFI fixtures for UniFFI array/record mapping and legacy-compat comparisons
- password-message regression coverage because password decrypt reuses the fixed-session-key decrypt path

## 3. Profile Test Matrix

**Every crypto test must run for both profiles unless explicitly scoped.**

| Test Category | Profile A | Profile B | Notes |
|--------------|-----------|-----------|-------|
| Key generation | v4 Ed25519+X25519 | v6 Ed448+X448 | Verify key version + algo |
| Encrypt/decrypt round-trip | SEIPDv1 | SEIPDv2 OCB | |
| Password/SKESK round-trip | SEIPDv1 | SEIPDv2 OCB | Includes armored + binary coverage |
| Sign/verify | v4 sigs | v6 sigs | |
| Tamper (1-bit flip) | Both | Both | |
| Targeted password-message auth/integrity tamper | MDC fatal | AEAD/integrity fatal | Use targeted payload/tag-area mutations, not arbitrary bit-flips |
| Cross-profile encrypt | A→B recipient | B→A recipient | Format auto-selection |
| Mixed recipients | — | v4+v6 → SEIPDv1 | |
| Key export/import | Iterated+Salted | Argon2id | |
| Key revocation construction | Yes | Yes | Key-level for both profiles; selector tests where applicable |
| GnuPG interop | Profile A only | N/A | |
| Argon2id memory guard | N/A | Profile B only | |
| SE wrap/unwrap | Both | Both | Same wrapping scheme |

## 4. Mock Patterns

### Keychain Mock (Protocol-Based)

Define a protocol that captures Keychain operations. Inject the real or mock implementation.

```swift
protocol KeychainManageable {
    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws
    func load(service: String, account: String) throws -> Data
    func delete(service: String, account: String) throws
}

// Production implementation: calls Security.framework
struct SystemKeychain: KeychainManageable { ... }

// Test implementation: in-memory dictionary
class MockKeychain: KeychainManageable {
    var storage: [String: Data] = [:]
    var saveCalled = false
    var deleteCalled = false
    // ... record calls for verification
}
```

**Current repository note:** `MockKeychain` also supports deterministic failure injection for delete operations so crash-recovery retry semantics can be tested (`retryableFailure` vs `unrecoverable`).

### Secure Enclave Mock

SE operations cannot run in the simulator. Use a protocol with a software fallback for testing.

```swift
protocol SecureEnclaveManageable {
    func generateWrappingKey(accessControl: SecAccessControl) throws -> SEKeyHandle
    func wrap(privateKey: Data, using handle: SEKeyHandle) throws -> WrappedKeyBundle
    func unwrap(bundle: WrappedKeyBundle, using handle: SEKeyHandle) throws -> Data
    func deleteKey(_ handle: SEKeyHandle) throws
}

// Production: CryptoKit SecureEnclave APIs
struct HardwareSecureEnclave: SecureEnclaveManageable { ... }

// Test: software P-256 + AES-GCM (same algorithm, no hardware binding)
class MockSecureEnclave: SecureEnclaveManageable { ... }
```

### Authentication Mock

```swift
protocol AuthenticationEvaluable {
    func canEvaluate(policy: LAPolicy) -> Bool
    func evaluate(policy: LAPolicy, reason: String) async throws -> Bool
}

class MockAuthenticator: AuthenticationEvaluable {
    var shouldSucceed = true
    var biometricsAvailable = true
    // Control behavior in tests
}
```

## 5. Test Naming Convention

```
test_<unitOfWork>_<scenario>_<expectedResult>
```

Examples:
```swift
// Profile-aware naming (preferred for crypto tests)
func test_encrypt_profileA_v4Recipient_producesSEIPDv1()
func test_encrypt_profileB_v6Recipient_producesSEIPDv2()
func test_encrypt_mixedRecipients_v4AndV6_producesSEIPDv1()
func test_decrypt_profileB_aeadTampered_throwsAEADFailure()
func test_generateKey_profileA_producesV4Ed25519()
func test_generateKey_profileB_producesV6Ed448()
func test_export_profileA_usesIteratedSaltedS2K()
func test_export_profileB_usesArgon2idS2K()

// General naming
func test_seWrap_ed448Key_thenUnwrap_returnsIdentical()
func test_decrypt_withWrongKey_throwsNoMatchingKeyError()
func test_modeSwitch_standardToHighSecurity_rewrapsAllKeys()
func test_modeSwitch_crashMidway_recoversOnLaunch()
func test_argon2idGuard_exceeds75Percent_refusesWithError()
func test_unicodeRoundTrip_chineseAndEmoji_preservedAcrossFFI()
func test_urlSchemeParse_malformedBase64_returnsInvalidQRError()
```

## 6. Crypto Test Patterns

### Round-Trip Test (per profile)

Every crypto operation must have a round-trip test proving reversibility.

```swift
func test_encryptDecrypt_profileA_roundTrip_returnsOriginalPlaintext() throws {
    let plaintext = "Hello, 你好, 🔐"
    let keyPair = try pgpMobile.generateKeyPair(name: "Test", email: nil, expiry: nil, profile: .universal)
    
    let ciphertext = try pgpMobile.encrypt(
        plaintext: Data(plaintext.utf8),
        recipients: [keyPair.publicKey],
        signingKey: keyPair.privateKey
    )
    
    let decrypted = try pgpMobile.decrypt(
        ciphertext: ciphertext,
        privateKey: keyPair.privateKey
    )
    
    XCTAssertEqual(String(data: decrypted.plaintext, encoding: .utf8), plaintext)
}

func test_encryptDecrypt_profileB_roundTrip() throws {
    let keyPair = try pgpMobile.generateKeyPair(name: "Test", profile: .advanced)
    let ciphertext = try pgpMobile.encrypt(plaintext: Data("Hello".utf8), recipients: [keyPair.publicKey])
    let decrypted = try pgpMobile.decrypt(ciphertext: ciphertext, privateKey: keyPair.privateKey)
    XCTAssertEqual(String(data: decrypted.plaintext, encoding: .utf8), "Hello")
}
```

### Cross-Profile Test

```swift
func test_encrypt_profileBSender_toProfileARecipient_producesSEIPDv1() throws {
    let senderB = try pgpMobile.generateKeyPair(name: "Sender", profile: .advanced)
    let recipientA = try pgpMobile.generateKeyPair(name: "Recipient", profile: .universal)
    let ciphertext = try pgpMobile.encrypt(
        plaintext: Data("Cross".utf8),
        recipients: [recipientA.publicKey],
        signingKey: senderB.privateKey)
    // Verify: recipient A can decrypt; message format is SEIPDv1
    let result = try pgpMobile.decrypt(ciphertext: ciphertext, privateKey: recipientA.privateKey)
    XCTAssertEqual(String(data: result.plaintext, encoding: .utf8), "Cross")
}
```

### Tamper Test (1-Bit Flip)

Proves integrity checking works (AEAD for Profile B, MDC for Profile A).

```swift
func test_decrypt_withTamperedCiphertext_throwsAEADError() throws {
    let keyPair = try pgpMobile.generateKeyPair(name: "Test", email: nil, expiry: nil, profile: .advanced)
    var ciphertext = try pgpMobile.encrypt(
        plaintext: Data("secret".utf8),
        recipients: [keyPair.publicKey],
        signingKey: nil
    )
    
    // Flip one bit near the middle of the ciphertext
    let midpoint = ciphertext.count / 2
    ciphertext[midpoint] ^= 0x01
    
    XCTAssertThrowsError(try pgpMobile.decrypt(ciphertext: ciphertext, privateKey: keyPair.privateKey)) { error in
        guard let pgpError = error as? PgpError else { return XCTFail("Wrong error type") }
        XCTAssertEqual(pgpError, .AeadAuthenticationFailed)
    }
}
```

### Negative Auth Test

```swift
func test_decrypt_highSecurityMode_biometricsUnavailable_throwsAuthError() async throws {
    let mockAuth = MockAuthenticator()
    mockAuth.biometricsAvailable = false
    
    let service = DecryptionService(authenticator: mockAuth, ...)
    
    await XCTAssertThrowsError(try await service.decrypt(ciphertext: someCiphertext)) { error in
        // Should fail without attempting decryption
    }
}
```

## 7. Recovery-Specific Tests

Crash-recovery logic now distinguishes safe cleanup, successful promotion, retryable failure, and unrecoverable states. Tests should cover:

- complete permanent + stale pending -> cleanup only
- partial permanent + complete pending -> replace permanent from pending
- missing permanent + complete pending -> promote pending
- delete/write failure during recovery -> retryable failure, keep flags set
- no complete bundle in either namespace -> unrecoverable, clear flags, surface startup warning
- startup warning text remains generic and does not leak fingerprints

### Memory Zeroing Test

```swift
func test_privateKeyBytes_zeroedAfterDecrypt() throws {
    var keyBytes = try loadTestPrivateKey()
    let originalCount = keyBytes.count
    
    // Perform operation that should zeroize
    _ = try decryptionService.decryptAndZeroize(using: &keyBytes)
    
    // Verify all bytes are zero
    XCTAssertTrue(keyBytes.allSatisfy { $0 == 0 }, "Key bytes not zeroed")
    XCTAssertEqual(keyBytes.count, originalCount, "Buffer should not be deallocated, just zeroed")
}
```

### Mode Switch Crash Recovery Test (Device Only)

```swift
func test_modeSwitch_crashMidway_recoversOnLaunch() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable)
    
    // Simulate interrupted re-wrap by setting flag and leaving temporary items
    UserDefaults.standard.set(true, forKey: "com.cypherair.internal.rewrapInProgress")
    try keychain.save(someData, service: "com.cypherair.v1.pending-se-key.abcdef...", ...)
    
    // Run recovery
    authManager.checkAndRecoverFromInterruptedRewrap()
    
    // Verify: flag cleared, temporary items removed, original keys intact
    XCTAssertFalse(UserDefaults.standard.bool(forKey: "com.cypherair.internal.rewrapInProgress"))
    XCTAssertThrowsError(try keychain.load(service: "com.cypherair.v1.pending-se-key.abcdef..."))
    XCTAssertNoThrow(try keychain.load(service: "com.cypherair.v1.se-key.abcdef..."))
}
```

## 7. GnuPG Interoperability Tests (Profile A Only)

These tests verify bidirectional compatibility with GnuPG. **Profile B is explicitly excluded from GnuPG interop tests** — Profile B output is expected to be rejected by GnuPG. Verify this in POC test C3.8.

**Execution model:** GnuPG (`gpg`) runs on macOS only — it cannot run on iOS. These tests use one of two approaches:

**Approach A (preferred): Pre-generated fixtures.** Use `gpg` on macOS to generate test data (encrypted messages, signatures, exported keys) and commit them as test fixtures in the Xcode project. The iOS/simulator tests then verify that the App correctly processes these fixtures. This approach is deterministic and works in CI.

**Approach B (Rust layer): Sequoia-to-fixture comparison.** Run interoperability tests entirely in the Rust `pgp-mobile` test suite (Layer 1), comparing Sequoia output against known-good fixtures generated by `gpg`. This avoids any iOS dependency.

| Test | Description |
|------|-------------|
| App encrypt → fixture: `gpg --decrypt` | gpg successfully decrypts App output (verified during fixture generation) |
| App sign → fixture: `gpg --verify` | gpg reports "Good signature" (verified during fixture generation) |
| Fixture: `gpg` encrypt → App decrypt | App successfully decrypts gpg-generated fixture |
| Fixture: `gpg` sign → App verify | App reports valid signature for gpg-generated fixture |
| Tamper App ciphertext → `gpg --decrypt` | gpg reports decryption failure (verified during fixture generation) |
| Import gpg pubkey fixture → App encrypt → verify | Full round-trip across implementations |

**Regenerate fixtures** when: Sequoia version changes, algorithm selection changes, or GnuPG releases a major version.

## 8. MIE Validation Tests

Run on iPhone 17 or iPhone Air (A19/A19 Pro) with Hardware Memory Tagging enabled in Xcode diagnostics. Both profiles.

| Test | Pass Criteria |
|------|--------------|
| Full workflow (keygen, encrypt, decrypt, sign, verify) — both profiles | Zero tag mismatch crashes |
| 100 encrypt/decrypt cycles — both profiles | Zero intermittent tag violations |
| OpenSSL operations (AES-256, SHA-512, Ed25519, X25519, Ed448, X448, Argon2id) | All succeed without memory tagging violations |
| Check Console.app + crash logs | No `EXC_GUARD` or `GUARD_EXC_MTE_SYNC_FAULT` entries |

## 9. AI Coding Expectations

### Every PR Must Include

- Tests for all new or changed functionality. No exceptions. **Both profiles unless explicitly scoped to one.**
- For security changes: both positive and negative tests (see Section 6).
- For new PgpError variants: test that the error is thrown and maps correctly to Swift.
- For UI changes: at minimum, verify the view compiles and renders (snapshot or manual).
- For screen ownership, launch, routing, or tutorial-host refactors: run `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` or an equivalent targeted macOS smoke/routing subset together with the relevant screen-model or routing tests.
- For guided tutorial product, sandbox, output-interception, or completion-state changes: run `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS' -only-testing:CypherAirTests/TutorialSessionStoreTests`, then add the Mac UI plan above when the change affects tutorial launch, routing, or visible tutorial surfaces.

### Coverage Goals

- `pgp-mobile` Rust crate: every public function has at least one positive and one negative test, covering both profiles.
- `Sources/Services/`: each service method has a round-trip or behavior test.
- `Sources/Security/`: every code path (success, each error case) is covered.
- Views (`Sources/App/`): not required to have unit tests, but must not contain business logic.

### When Writing Tests

- Use descriptive names following the convention in Section 5.
- Prefer real Sequoia operations in Rust tests. Prefer mocks for Swift service tests.
- Never hardcode key material or ciphertexts. Generate fresh keys in test setup.
- Clean up Keychain entries in `tearDown` to avoid test pollution.
- Mark device-only tests clearly with `XCTSkipUnless(SecureEnclave.isAvailable)`.

## 10. POC Test Case Reference

The POC Test Plan defines test cases that validated the technical stack. These map to the test layers above:

| POC Category | Layer | Notes |
|-------------|-------|-------|
| C1.x Compilation & Integration | Build verification | One-time setup, not ongoing tests |
| C2A.x Profile A Core PGP | Layer 1 (Rust) + Layer 3 (FFI) | v4/Ed25519, key gen, encrypt/decrypt, sign/verify |
| C2B.x Profile B Core PGP | Layer 1 (Rust) + Layer 3 (FFI) | v6/Ed448, key gen, encrypt/decrypt, sign/verify |
| C2X.x Cross-profile | Layer 1 (Rust) + Layer 3 (FFI) | Format auto-selection |
| C3.x GnuPG Interop | Layer 1 (Rust fixtures) or Layer 2 (Swift fixtures) | Profile A only. Pre-generated fixtures, not live gpg invocation on iOS |
| C4.x Argon2id Memory | Layer 3 + Layer 4 | Profile B only. Memory guard logic + device memory behavior |
| C5.x FFI Boundary | Layer 3 | Both profiles. Round-trips, Unicode, error mapping, leak detection (manual Instruments) |
| C6.x Secure Enclave | Layer 4 (device only) | Both profiles. Wrap/unwrap, lifecycle, deletion |
| C7.x Auth Modes | Layer 4 (device only) | Standard/High Security, mode switching, crash recovery |
| C8.x MIE | Layer 4 (A19 device only) | Both profiles. Hardware memory tagging validation |
