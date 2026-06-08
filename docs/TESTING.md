# Testing Guide

> Status: Canonical current-state.
> Purpose: Test strategy, how to run and write tests, and expectations for AI-assisted development.
> Audience: Human developers and AI coding tools.
> Source of truth: validation commands, Rust artifact refresh, and UniFFI/bindings sync for the current workspace.
> Last reviewed: 2026-06-04.

## 1. Test Layers

CypherAir has four test layers, each with different runtime requirements.

### Layer 1: Rust Unit Tests

**Run on:** macOS (host), CI.
**What they cover:** Sequoia PGP operations in isolation — key generation (both profiles), recipient-key encrypt/decrypt, password/SKESK encrypt/decrypt, sign/verify, armor encode/decode, error mapping, and S2K (Iterated+Salted and Argon2id) export/import. They also cover the Secure Enclave custody Rust boundary: the external P-256 signer and ECDH/session-key proofs plus the hidden/test runtime signer and key-agreement API matrices. These exercise public-only v4/v6 certificate and revocation construction; cleartext, sign-plus-encrypt, detached, expiry-mutation, selective-revocation, and certification signing; recipient-key message and streaming file decrypt; and a negative matrix that fails closed on secret-certificate input, wrong fingerprint/role/digest/public-binding/shared-secret, malformed or zero callback responses, callback cancellation/category propagation, tampered SEIPDv1/MDC and SEIPDv2/AEAD payloads, and any secret-certificate fallback.
**No device needed.** These test the `pgp-mobile` crate without any iOS dependency.

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

The local default command above skips tests marked `#[ignore = "slow"]`, including
`profile_b_slow_tests` and `large_payload_tests`.

The blocking automation lanes and the XCFramework edge-release workflow run the default suite plus the slow Rust targets explicitly:

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test profile_b_slow_tests -- --ignored
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test large_payload_tests -- --ignored
```

Fixture-dependent ignored tests in `gnupg_fixture_regression_tests.rs` remain manual and
are not part of the standard GitHub workflows.

### Rust Dependency Audit

Run the RustSec audit whenever `pgp-mobile/Cargo.lock` changes and before
formal release validation:

```bash
cargo +stable install cargo-audit --version 0.22.1 --locked
cargo +stable audit --file pgp-mobile/Cargo.lock --deny warnings
```

The GitHub PR, nightly, edge XCFramework, and stable release workflows pin
`cargo-audit` to `0.22.1` in an independent `rust-dependency-audit` job. A
failed audit makes the workflow/check fail. PR, nightly, and stable asset
generation can still run for diagnostic signal, but release publication is
gated: edge/drill publishing and stable tag-push publishing both depend on
`rust-dependency-audit` and will not create tags, releases, attestations, or
published release assets unless the audit passes.

### Layer 2: Swift Unit Tests

**Run on:** macOS local validation, iOS Simulator (Apple Silicon), CI.
**What they cover:** Services layer logic, model validation, key operation failure-category vocabulary, error message mapping, QR URL parsing/generation, UserDefaults handling, memory zeroing utility, profile selection logic, dedicated password-message service behavior, ordinary-settings coordinator gating plus protected-settings schema v2 migration, self-test legacy cleanup, temporary/export/tutorial artifact cleanup, and ProtectedData framework coverage such as registry bootstrap/classification, wrapped-DMK contract checks, session relock behavior, startup seam validation, bootstrap outcome shaping, protected-data access-gate decisions, storage-root containment, explicit file-protection verification, fail-closed unsupported-volume handling, local-data reset, post-unlock key-metadata domain schema v2 creation/v1 migration/recovery, key custody capability resolver matrix and failure-category resolution coverage, Secure Enclave custody routing through mocks and software P-256 keys — resolver gating, router routing/blocking/failure-mapping and signing/key-agreement handle lookup, hidden/test generation and public-binding/recovery classification, the signer-route and key-agreement message/file decrypt consumers, software custody unchanged, production-policy blocks, no software fallback, sanitized failure mapping, and source-audit containment, protected-settings handoff-only auto-open behavior, private-key-control migration/recovery behavior, and the root-secret SE device-binding envelope through protocol-based mocks. Uses protocol-based mocks for Keychain and SE. v2 `CAPDSEV2` coverage belongs here first: seal/open round trip, field-length validation, HKDF sharedInfo mismatch, AAD mismatch, AAD-version rejection, ephemeral public-key binding, ciphertext/tag/nonce/salt/public-key tampering, v1-to-v2 migration, registry + Keychain `format-floor` downgrade rejection, `legacy-cleanup` deletion after the next successful v2 open, and Reset deleting the SE binding key.

The Secure Enclave custody decrypt consumers (`PrivateKeyMessageDecryptionService`, `PrivateKeyStreamingFileDecryptionService`) prove software/Secure Enclave dispatch, v4/v6 round-trip, signed-message folding, mixed-recipient and repeated decrypt, and recipient-mismatch/tamper fail-closed-without-partial-plaintext through mocks and software P-256 keys; the existing `DecryptionServiceTests` software round-trip, tamper, and Phase 1/Phase 2 boundary coverage stays green through the router delegation.

```bash
# Practical local path used in this repository
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Simulator path (also valid when the host/runtime supports it)
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=iOS Simulator,name=iPhone 17'
```

### Layer 3: FFI Integration Tests

**Run on:** macOS local validation, iOS Simulator when the host/runtime supports it, and physical device when included in the selected test plan.
**What they cover:** Round-trips across the Rust-Swift boundary (both profiles) — generate key in Rust, pass to Swift, pass back, verify identical. Unicode strings (Chinese, emoji) survive round-trip. Each `PgpError` variant maps to the correct Swift enum case. `KeyProfile`, password-message format/status enums, and password decrypt result records cross the FFI boundary.

These tests exist in the Swift test target but call through the UniFFI bindings into Rust.

**Memory leak detection:** Run 100 encrypt/decrypt cycles and monitor with Xcode Instruments (Allocations instrument). This is a **manual** test step — Instruments cannot be automated in CI. Document results in the test report.

### Layer 4: Device-Only Tests

**Run on:** Physical device only. Cannot run in simulator.
**What they cover:** Secure Enclave operations (both profiles), biometric authentication, auth mode switching, crash recovery, MIE hardware memory tagging, and protected-data root-secret Keychain/Data Protection behavior through authenticated `LAContext` handoff on real hardware. The ProtectedData SE device-binding layer keeps hardware-specific coverage here: real SE key creation, restart and reopen of the v2 root-secret envelope, deletion of the device-binding key producing fail-closed recovery/reset-required state, and proof that the SE unwrap layer does not add a second biometric prompt. Envelope format and migration state-machine coverage should remain in the macOS unit lane through mocks.

For Secure Enclave custody, most coverage stays in the macOS unit lane (mocks plus software P-256 keys); the device lane carries only the real-hardware evidence that cannot be mocked: handle creation/load/delete, biometric signing and ECDH private operations, hidden generation with a real signing handle, and end-to-end key-agreement decrypt. `DeviceSecureEnclaveCustodyDecryptTests` creates and deletes a single test-owned handle pair, decrypts v4/v6 messages and a mixed-recipient file through a real `.keyAgreement` P-256 handle, and confirms a tampered payload hard-fails with no output under one authenticated `LAContext`. The destructive Reset All Local Data cleanup proof is isolated in `CypherAir-DangerousDeviceTests` because it deletes every app-owned Secure Enclave custody handle for the current app bundle, not only handles created by the test. Secure Enclave custody device tests require Secure Enclave plus enrolled biometrics — available on Apple Silicon / T2 Macs and SE-capable iPhones/iPads — and skip elsewhere; only the `DeviceMIETests` subset additionally requires A19/A19 Pro Hardware Memory Tagging.

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'
```

Dangerous custody reset-cleanup evidence is manual-only and must run only on a disposable install or device state:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-DangerousDeviceTests \
    -destination 'platform=<PLATFORM>,name=<DEVICE_NAME>'
```

Guard all SE-dependent tests:
```swift
try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available on this device")
```

Guard MIE tests for supported hardware:
```swift
// MIE tests only meaningful on hardware that supports Hardware Memory Tagging.
// Run on supported A19/A19 Pro-or-newer devices with Xcode diagnostics enabled.
```

## 2. Test Plans

The workspace currently includes four Xcode Test Plans:

**CypherAir-UnitTests.xctestplan** — Layers 2–3 (Swift unit tests + FFI integration tests). Runs in macOS local validation, simulator, and CI. macOS local validation does not execute iOS-only device classes, and any hardware-dependent test that is visible on another destination must guard and skip at runtime. Layer 1 (Rust unit tests) runs independently via `cargo +stable test` as a separate CI step. This is the default test plan bound to the `CypherAir` scheme.

Build-input audit tests such as `LocalizationCatalogTests`, `ArchitectureSourceAuditTests`, and the source-audit assertions in `TutorialSessionStoreTests` read a build-time `RepositoryAudit` snapshot bundled into `CypherAirTests.xctest`. This keeps the same static-audit semantics across macOS, iOS Simulator, and physical-device `CypherAir-UnitTests` runs.

`ArchitectureSourceAuditTests` are the architecture-refactor guardrails. They block new measurable boundary leaks for generated UniFFI types above the adapter boundary, generated error mapper use outside FFI adapters, App-layer `PgpError` handling, SwiftUI or localized presentation policy in `Sources/Models`, ProtectedData / Security implementation vocabulary in `Sources/Models`, ordinary runtime `[Contact]` dependencies, reintroduction of legacy flat Contacts projection types, and view-level key/contact/QR workflow orchestration in route views. Phase 4 added guardrails that keep `PhotosUI` picker types out of ScreenModels, keep service phase, progress, and temporary-artifact internals out of ScreenModel public APIs, and ensure streaming ScreenModels use the per-operation progress reporter passed to the active file operation. SR-FIX-18 interim guardrails keep mock implementations out of production sources except the temporary `Sources/Security/Mocks` tutorial/UI-test debt directory, keep mock implementations out of ProtectedData production files, and block non-mock production references to `MockKeychainError`. After Phase 3 PR3D, production `Sources/` have zero `[Contact]` exceptions. If a future PR intentionally adds a temporary exception, add the file with a reason in the test and explain the deferral in that PR.

FFI error-mapping tests should distinguish operation-specific policy from
general generated-error normalization. Recipient matching maps only generated
`NoMatchingKey` to `CypherAirError.noMatchingKey`; file I/O, cancellation,
corrupt data, unsupported algorithms, and other infrastructure errors must
remain their ordinary app-owned error categories.

When adding, moving, or deleting Swift source files that should be visible to build-input audits, update both `Tests/RepositoryAuditInputs.xcfilelist` and `Tests/RepositoryAuditOutputs.xcfilelist` in the same change. The Xcode user-script sandbox only grants the snapshot phase access to files declared in these manifests.

`TutorialSessionStoreTests` are the canonical unit-level coverage for the guided tutorial contract. They verify sandbox storage and mocks, the seven-module artifact flow, completion-version persistence, onboarding-to-tutorial handoff, replay unlock rules, unsafe-route blocklisting, output interception, production-page configuration seams, guidance resolver behavior, and source-audit guards that keep tutorial output handling out of production page implementations.

**CypherAir-DeviceTests.xctestplan** — Layer 4 only. Runs on physical device. Includes SE wrapping/unwrapping, non-destructive Secure Enclave custody handle-store and hidden-generation evidence, biometric auth modes, mode switching, crash recovery, MIE validation, and protected-data root-secret handoff validation.

**CypherAir-DangerousDeviceTests.xctestplan** — Manual physical-device lane for destructive device evidence. Currently selects only the Secure Enclave custody Reset All Local Data cleanup proof, which enumerates and deletes all app-owned custody `kSecClassKey` rows for the current bundle. Do not run this plan against a device/install that may contain custody handles worth preserving.

ProtectedData device-test isolation rules:

- use test-only identifiers of the form `com.cypherair.tests.protected-data.<TestCase>.<UUID>`
- never use the production shared-right identifier in tests
- clean up by identifier before and after each device test
- do not call `removeAllRightsWithCompletion()`

Current ProtectedData unit-test expectations for the implemented AppData and Contacts protected-domain security surface:

- verify that pre-auth bootstrap never touches the root-secret store or legacy right-store adapter
- verify that pre-auth bootstrap does not load key metadata or enumerate private-key Keychain rows
- verify that bootstrap can return framework recovery without a trusted registry object
- verify that `.continuePendingMutation` is preserved as an explicit bootstrap outcome
- verify that the access gate distinguishes authorization-required, already-authorized, pending-mutation-recovery, framework-recovery, and no-protected-domain states
- verify that generic pending-mutation recovery dispatches by domain handler and refuses target mismatches as framework recovery
- verify that abandoning a first-domain create cleans a provisioned shared resource based on post-removal membership and fails closed if cleanup fails
- verify that post-unlock orchestration opens only committed registered domains with an authenticated `LAContext`, skips pending mutation recovery, and never authorizes without a context
- verify that `private-key-control` migrates `authMode` and private-key recovery journals after app unlock, keeps private-key material out of ProtectedData, participates in relock, and runs private-key recovery checks only after the domain opens
- verify that `key-metadata` pending-create recovery reuses the authenticated `LAContext` for legacy default-account metadata or remains retryable without committing a partial payload, and that legacy cleanup retry deletes already-migrated source rows by fingerprint membership
- verify that key metadata loading starts as locked/loading before app unlock, completes from `key-metadata` after post-unlock orchestration, and does not regress to pre-auth metadata reads or visible empty-key-list flashes
- verify that protected-settings refresh auto-opens with a valid handoff context and stays locked without starting interactive authorization when the handoff is absent or disappears
- verify that ordinary settings stay locked before app authentication, load/save only from `protected-settings` schema v2 after an unlocked post-auth protected-settings handoff, migrate schema v1 plus legacy ordinary values only after verified readback, treat existing schema v2 as authoritative over legacy keys, enter recovery without resetting to defaults when the protected payload is corrupt, persist updates through the coordinator, clear snapshots on relock, and fail closed for resume grace while unavailable
- verify that onboarding, root tint/theme, guided tutorial entry/completion, Settings controls, and encrypt-to-self behavior consume `ProtectedOrdinarySettingsCoordinator` state rather than `AppConfiguration` or `ProtectedSettingsHost`
- verify that Contacts creates an empty protected `contacts` domain after authorized unlock, treats corrupt or missing protected Contacts state as recovery, persists protected mutations across reopen, fails closed on unsupported schema v1 Contacts payloads by routing the domain to recovery (the v1→v2 migration was removed under the 2026-06-08 cutoff), and clears Contacts runtime state on relock or framework reset
- verify that Reset All Local Data deletes default-account and metadata-account CypherAir Keychain items plus app-owned Secure Enclave custody `kSecClassKey` rows, treats missing items as success, clears in-memory state, validates no remaining custody handles, and exposes only sanitized cleanup categories/counts on failure

Current ProtectedData file-protection expectations:

- verify that default and UI-test ProtectedData roots remain inside `Application Support`
- verify that registry, bootstrap metadata, staged wrapped-DMK files, and committed wrapped-DMK files read back with explicit `NSFileProtectionComplete`
- verify that protected-file promotion preserves explicit file protection on the committed path
- verify that macOS ProtectedData bootstrap fails closed when the storage root is outside `Application Support` or when the volume-capability probe reports that file protection is unavailable
- verify that fresh-install/reset validation uses the nearest existing parent for volume capability probing when `ProtectedData` does not yet exist, without creating the root during validation
- keep lock-state readability semantics as manual/device validation; do not treat repository automation as proof of locked-device behavior

Current non-Contacts ProtectedData validation expectations:

- Self-test coverage proves export-only report state and legacy `Documents/self-test/` cleanup.
- Temporary/export/tutorial coverage proves per-operation streaming/decrypted owner directories, owner cleanup, startup cleanup, Reset All Local Data cleanup, verified complete file protection, export handoff ownership, fixed tutorial defaults cleanup, and legacy tutorial defaults UUID cleanup.

Current Contacts validation expectations:

- Contacts validation should prove person-centered merge/preferred/additional/historical key behavior, per-key verification/certification preservation, certification projection and artifact persistence/revalidation, search ranking, tag normalization, unsupported-schema fail-closed behavior, locked/opening/recovery/framework-unavailable route states, relock cleanup, and Encrypt tag batch selection over the protected `contacts` domain without reactivating legacy Contacts files or weakening the implemented protected-domain security lifecycle.
- Phase 3 Contacts contract validation should also cover `ContactService.importContact(...)` added/duplicate/updated/candidate outcomes, the absence of legacy key-replacement runtime outcomes, `ContactsVerificationContext` with historical signer keys, import/tutorial/URL workflows receiving summaries rather than flat `Contact`, and signature/decryption/password-message/certificate-signature signer resolution through `ContactKeyRecord`.
- Contacts package exchange is not active; any future complete Contacts backup must be covered by a separate mandatory encrypted design and test plan.

Docs-only documentation authority or archive PRs do not require Rust or Xcode test runs unless they touch code, generated files, project files, entitlements, release metadata, or build settings. They should still run documentation consistency checks, link checks for active platform references, and `git diff --check`.

**CypherAir-MacUITests.xctestplan** — Runs the `CypherAirMacUITests` target for targeted macOS UI automation and smoke validation. In the current repo, this lane is complemented by service-level routing and screen-model coverage such as `MacPresentationRoutingTests`, `SelectiveRevocationScreenModelTests`, and `ContactCertificateSignaturesScreenModelTests`. The macOS smoke suite also covers tutorial launch paths for generating Alice's sandbox key, opening key-detail follow-up surfaces, opening sandbox QR / backup surfaces, confirming that tutorial-disabled certificate and selective-revocation routes remain visible but unavailable, and tutorial lifecycle coverage for first-run start/skip, leave confirmation, completion finish, Settings replay, and auth-mode helper-modal automation markers. SR-FIX-18 changes to tutorial/UI-test mock wiring or launch gating require this full Mac UI test plan.

There is currently no dedicated visionOS XCTest plan. Native visionOS validation uses a generic build probe together with the existing Rust, macOS-local, and iOS-device validation paths.

**All test commands in CLAUDE.md and CI configuration must use `-testPlan` to ensure consistent scope.**

## 2.1 Current GitHub Actions Lanes

The repository currently treats PR Checks as blocking release-readiness signal
in GitHub Actions.

These jobs must pass on pull requests and nightly validation:

- `rust-dependency-audit` audits `pgp-mobile/Cargo.lock` with `cargo-audit --deny warnings` as an independent failure signal
- `rust-full-tests` runs the Rust default suite plus `profile_b_slow_tests` and `large_payload_tests`
- `xcframework-package` checks the arm64e OpenSSL carry-chain freshness, downloads the arm64e stage1 toolchain in a token-free pre-build step, runs the `./build-xcframework.sh --release` entrypoint without GitHub token variables in the build environment, and uploads the `pgpmobile-xcframework` artifact plus `PgpMobile.arm64e-build-manifest.json` for 5 days
- `apple-platform-probes` downloads the uploaded XCFramework artifact and validates the packaged output with `generic/platform=iOS` and `generic/platform=visionOS` build probes when the hosted runner has a healthy Xcode 26.5 platform/runtime install; during GitHub image rollouts, incomplete Xcode/SDK/runtime installs emit an explicit warning and skip this app-side probe job without changing the XCFramework packaging signal, while project or scheme destination failures still fail the job
- `swift-unit-tests-hosted-preview` checks hosted macOS/Xcode/macOS SDK readiness, requires an `arm64e` macOS test destination, downloads the `pgpmobile-xcframework` artifact, restores `PgpMobile.xcframework`, and runs hosted macOS `CypherAir-UnitTests` on `platform=macOS,arch=arm64e` when the runner can launch the test bundle; hosted environment mismatches emit an explicit warning and skip this preview without changing the XCFramework packaging signal, while project, signing profile, build, link, or test failures after readiness still fail the job

The repository also publishes unique edge XCFramework prereleases:

- `XCFramework Edge Release` runs on `main` pushes and `workflow_dispatch`, starts the independent Rust dependency audit, rebuilds and validates the XCFramework in a read-scoped build job, conditionally runs hosted Apple platform probes when Xcode 26.5 is healthy, then publishes a unique `pgpmobile-edge-` prerelease only after the audit passes; non-main manual runs must use `pgpmobile-drill-*` prefixes, and drill verification commands quote the exact source ref for safe shell copy/paste
- The arm64e XCFramework path consumes the pinned `cypherair/rust`
  `rust-arm64e-stage1-stable196-*` prerelease recorded in
  `docs/ARM64E_STATUS.md` and the GitHub Actions workflow env. CI downloads
  that public toolchain before invoking the build script, then passes
  `ARM64E_STAGE1_DIR` and `ARM64E_RUST_STAGE1_MANIFEST` to the build with token
  variables scrubbed. Stage1 downloads use direct GitHub release asset URLs for
  the pinned tag without `GH_TOKEN`, `GITHUB_TOKEN`, or anonymous releases API
  discovery, including PR validation, manual dry-runs, edge/drill builds,
  nightly builds, and stable asset generation. Stable `arm64` slices are still
  built with official stable Rust, while `arm64e` slices use stable Cargo with
  `RUSTC` pointing at the downloaded stable196 stage1 compiler and its prebuilt
  std payloads. The official path does not use nightly Cargo or `-Zbuild-std`.
- `Stable Build Release` splits asset generation from publishing: `build-stable-release-assets` uses the same hosted Xcode 26.5 platform preflight as edge, runs app-side iOS/visionOS probes only when the runner is platform-ready, records skipped probes in release notes when the hosted image lags, fails before packaging on project or scheme destination regressions, and can upload diagnostic stable asset artifacts even if `rust-dependency-audit` fails. `workflow_dispatch` is dry-run only; `publish-stable-release` runs only for stable tag pushes, depends on both jobs, verifies checked-out `HEAD` against the peeled stable tag commit, revalidates that the current remote tag is an SSH-signed annotated tag for the artifact commit before attestation, and creates the immutable GitHub Release only after the audit passes.

Toolchain contract:

- `stable` means the official Rust stable channel, not a CypherAir release channel or Rust fork branch.
- The repository root intentionally has no custom `rust-toolchain.toml` override. Use explicit `cargo +stable` / `rustc +stable` for ordinary Rust validation and metadata.
- App-side Rust or UniFFI changes do not require waiting for a new GitHub Rust
  stage1 prerelease beyond the currently pinned one. Local full packaging should
  force-download the pinned attested Rust fork stage1 prerelease to match
  GitHub-hosted release jobs; use a linked `stage1-arm64e-patch` only when
  deliberately testing a local compiler build.
- Only changes to the Rust compiler fork itself require rebuilding the local stage1 or publishing a new Rust fork stage1 prerelease before app-side arm64e packaging can consume the new compiler.
- GitHub-hosted Rust and XCFramework jobs intentionally do not use Cargo
  cache actions. The arm64e path can consume a newer Rust fork stage1 while
  `Cargo.lock` and official stable Rust remain unchanged; restoring old
  `target/` artifacts can mix compiler generations and break proc-macro
  builds. Prefer slower clean CI builds over cached Rust artifacts for release
  correctness.

## 2.2 GitHub Actions Hosted macOS Limitation

The repository workflows target `macos-26`, but GitHub's hosted runner image may still lag the app's minimum deployment target or expose an Xcode build before all matching Apple platform runtimes are installed.

Known hosted-image states that the workflows preflight:

- Project deployment target: **macOS 26.5**
- Hosted GitHub runner images can still report **macOS 26.3** or expose Xcode 26.5 before the matching iOS/visionOS 26.5 platform probes are usable

Impact:

- Rust CI remains valid.
- The hosted Swift unit-test preview uses `scripts/ci_xcode_platform_preflight.sh macos-unit-test-preflight` to detect when the runner OS, selected Xcode, or macOS SDK cannot launch the app/test deployment target; those hosted-image mismatches emit a warning and skip the preview.
- When the hosted Swift unit-test preview passes readiness and starts `xcodebuild test`, build, link, and test failures remain code or project failure signals. Local macOS validation remains the Swift source of truth while GitHub's hosted image catches up.
- PR, nightly, edge, and stable Apple platform probes use `scripts/ci_xcode_platform_preflight.sh` to detect incomplete Xcode 26.5 hosted platform installs and skip those app probes with a warning while keeping the XCFramework packaging and stable asset-generation signals clean; `xcodebuild -showdestinations` project failures or missing generic iOS/visionOS destinations are treated as configuration regressions and fail the workflow.
- Formal stable release notes record whether hosted app-side probes passed or were skipped. A skipped hosted probe does not stand in for release validation; local App Store candidate validation remains the source of truth while GitHub's hosted image catches up.
- Continue using local macOS validation until GitHub's hosted image catches up or a self-hosted macOS runner is used.

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

Treat `pgp-mobile/Cargo.lock` updates as Rust artifact inputs. Even when a
lockfile-only dependency update does not change Rust source or UniFFI surface,
run the dependency audit, Rust tests, and the full XCFramework sync before
Swift / FFI validation so local generated artifacts are built from the same
lockfile that will be submitted. Do not submit the ignored
`PgpMobile.xcframework` directory itself.

Xcode user-script sandboxing is enabled for app and test targets. Local `xcodebuild` validation must not depend on `ENABLE_USER_SCRIPT_SANDBOXING=NO`. When adding or modifying a Run Script phase, declare every file the script reads in `inputPaths` or an `inputFileListPaths` file, and declare every generated or modified build product in `outputPaths` or an `outputFileListPaths` file. A parent directory input is not a substitute for recursive child-file access under the sandbox. This includes generated bundle resources such as `Settings.bundle/Root.plist`, fixture/source audit manifests, and repository metadata such as `.git/HEAD` plus `.git/logs/HEAD` for the source-compliance fallback. The app's `Settings.bundle` is copied and version-stamped by its script phase rather than by the Resources phase so the sandboxed script owns the generated bundle output. When adding fixture resources or repository-audited source files, update the matching `Tests/*.xcfilelist` manifests in the same change.

GitHub Actions package jobs archive the generated `PgpMobile.xcframework` as the `pgpmobile-xcframework` artifact so downstream jobs can restore the exact build product on a clean runner.

The Rust static archives under `pgp-mobile/target/.../release` are intermediate inputs used to create the XCFramework, not Xcode link inputs. After a successful `./build-xcframework.sh --release`, you may reclaim Cargo target space with:

```bash
cargo clean --manifest-path pgp-mobile/Cargo.toml
```

Target-specific `libpgp_mobile.dylib` files must **not** exist next to those intermediate static archives. They are stale build state from older direct-link flows and can shadow the intended static archive if stale project settings or manual linker flags are used. The build script treats the host dylib used for UniFFI bindgen as a temporary artifact and removes it before exiting.

Before submitting Rust or generated-binding work, keep the repository hygiene gates clean:

```bash
cargo +stable fmt --manifest-path pgp-mobile/Cargo.toml --all -- --check
python3 scripts/check_text_hygiene.py
```

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
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
    ./build-xcframework.sh --release
```

Prefer this path after Rust or UniFFI changes because it refreshes the stable `arm64` static archives, builds patched `arm64e` static archives with stable Cargo plus explicit `RUSTC` and prebuilt std payloads, regenerates bindings from an `arm64e-apple-darwin` host dylib, recreates `PgpMobile.xcframework`, writes `PgpMobile.arm64e-build-manifest.json`, and enforces the dylib cleanup/validation that keeps Xcode linking deterministic.

The sync script normalizes generated Swift bindings, C headers, and modulemaps by stripping trailing whitespace before copying them into `bindings/` and `Sources/PgpMobile/`. Do not hand-edit generated binding whitespace; rerun the sync path instead.

For local packaging, prefer the same force-download mode used by GitHub Actions.
It downloads the pinned `cypherair/rust` `rust-arm64e-stage1-stable196-*`
prerelease into `pgp-mobile/target/apple-arm64e-stage1/`, verifies the packaged
checksum, validates the stable196 prebuilt-std manifest, and avoids depending on
stale or incomplete local `stage1-arm64e-patch` rustup state. The downloader
rejects `ARM64E_STAGE1_RELEASE_TAG=latest`; when a new Rust fork stage1
prerelease becomes the official input, update the workflow env, script default,
`docs/ARM64E_STATUS.md`, and the workflow hardening tests in the same PR.
`ARM64E_RUSTC`, `ARM64E_STAGE1_DIR`, and the locally linked
`stage1-arm64e-patch` toolchain remain supported for Rust-fork development and
diagnostics, but release-candidate app artifact refreshes should use the
force-download path unless you are deliberately testing a local compiler build.

If you must run the underlying bindgen step manually, run it from `pgp-mobile/`, not from the repo root:

```bash
cd pgp-mobile
cargo +stable run --release --bin uniffi-bindgen generate \
    --library target/release/libpgp_mobile.dylib \
    --language swift --out-dir ../bindings
```

The repo-root form of this command is not valid in the current workspace because the root directory does not contain a `Cargo.toml`.

### Local Xcode validation

After refreshing the artifacts that apply to your change, validate Swift / FFI behavior locally with:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'
```

Treat this macOS-local arm64e path as the source of truth for Swift validation until GitHub's hosted macOS image catches up to the project's deployment target and has the project provisioning profiles required for signed Keychain/ProtectedData coverage.

For native visionOS validation, use a build probe rather than a dedicated XCTest plan:

```bash
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO
```

Treat this as build/linkage and platform-availability validation, not as a substitute for the existing Rust, macOS-local, and iOS-device test matrix.

Recommended flows:

```bash
# Cargo.lock dependency update
cargo +stable audit --file pgp-mobile/Cargo.lock --deny warnings
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
    ./build-xcframework.sh --release
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'

# Rust-backed behavior change
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
    ./build-xcframework.sh --release
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
xcodebuild build -scheme CypherAir \
    -destination 'generic/platform=visionOS' \
    CODE_SIGNING_ALLOWED=NO

# UniFFI surface / bindings / packaged artifact change
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 \
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
- Secure Enclave custody revocation export using only the stored revocation artifact; missing artifacts fail closed without private-key unwrap or lazy backfill
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

- detailed `verify_*_detailed`, `decrypt_detailed`, and detailed file APIs as
  the primary verification/decrypt surface
- collector preservation of every observed signature result in global parser order, including repeated signers
- mixed `valid + unknown`, `expired + bad`, and `expired + unknown` fold behavior
- `UnknownSigner` detailed entries carrying no fingerprint
- unsigned coverage on detailed APIs that support unsigned input (`decrypt_detailed` / `decrypt_file_detailed`)
- detached verify setup-failure and payload-failure paths, including `signatures = []` when no per-signature result was observed
- `verify_detached_file_detailed` cancellation returning `OperationCancelled`
- fixed multi-signer Swift FFI fixtures for UniFFI array/record mapping and exact fixture payload expectations
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

### Mode Switch Journal Recovery Test (Device Only)

```swift
func test_modeSwitch_crashMidway_recoversOnLaunch() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable)

    // Simulate interrupted re-wrap by writing the post-unlock recovery journal
    // and leaving temporary items.
    try privateKeyControlStore.beginRewrap(targetMode: .highSecurity)
    try privateKeyControlStore.markRewrapCommitRequired()
    try keychain.save(someData, service: "com.cypherair.v1.pending-se-key.abcdef...", ...)

    // Run recovery after app unlock has opened private-key-control.
    authManager.checkAndRecoverFromInterruptedRewrap(fingerprints: ["abcdef..."])

    // Verify: journal cleared, temporary items removed, original keys intact
    XCTAssertNil(try privateKeyControlStore.recoveryJournal().rewrapTargetMode)
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

Run on supported A19/A19 Pro-or-newer hardware with Hardware Memory Tagging enabled in Xcode diagnostics. Current examples include iPhone 17 and iPhone Air devices that expose the diagnostic. Test both profiles.

| Test | Pass Criteria |
|------|--------------|
| Full workflow (keygen, encrypt, decrypt, sign, verify) — both profiles | Zero tag mismatch crashes |
| 100 encrypt/decrypt cycles — both profiles | Zero intermittent tag violations |
| OpenSSL operations (AES-256, SHA-512, Ed25519, X25519, Ed448, X448, Argon2id) | All succeed without memory tagging violations |
| Check Console.app + crash logs | No `EXC_GUARD` or `GUARD_EXC_MTE_SYNC_FAULT` entries |

## 9. AI Coding Expectations

### Functional PRs Must Include

- Tests for all new or changed functionality. No exceptions. **Both profiles unless explicitly scoped to one.**
- For security changes: both positive and negative tests (see Section 6).
- For new PgpError variants: test that the error is thrown and maps correctly to Swift.
- For UI changes: at minimum, verify the view compiles and renders (snapshot or manual).
- For screen ownership, launch, routing, or tutorial-host refactors: run `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'` or an equivalent targeted macOS smoke/routing subset together with the relevant screen-model or routing tests.
- For SR-FIX-18 mock-boundary or UI-test launch-gating changes: run the full `CypherAir-MacUITests` plan plus Release and `AppStore Candidate Release` macOS build probes to prove `UITEST_*` app-container paths are ignored outside Debug.
- For guided tutorial product, sandbox, output-interception, or completion-state changes: run `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS' -only-testing:CypherAirTests/TutorialSessionStoreTests`, then add the Mac UI plan above when the change affects tutorial launch, routing, or visible tutorial surfaces.

Documentation-only PRs that do not touch code, generated files, project files, entitlements, release metadata, or build settings may use the documentation-only validation path in Section 2 instead of Rust/Xcode test runs.

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
| C8.x MIE | Layer 4 (supported hardware only) | Both profiles. Hardware memory tagging validation |
