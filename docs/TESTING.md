# Testing Guide

> Status: Canonical current-state.
> Purpose: Test layers, test plans, CI lanes, and the build/validation workflows that connect Rust artifacts to Swift testing.
> Audience: Human developers and AI coding tools.
> Update triggers: Test plans, CI lanes, validation commands, or the Rust↔Xcode artifact contract change.
> Last reviewed: 2026-07-05.

## 1. Test Layers

Four layers, distinguished by what they can run on.

### Layer 1: Rust unit and integration tests

No Apple dependency — they exercise the `pgp-mobile` engine directly: per-family key lifecycle and message suites (`portable_legacy_*`, `portable_modern_*`, `portable_modern_high_*`, `portable_pq_*`, `composite_custody_*`), cross-family format selection, password/SKESK, streaming, revocation/certification, QR URL validation, the external signer/decryptor seams, and the security policy suites. The files under `pgp-mobile/tests/` are the source of truth for current coverage.

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

The default run skips tests marked `#[ignore = "slow"]`. CI's blocking lanes add them explicitly:

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test portable_modern_high_slow_tests -- --ignored
cargo +stable test --manifest-path pgp-mobile/Cargo.toml --test large_payload_tests -- --ignored
```

`gnupg_fixture_regression_tests.rs` is fixture-dependent and manual-only.

**Dependency audit.** Run whenever `pgp-mobile/Cargo.lock` changes and before release validation:

```bash
cargo +stable install cargo-audit --version 0.22.2 --locked
cargo +stable audit --file pgp-mobile/Cargo.lock --deny warnings
```

The PR, nightly, and edge workflows pin the same `cargo-audit` version in an independent `rust-dependency-audit` job, and the Xcode Cloud XCFramework workflow runs the audit in `ci_post_clone`. Edge/drill publication and the stable build are gated on a passing audit.

### Layer 2: Swift unit tests

Run on macOS — the unit lane's only working host: the iOS Simulator compiles but the unit-test host app currently fatal-errors at launch under the ProtectedData fail-closed volume probe, so iOS-only behavior is verified through the macOS lane plus real devices. The lane covers the Services layer, Models, and the Security layer through protocol-based mocks — including the ProtectedData framework, the envelope codecs (`CAPKEV1`/`CAPDSEV3`/`CADMKV2`/`CPDENV2`), Secure Enclave custody routing driven by mocks and software P-256 keys, and Contacts SQLCipher persistence. The test files are the source of truth for what is asserted; this document does not maintain prose copies of their coverage.

One mapping rule that is easy to get wrong: recipient matching maps only the generated `NoMatchingKey` error to `CypherAirError.noMatchingKey`. File I/O, cancellation, corrupt data, unsupported algorithms, and other infrastructure failures keep their ordinary app-owned error categories.

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'
```

Localization catalog health is reported outside XCTest. When touching `Sources/Resources/*.xcstrings`, run `python3 scripts/report_localization_catalog.py --github-annotations` or read the PR/nightly Step Summary. It reads `Localizable.xcstrings` and `InfoPlist.xcstrings` and flags stale entries, missing `en`/`zh-Hans` localizations, untranslated units, and incomplete plural categories.

### Layer 3: FFI integration tests

Swift tests that call through the generated UniFFI bindings into real Rust: round-trips across the boundary for the software families, Unicode survival (Chinese, emoji), and 1:1 `PgpError` → Swift error mapping. Memory-leak spot checks (100 encrypt/decrypt cycles under Instruments' Allocations) are manual — Instruments cannot run in CI.

### Layer 4: Device-only tests

Require real Secure Enclave hardware. An Apple Silicon Mac runs the entire lane locally (`-destination 'platform=macOS,arch=arm64e'` — the Mac host has a Secure Enclave); SE-capable iPhones/iPads work too; the iOS Simulator cannot. Biometric steps use Touch ID or the system authentication prompt, and biometric-gated tests guard-and-skip when nothing is enrolled.

The lane carries only what mocks cannot prove: SE wrap/unwrap, custody handle lifecycle, biometric signing and ECDH private operations, custody generation with real handles, end-to-end key-agreement and split-custody composite decrypt, auth-mode switching and crash recovery, the ProtectedData root-secret envelope on real hardware, and MIE. Only the `DeviceMIETests` subset additionally requires A19/A19 Pro-class Hardware Memory Tagging.

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-DeviceTests \
    -destination 'platform=macOS,arch=arm64e'    # or a physical iPhone/iPad
```

Guard every SE-dependent test:

```swift
try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave not available on this device")
```

## 2. Test Plans

Five Xcode test plans. All test invocations — CLAUDE.md, CI configuration, local runs — use explicit `-testPlan` for consistent scope.

- **CypherAir-UnitTests** — Layers 2–3; the default plan on the `CypherAir` scheme. Its `skippedTests` array is a skip-list of `Device*` classes: **every new `Device*` test class must be added there, or it will run — and prompt for biometrics — in the unit lane.**
- **CypherAir-DeviceTests** — Layer 4, selected tests only. Non-destructive.
- **CypherAir-DangerousDeviceTests** — manual, destructive: its Reset All Local Data cleanup proof deletes every app-owned Secure Enclave custody handle for the current bundle, not just test-created ones. Run only against a disposable install or device state.
- **CypherAir-InteropEvidenceTests** — manual macOS-only real-SE↔GnuPG evidence harness (`DeviceSecureEnclaveGnuPGInteropEvidenceTests`); needs real Secure Enclave hardware, biometric approval, and a local `gpg`. Captured evidence: [SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md) §8.
- **CypherAir-MacUITests** — targeted macOS UI smoke coverage: routes, settings, and tutorial launch/lifecycle flows.

There is no dedicated visionOS test plan; native visionOS validation is the build probe in §2.4.

Tutorial-focused changes: `TutorialSessionStoreTests` is the canonical unit coverage (run it directly with `-only-testing:CypherAirTests/TutorialSessionStoreTests` on the unit plan). Tutorial/UI-test mock-boundary or launch-gating changes additionally need the full Mac UI plan plus Release and `AppStore Candidate Release` macOS build probes, to prove `UITEST_*` app-container paths stay Debug-only.

ProtectedData device-test isolation rules:

- use test-only identifiers of the form `com.cypherair.tests.protected-data.<TestCase>.<UUID>`
- never use the production shared-right identifier in tests
- clean up by identifier before and after each device test
- do not call `removeAllRightsWithCompletion()`

Docs-only changes skip Rust/Xcode runs entirely — the documentation path in [WORKFLOW.md](WORKFLOW.md) §2 (text hygiene, link validity) is sufficient.

## 2.1 GitHub Actions Lanes

PR Checks and the nightly run are the blocking release-readiness signal. Jobs:

- `rust-dependency-audit` — `cargo audit --deny warnings` against `pgp-mobile/Cargo.lock`, as an independent failure signal.
- `rust-full-tests` — the default Rust suite plus the slow targets.
- `rust-gnupg-interop` — installs gpg, asserts the `>= 2.4.0` floor (`scripts/assert_min_gpg_version.sh`), and runs `secure_enclave_gnupg_interop_tests` plus `gnupg_binary_tests` under `CYPHERAIR_REQUIRE_GPG=1`, so a missing gpg fails the lane instead of skipping. Runs parallel to `rust-full-tests`; needs no XCFramework.
- `xcframework-package` — checks OpenSSL carry-chain freshness, downloads the pinned arm64e stage1 toolchain in a token-free pre-build step, runs `./build-xcframework.sh --release`, and uploads the `pgpmobile-xcframework` artifact plus `PgpMobile.arm64e-build-manifest.json` for 5 days.
- `apple-platform-probes` — restores the XCFramework artifact and the pinned SQLCipher dependency (attestation-verified), then runs unsigned `generic/platform=iOS` and `generic/platform=visionOS` build probes when the hosted Xcode 26.5 install is healthy. Hosted runners intentionally carry no CypherAir signing material; signed app builds stay local and on Xcode Cloud.
- `swift-unit-tests-hosted-preview` — hosted macOS `CypherAir-UnitTests` on `platform=macOS,arch=arm64e` after a readiness preflight; hosted-environment mismatches warn-skip (§2.2), while real build/link/test failures fail the job.

`XCFramework Edge Release` (main pushes and manual dispatch) audits, rebuilds, probes, then publishes a unique `pgpmobile-edge-*` prerelease; non-main manual runs must use `pgpmobile-drill-*` prefixes. The stable release path runs on Xcode Cloud and is owned by [RELEASE.md](RELEASE.md); `.github/workflows/stable-release-attest.yml` re-verifies the signed tag, checksums, and SQLCipher record on `release.published` and attests the SDK/compliance assets.

arm64e toolchain consumption: CI force-downloads the pinned `cypherair/rust` stage1 prerelease (tag, slice policy, and toolchain contract owned by [ARM64E_STATUS.md](ARM64E_STATUS.md)) via direct release-asset URLs with token variables scrubbed; `latest` is never allowed. Two TESTING-specific rules on top:

- Rust/XCFramework jobs deliberately use no Cargo cache actions: restored `target/` artifacts can mix compiler generations and break proc-macro builds. Prefer slower clean CI builds.
- App-side Rust or UniFFI changes never wait for a new stage1 prerelease; only changes to the Rust compiler fork itself do.

## 2.2 GitHub Actions Hosted macOS Limitation

The workflows target `macos-26`, but GitHub's hosted image can lag the project's macOS 26.5 deployment target (e.g. report 26.3) or expose Xcode 26.5 before matching platform runtimes are installed. `scripts/ci_xcode_platform_preflight.sh` detects this: hosted-image mismatches emit an explicit warning and skip the affected probe/preview without degrading the XCFramework packaging signal, while project-configuration or missing-destination failures still fail the workflow. Stable release notes record whether hosted probes ran or were skipped; a skipped probe never stands in for release validation. Local macOS validation is the Swift source of truth either way.

## 2.3 Release Flows

Internal/experimental TestFlight uploads use the standard `CypherAir` scheme. The formal App Store candidate path uses `CypherAir AppStore Candidate`, which rejects tracked worktree or index changes and requires `HEAD` to match the remote stable tag commit exactly. Release ordering, gating, and the compliance-asset contract live in [RELEASE.md](RELEASE.md).

## 2.4 Rust Artifacts, UniFFI Outputs, and Xcode Validation

Rust changes under `pgp-mobile/src` do **not** automatically refresh what Xcode links. The project consumes:

- `PgpMobile.xcframework` (git-ignored, locally generated) plus `PgpMobile.arm64e-build-manifest.json`
- `bindings/module.modulemap` plus the generated `Sources/PgpMobile/pgp_mobile.swift`
- `SQLCipher.xcframework` (git-ignored, restored from the pinned external release) plus its manifest, privacy file, and release record

Treat `pgp-mobile/Cargo.lock` updates as artifact inputs too: even a lockfile-only bump needs the audit, Rust tests, and a full sync before Swift validation, so local artifacts are built from the lockfile being submitted. Never commit the ignored XCFramework directories.

### A. Rust behavior validation only

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

Validates Rust logic in isolation; refreshes nothing that Xcode consumes.

### B. Build Rust release archives only

Per-target release archives, for direct inspection; still no XCFramework refresh:

```bash
cargo +stable build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-darwin --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-visionos --manifest-path pgp-mobile/Cargo.toml
cargo +stable build --release --target aarch64-apple-visionos-sim --manifest-path pgp-mobile/Cargo.toml
```

### C. Full UniFFI / bindings / XCFramework sync

Run after any Rust or UniFFI change that can affect Swift-visible behavior (decision choreography: `.claude/skills/rust-sync`):

```bash
ARM64E_STAGE1_FORCE_DOWNLOAD=1 \
ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260618T140657Z-abeb845-r27765229620-a1 \
    ./build-xcframework.sh --release
```

Force-download matches GitHub Actions: it consumes the pinned `cypherair/rust` stage1 prerelease instead of trusting local rustup state, refreshes the stable `arm64` archives, builds `arm64e` archives with the stage1 compiler, regenerates bindings from an `arm64e-apple-darwin` host dylib (whitespace-normalized — never hand-edit generated bindings; rerun the sync), recreates `PgpMobile.xcframework`, and writes the build manifest. The downloader rejects `ARM64E_STAGE1_RELEASE_TAG=latest`; pin rotation follows the re-pin rule in [ARM64E_STATUS.md](ARM64E_STATUS.md) (agent checklist: `.claude/skills/repin-arm64e`). `ARM64E_RUSTC` / `ARM64E_STAGE1_DIR` / a locally linked `stage1-arm64e-patch` toolchain are for deliberate compiler testing only.

Manual bindgen must run from `pgp-mobile/` — the repo root has no `Cargo.toml`:

```bash
cd pgp-mobile
cargo +stable run --release --bin uniffi-bindgen generate \
    --library target/release/libpgp_mobile.dylib \
    --language swift --out-dir ../bindings
```

After a successful sync you may reclaim space with `cargo clean --manifest-path pgp-mobile/Cargo.toml`; the per-target release static archives are intermediates, not Xcode link inputs. Target-specific `libpgp_mobile.dylib` files must not linger next to them — stale dylibs from older direct-link flows can shadow the intended static archives.

### SQLCipher restore

```bash
scripts/restore_sqlcipher_xcframework.sh                        # local
scripts/restore_sqlcipher_xcframework.sh --require-attestation  # CI / Xcode Cloud
```

The script reads `third_party/sqlcipher-xcframework.pin.json`, rejects `latest` and non-stable pins, verifies the zip checksum, release metadata, expected slices/headers/flags, and smoke-tests raw-key good-key read/write plus wrong-key rejection (`scripts/validate_sqlcipher_xcframework.py`). To refresh SQLCipher, publish a new stable immutable release from `cypherair/sqlcipher-xcframework` first, then update the pin file, docs, and tests here.

### Local Xcode validation

```bash
# Swift/FFI source of truth
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS,arch=arm64e'

# Native visionOS build probe (linkage + availability, not a test substitute)
xcodebuild build -scheme CypherAir -destination 'generic/platform=visionOS'
```

| Change type | Run |
|---|---|
| `Cargo.lock` dependency update | audit → Rust tests → sync C → unit plan |
| Rust-backed behavior change | Rust tests → sync C → unit plan → visionOS probe |
| UniFFI surface / bindings / packaging change | Rust tests → sync C → unit plan → visionOS probe |

Stale-artifact symptoms: Rust tests show the new behavior but Swift/FFI tests still show the old one, or new UniFFI symbols are missing at link time. Suspect a stale `PgpMobile.xcframework` or generated bindings before suspecting Swift source.

Two repo-specific gotchas:

- **Script sandboxing.** Xcode user-script sandboxing is enabled for app and test targets; local validation must not depend on `ENABLE_USER_SCRIPT_SANDBOXING=NO`. A Run Script phase must declare every file it reads in `inputPaths`/`inputFileListPaths` and every product in `outputPaths`/`outputFileListPaths` — a parent directory is not recursive access. This covers the script-owned, version-stamped `Settings.bundle/Root.plist`, fixture manifests (update the fixture xcfilelists when adding fixtures), and `.git/HEAD` + `.git/logs/HEAD` for the source-compliance fallback.
- **Contact-import contract.** If a Rust/UniFFI change touches contact-import validation, prove the public-only contract end to end: secret-bearing input is rejected before inspection or persistence, the Rust surface returns `InvalidKeyData` with the stable contact-import reason token, and Swift maps it to the explicit contact-import public-certificate error.

Keep the hygiene gate clean before submitting: `python3 scripts/check_text_hygiene.py` (`rustfmt` is a local courtesy, not a CI gate).

## 3. Family Test Matrix

Crypto tests cover every family the change touches. The software profiles are what most suites parameterize over; the device-bound families get equivalent coverage through the custody unit suites (mocks + software P-256) plus the Layer 4 device lane.

| Test category | Legacy | Modern | Modern · High | Post-Quantum | Post-Quantum · High |
|---|---|---|---|---|---|
| Key generation | v4 Ed25519+X25519 | v6 Ed25519+X25519 | v6 Ed448+X448 | v6 ML-DSA-65+Ed25519 / ML-KEM-768+X25519 | v6 ML-DSA-87+Ed448 / ML-KEM-1024+X448 |
| Encrypt/decrypt round-trip | SEIPDv1 | SEIPDv2 OCB | SEIPDv2 OCB | SEIPDv2 OCB, AES-256 floor | SEIPDv2 OCB, AES-256 floor |
| Sign/verify | v4 sigs | v6 sigs | v6 sigs | v6 composite sigs | v6 composite sigs |
| Tamper | MDC fatal | AEAD fatal | AEAD fatal | AEAD fatal | AEAD fatal |
| Cross-family format | → SEIPDv1 (v4 recipient) | → SEIPDv2 (v6 recipient) | → SEIPDv2 (v6 recipient) | PQ-only → SEIPDv2; mixed w/ v4 → SEIPDv1 + AES-256 floor | PQ-only → SEIPDv2; mixed w/ v4 → SEIPDv1 + AES-256 floor |
| Key export/import S2K | Iterated+Salted | Argon2id | Argon2id | Argon2id | Argon2id |
| GnuPG interop | Yes | Expected rejection | Expected rejection | No claim (LibrePGP divergence) | No claim (LibrePGP divergence) |
| Argon2id memory guard | N/A | Yes | Yes | Yes | Yes |
| SE software-custody wrap | Yes | Yes | Yes | Yes (portable family) | Yes (portable family) |
| Rust suite | `portable_legacy_*` | `portable_modern_*` | `portable_modern_high_*` | `portable_pq_*` | `portable_pq_high_*`, `composite_custody_high_*` |

Password/SKESK round-trips (armored + binary) are recipient-key-independent and covered per message format. Tamper tests for password messages use targeted payload/tag-area mutations, not arbitrary bit flips.

## 4. Writing Tests

- Name tests `test_<unitOfWork>_<scenario>_<expectedResult>`.
- Swift service/security tests use protocol-based mocks (`MockKeychain`, `MockSecureEnclave`, `MockAuthenticator` under `Sources/Security/Mocks/`); Rust tests prefer real Sequoia operations. `MockKeychain` supports deterministic delete-failure injection (`deleteError`, `failOnDeleteNumber`) for crash-recovery tests.
- Assert behavior, not source text: no source-scanning XCTest assertions — architecture conformance is review's job, not a test's.
- Every crypto operation needs a round-trip test per family it supports, a targeted tamper test proving hard-fail with no partial output, and format assertions where the format rule applies (SEIPDv1/v2 selection, AES-256 floor).
- Crash-recovery coverage exercises all four outcomes of the crash-recovery invariant ([SECURITY.md](SECURITY.md) §4): cleanup-only, promote-pending, retryable (keeps flags set), unrecoverable (generic startup warning, no fingerprints).
- Never hardcode key material or ciphertexts; generate fresh keys in setup. Clean up Keychain entries in `tearDown`. Guard device-only tests with `XCTSkipUnless(SecureEnclave.isAvailable)`.

## 5. GnuPG Interoperability

Interop applies to Portable Legacy (software v4) and the Device-Bound Legacy (v4) custody family. **v6 output — Modern, Modern · High, and Device-Bound Modern — is expected to be rejected by GnuPG** (no v6 support; `gnupg_binary_tests::test_gpg_rejects_sequoia_modern_high_pubkey` proves the rejection). The post-quantum families make no GnuPG claim at all — GnuPG follows LibrePGP's different PQ wire format ([POST_QUANTUM.md](POST_QUANTUM.md) §1).

`gpg` runs on macOS only. Two mechanisms:

- **Fixtures** — `gpg`-generated messages/signatures/keys committed as test data; deterministic and CI-safe. Regenerate when the Sequoia version, algorithm selection, or GnuPG major version changes (`gnupg_fixture_regression_tests.rs`, manual).
- **Live lanes** — drive the `gpg` binary through `pgp-mobile/tests/common/gnupg.rs` and its `require_gpg_or_skip()` gate: under `CYPHERAIR_REQUIRE_GPG=1` a missing gpg fails instead of skipping.
  - `gnupg_binary_tests.rs` — Portable Legacy Sequoia↔gpg.
  - `secure_enclave_gnupg_interop_tests.rs` — device-bound legacy (v4) SE-shaped certificates ↔ gpg, bidirectional, through the production external-signer/key-agreement seams driven by a software-P256 stand-in; asserts PKESK v3 + SEIPDv1/MDC, not AEAD.
  - `secure_enclave_v6_aead_evidence_tests.rs` — device-bound modern (v6) SEIPDv2 AEAD correctness through the production seam (no gpg; runs in `rust-full-tests`).

The `rust-gnupg-interop` CI job runs the first two lanes under `CYPHERAIR_REQUIRE_GPG=1` after asserting the gpg version floor. Real-hardware SE↔gpg evidence is the manual `CypherAir-InteropEvidenceTests` plan; captured evidence lives in [SECURE_ENCLAVE_CUSTODY.md](SECURE_ENCLAVE_CUSTODY.md) §8.

## 6. MIE Validation

Run on hardware with Hardware Memory Tagging (A19/A19 Pro class — e.g. iPhone 17, iPhone Air) with the Xcode diagnostic enabled.

| Test | Pass criteria |
|---|---|
| Full workflow (keygen, encrypt, decrypt, sign, verify) across families | Zero tag-mismatch crashes |
| 100 encrypt/decrypt cycles | Zero intermittent tag violations |
| OpenSSL primitives (AES-256, SHA-512, Ed25519/X25519, Ed448/X448, Argon2id) | No memory-tagging violations |
| Console.app + crash logs | No `EXC_GUARD` / `GUARD_EXC_MTE_SYNC_FAULT` entries |
