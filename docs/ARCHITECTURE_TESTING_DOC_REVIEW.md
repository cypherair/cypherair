# Code-Baseline Verification of `ARCHITECTURE_TESTING_DOC_REVIEW.md`

## Executive Summary

This document verifies the findings previously listed in `docs/ARCHITECTURE_TESTING_DOC_REVIEW.md`
against the current repository state.

Verification rules for this pass:

- Primary facts come from code, tests, test plans, workflows, and on-disk layout.
- `docs/ARCHITECTURE.md`, `docs/TESTING.md`, and `CLAUDE.md` are comparison targets, not
  facts in their own right.
- The earlier review content was treated as a claim list only, never as evidence.

Verdict summary:

| ID | Verdict | Severity assessment | Short note |
|---|---|---|---|
| A-1 | Partially confirmed | Keep `High` | The doc flow is stale, but the Swift service still uses `parseRecipients(...)` as its own phase-1 entrypoint name. |
| A-2 | Confirmed | Keep `Medium` | The crate tree is stale and still references a missing `uniffi.toml`. |
| A-3 | Confirmed | Lower to `Medium` | The mismatch is real, but it documents a behavior limit rather than a security boundary. |
| A-4 | Confirmed | Keep `Medium` | The storage section misses real files, temp paths, and defaults. |
| A-5 | Confirmed | Keep `Medium` | The URL import flow now has more coordinator and gating stages than the doc shows. |
| A-6 | Confirmed | Keep `Medium` | The documented ownership of zeroing helpers no longer matches the code split. |
| T-1 | Confirmed | Keep `High` | The FFI layer description conflicts with the active Xcode test-plan layout. |
| T-2 | Confirmed | Keep `High` | Several snippets no longer match the shipping APIs. |
| T-3 | Confirmed | Keep `Medium` | The mock seams in the guide lag the real protocols. |
| T-4 | Partially confirmed | Keep `Medium` | Direct mapping coverage is incomplete for some newer variants, but broader behavior coverage exists elsewhere. |
| T-5 | Confirmed | Keep `Low` | The workflow note over-generalizes `macos-26`. |
| T-6 | Confirmed | Keep `Low` | The duplicated section number is real. |
| C-1 | Partially confirmed | Lower to `Low` | There is a real omission in `CLAUDE.md`, but it is more incomplete than contradictory. |

Totals:

- Confirmed: 10
- Partially confirmed: 3
- Not supported: 0

## Source Priority

Primary evidence used for every verdict:

- `Sources/`
- `pgp-mobile/src/`
- `Tests/`
- `UITests/`
- `CypherAir-UnitTests.xctestplan`
- `CypherAir-DeviceTests.xctestplan`
- `CypherAir-MacUITests.xctestplan`
- `CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme`
- `.github/workflows/`
- actual file-tree layout under the repo root

Secondary comparison targets:

- `docs/ARCHITECTURE.md`
- `docs/TESTING.md`
- `CLAUDE.md`

## Detailed Verification

### Architecture Findings

#### A-1. Phase-1 decrypt flow documents the wrong matching model

- Verdict: Partially confirmed.
- Code evidence: `Sources/Services/DecryptionService.swift:57-106` dearmors and calls `engine.matchRecipients(...)`; `Sources/Services/DecryptionService.swift:120-156` calls `engine.matchRecipientsFromFile(...)`; `pgp-mobile/src/lib.rs:209-230` explicitly says `parse_recipients` returns PKESK subkey identifiers and that callers should use `match_recipients` for local matching.
- Why the review is correct: The Architecture doc's sequence still shows the Rust side returning recipient key IDs and Swift then matching them locally, which is no longer how the app performs Phase 1.
- Why the review overstates the change: The Swift service still exposes `parseRecipients(...)` and `parseRecipientsFromFile(...)` as its own Phase-1 entrypoints. What changed is the Rust API used underneath, not the service method name.
- Severity assessment: Keep `High`. This is a security-critical flow, and the doc currently attributes matching to the wrong layer.
- Recommendation assessment: Keep, but make it more precise: update the flow to show `DecryptionService.parseRecipients(...)` delegating to Rust `matchRecipients(...)` / `matchRecipientsFromFile(...)`.

#### A-2. Rust crate inventory is stale

- Verdict: Confirmed.
- Code evidence: the live tree includes `pgp-mobile/src/cert_signature.rs`, `pgp-mobile/src/signature_details.rs`, `pgp-mobile/uniffi-bindgen.rs`, and `pgp-mobile/bindings/`; there is no `pgp-mobile/uniffi.toml`; `pgp-mobile/src/lib.rs` uses UniFFI proc-macro scaffolding.
- Why the review is correct: The Architecture doc's crate tree omits real files and still lists a `uniffi.toml` that does not exist.
- Severity assessment: Keep `Medium`.
- Recommendation assessment: Keep. Refresh the tree and mention the proc-macro-based UniFFI setup plus generated binding outputs.

#### A-3. `DiskSpaceChecker` is documented as replacing the fixed 100 MB limit

- Verdict: Confirmed.
- Code evidence: `Sources/Services/EncryptionService.swift:72-93` still enforces a fixed `100 * 1024 * 1024` limit in `encryptFile(...)`; `Sources/Services/EncryptionService.swift:108-127` uses `diskSpaceChecker.validateForEncryption(...)` only in `encryptFileStreaming(...)`.
- Why the review is correct: The Architecture table says `DiskSpaceChecker` replaced the fixed 100 MB limit, but non-streaming file encryption still keeps that hard cap.
- Severity assessment: Lower to `Medium`. The mismatch is real and user-visible, but it is not a security-boundary error.
- Recommendation assessment: Keep. The doc should narrow `DiskSpaceChecker` to streaming preflight validation and separately mention the non-streaming in-memory limit.

#### A-4. Storage layout is incomplete and partially outdated

- Verdict: Confirmed.
- Code evidence: `Sources/Services/ContactRepository.swift:82-87` stores `contact-metadata.json`; `Sources/App/AppStartupCoordinator.swift:45-57` cleans both `tmp/decrypted/` and `tmp/streaming/`; `Sources/Models/AppConfiguration.swift:65-97` persists `guidedTutorialCompletedVersion` and `colorTheme`; `Sources/Models/AppConfiguration.swift:139-145` defaults `colorTheme` to `.systemDefault`; `Sources/App/AppContainer.swift:113-122` writes `com.cypherair.preference.uiTestBypassAuthentication` for the UI-test container; `Sources/App/Keys/KeyDetailScreenModel.swift:135-157` routes revocation export through the export controller instead of a persistent `Documents/revocation/` folder.
- Why the review is correct: The Architecture storage section omits real contact metadata, startup cleanup for `tmp/streaming/`, the guided-tutorial completion key, and the current color-theme default.
- Why the review is also correct about revocation export: the current flow prepares exported revocation data for `fileExporter` presentation, not for storage in an app-managed revocation directory.
- Important nuance: `com.cypherair.preference.uiTestBypassAuthentication` is real, but it is test-container state rather than ordinary runtime preference storage. It belongs in a verification note, not in the main app-storage inventory.
- Additional check: `Sources/Services/SelfTestService.swift:3-5` still supports `Documents/self-test/`, so the review was right to leave that part alone.
- Severity assessment: Keep `Medium`.
- Recommendation assessment: Keep, with the test-only nuance above.

#### A-5. URL import flow omits the current coordinator and loader workflow

- Verdict: Confirmed.
- Code evidence: `Sources/Services/QRService.swift:43-87` parses and validates the URL and returns public-key bytes only; `Sources/Services/QRService.swift:92-105` performs public-certificate inspection; `Sources/App/Contacts/Import/PublicKeyImportLoader.swift:22-33` turns URL bytes into `PublicKeyImportInspection`; `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift:25-57` blocks import while the guided tutorial is active and routes the inspection into UI flow; `Sources/App/Contacts/Import/ContactImportWorkflow.swift:23-123` owns verified/unverified import and replacement confirmation.
- Why the review is correct: The current import path is more layered than the Architecture doc shows. Parsing, inspection, tutorial gating, confirmation, and replacement handling are now distinct steps.
- Severity assessment: Keep `Medium`.
- Recommendation assessment: Keep.

#### A-6. Memory-zeroing component description no longer matches file ownership

- Verdict: Confirmed.
- Code evidence: `Sources/Security/MemoryZeroingUtility.swift:3-52` defines `SensitiveData`; `Sources/Extensions/Data+Zeroing.swift:3-40` owns the `Data.zeroize()` and `Array<UInt8>.zeroize()` extensions.
- Why the review is correct: The Architecture security table attributes the extension-based zeroing helpers to `MemoryZeroingUtility`, but the code split is now `SensitiveData` in one file and zeroing extensions in another.
- Severity assessment: Keep `Medium`. This is contributor-facing architectural drift even though it does not change runtime behavior.
- Recommendation assessment: Keep.

### Testing Findings

#### T-1. Test-layer platform description is internally inconsistent

- Verdict: Confirmed.
- Code evidence: `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1-6` shows FFI tests are ordinary `XCTestCase`s in the Swift test bundle; `CypherAir-UnitTests.xctestplan:18-33` runs the `CypherAirTests` target and skips only device-only test classes; `CypherAir-DeviceTests.xctestplan:18-36` selects the device-specific classes; `.github/workflows/pr-checks.yml:22-32` and `.github/workflows/nightly-full.yml:20-26` run `CypherAir-UnitTests` on macOS.
- Why the review is correct: The active test-plan layout says FFI integration tests run wherever `CypherAir-UnitTests` runs, which includes the macOS-local and macOS-CI path documented elsewhere in the repo.
- Severity assessment: Keep `High`.
- Recommendation assessment: Keep.

#### T-2. Several Testing Guide code examples no longer compile against current APIs

- Verdict: Confirmed.
- Code evidence: `Sources/PgpMobile/pgp_mobile.swift:637-714` exposes `generateKey(...)`, `encrypt(...)`, `encryptFile(...)`, `matchRecipients(...)`, and `matchRecipientsFromFile(...)`; `Sources/Services/DecryptionService.swift:35-46` takes `engine`, `keyManagement`, and `contactService` in its initializer; `Sources/Security/AuthenticationManager.swift:355-392` requires `checkAndRecoverFromInterruptedRewrap(fingerprints:)`; no shipping API matches `pgpMobile.generateKeyPair(...)`, `decrypt(... privateKey:)`, `DecryptionService(authenticator: ...)`, or `decryptAndZeroize(...)`.
- Why the review is correct: The Testing guide still contains multiple stale names and signatures that do not match the current code.
- Severity assessment: Keep `High`.
- Recommendation assessment: Keep.

#### T-3. Mock interface examples no longer match current protocols

- Verdict: Confirmed.
- Code evidence: `Sources/Security/KeychainManageable.swift:10-46` adds `exists(...)` and `listItems(...)`; `Sources/Security/SecureEnclaveManageable.swift:30-75` adds `authenticationContext` parameters plus static `isAvailable`; `Sources/Security/AuthenticationEvaluable.swift:59-82` is mode-based and exposes `isBiometricsAvailable` and `lastEvaluatedContext`.
- Why the review is correct: The guide's mock protocols no longer match the actual seams that tests and production code use.
- Severity assessment: Keep `Medium`.
- Recommendation assessment: Keep.

#### T-4. Direct `PgpError -> CypherAirError` mapping coverage is narrower than implied

- Verdict: Partially confirmed.
- Code evidence: `Sources/Models/CypherAirError.swift:135-178` maps `.OperationCancelled`, `.FileIoError`, and `.KeyTooLargeForQr`; `Tests/ServiceTests/ModelTests.swift:11-170` has direct constructor-mapping tests for older variants but not dedicated mapping tests for those newer three cases; `Tests/FFIIntegrationTests/FFIIntegrationTests.swift:1564-1610` and `Tests/ServiceTests/StreamingServiceTests.swift:185-257` exercise cancellation behavior at runtime.
- Why the review is correct: Direct, one-assert-per-variant coverage of `CypherAirError.init(pgpError:)` is incomplete for some newer variants.
- Why the review overstates the gap: Cancellation and streaming I/O paths are still exercised elsewhere, so the problem is narrower than "mapping coverage is missing" in general.
- Severity assessment: Keep `Medium`.
- Recommendation assessment: Keep. Either add explicit constructor-mapping tests for the missing variants or narrow the wording in the guide.

#### T-5. The GitHub Actions runner note over-generalizes which jobs use `macos-26`

- Verdict: Confirmed.
- Code evidence: `.github/workflows/pr-checks.yml:10-23` runs the Rust job on `macos-latest` and the Swift job on `macos-26`; `.github/workflows/nightly-full.yml:8-10` runs the nightly full-validation job on `macos-26`.
- Why the review is correct: Only the Swift/Xcode jobs consistently target `macos-26`; the Rust-only PR job does not.
- Severity assessment: Keep `Low`.
- Recommendation assessment: Keep.

#### T-6. Section numbering is duplicated in the GnuPG section

- Verdict: Confirmed.
- Code evidence: `docs/TESTING.md:466` is `## 7. Recovery-Specific Tests`; `docs/TESTING.md:513` is also `## 7. GnuPG Interoperability Tests (Profile A Only)`.
- Why the review is correct: This is a direct document-structure error.
- Severity assessment: Keep `Low`.
- Recommendation assessment: Keep.

### Cross-Document Finding

#### C-1. `docs/TESTING.md` and `CLAUDE.md` disagree on the complete test-plan picture

- Verdict: Partially confirmed.
- Code evidence: `CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme:25-40` includes `CypherAir-UnitTests`, `CypherAir-MacUITests`, and `CypherAir-DeviceTests`; `CypherAir-MacUITests.xctestplan:18-25` is a real first-class plan; `CLAUDE.md:122` lists only the first two non-UI plans; `docs/TESTING.md:88` and `docs/TESTING.md:553` explicitly call out `CypherAir-MacUITests`.
- Why the review is correct: `CLAUDE.md` omits a real test plan that the scheme exposes and that the Testing guide explicitly names for UI/routing/tutorial refactors.
- Why the review overstates the conflict: This is more an omission in `CLAUDE.md` than a hard contradiction about the default required validation commands.
- Severity assessment: Lower to `Low`.
- Recommendation assessment: Keep, but the fix should be to mention `CypherAir-MacUITests` as a conditional plan rather than to imply it is part of every default validation run.

## Missed by Review

This verification pass did not add new findings outside the review's existing claim set.

Intentional non-expansions:

- No new full-document audit was started.
- No runtime pass/fail claims were added.
- No code or documentation changes outside this verification file were made.

## Verification Status

Static verification commands were sufficient for this pass. No runtime validation was required to
decide the verdicts above.

Representative evidence sources used during verification:

- `rg -n` across `Sources/`, `Tests/`, `UITests/`, `pgp-mobile/src/`, `.github/workflows/`
- `nl -ba` on key implementation files, test plans, and the shared Xcode scheme
- direct file-tree inspection under `pgp-mobile/`, `bindings/`, and the repo root
