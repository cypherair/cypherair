# Architecture and Testing Documentation Review

## Executive Summary

This audit reviews `docs/ARCHITECTURE.md` and `docs/TESTING.md` against the current repository state.

Overall, the two documents still describe the project's direction correctly, but several concrete statements are now stale. The most important mismatches are:

- the two-phase decrypt flow still describes the older `parseRecipients -> local fingerprint match` model instead of the current `matchRecipients` certificate-matching flow
- the Architecture Guide overstates the scope of `DiskSpaceChecker` and has an outdated Rust crate inventory and storage layout
- the Testing Guide is internally inconsistent about where FFI integration tests run
- several Testing Guide code examples and mock interfaces no longer match the current Swift and UniFFI APIs

Severity summary:

| ID | Severity | Area | Summary |
|---|---|---|---|
| A-1 | High | Architecture | Phase-1 decrypt flow documents the wrong Rust API and matching model |
| A-2 | Medium | Architecture | Rust crate file inventory is stale and still references missing `pgp-mobile/uniffi.toml` |
| A-3 | High | Architecture | `DiskSpaceChecker` is documented as replacing the fixed 100 MB limit, but the limit still exists for in-memory file encryption |
| A-4 | Medium | Architecture | Storage layout is incomplete and partially outdated |
| A-5 | Medium | Architecture | QR import flow omits the current loader/coordinator workflow and import gating behavior |
| A-6 | Medium | Architecture | Memory-zeroing component description no longer matches current file ownership |
| T-1 | High | Testing | Test-layer platform descriptions are internally inconsistent and do not match the active test plan layout |
| T-2 | High | Testing | Multiple code examples no longer compile against the current APIs |
| T-3 | Medium | Testing | Mock interface examples no longer match the current protocols |
| T-4 | Medium | Testing | Explicit `PgpError -> CypherAirError` mapping coverage is narrower than the guide implies |
| T-5 | Low | Testing | The GitHub Actions runner note over-generalizes which jobs use `macos-26` |
| T-6 | Low | Testing | Section numbering is duplicated in the GnuPG section |
| C-1 | Medium | Cross-document | `docs/TESTING.md` and `CLAUDE.md` disagree about the complete test-plan set and when `CypherAir-MacUITests` matters |

The issues found here are documentation-fidelity problems, not code changes. This audit did not find a code-level contradiction with the project's core zero-network, Secure Enclave, or AEAD hard-fail rules during the inspected paths.

## Methodology

This was a static, repository-local audit.

- Target documents reviewed:
  - `docs/ARCHITECTURE.md`
  - `docs/TESTING.md`
- Primary evidence sources:
  - `Sources/App/`
  - `Sources/Services/`
  - `Sources/Security/`
  - `Sources/Models/`
  - `pgp-mobile/src/`
  - `Tests/`
  - `UITests/`
  - `CypherAir-UnitTests.xctestplan`
  - `CypherAir-DeviceTests.xctestplan`
  - `CypherAir-MacUITests.xctestplan`
  - `CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme`
  - `.github/workflows/pr-checks.yml`
  - `.github/workflows/nightly-full.yml`
  - `CLAUDE.md`
- Read-only commands used:
  - `rg --files`
  - `rg -n`
  - `sed -n`
  - `nl -ba`
  - `plutil -p`
- Runtime validation commands were not required for the findings below. The mismatches are directly observable from source layout, test plans, workflows, and code signatures.

## Architecture Findings

### A-1. Phase-1 decrypt flow documents the wrong recipient-matching API

- Source document and section:
  - `docs/ARCHITECTURE.md`, Section 3, "Two-Phase Decrypt"
- Documented claim:
  - Phase 1 calls `parseRecipients(ciphertext)` and then "Match against local key fingerprints."
- Actual repository state:
  - `DecryptionService` does not use `parseRecipients` for local matching.
  - It uses `engine.matchRecipients(...)` for in-memory decrypt and `engine.matchRecipientsFromFile(...)` for streaming decrypt.
  - The Rust surface explicitly documents `parse_recipients` as returning encryption subkey identifiers and says callers should use `match_recipients` for correct certificate matching.
- Evidence:
  - `Sources/Services/DecryptionService.swift`
  - `pgp-mobile/src/lib.rs`
  - Example command: `rg -n "parse_recipients|match_recipients|matchRecipients" pgp-mobile/src/lib.rs Sources/Services/DecryptionService.swift`
- Severity:
  - High
- Recommended correction:
  - Update the decryption sequence diagram and surrounding text so Phase 1 is described as "match PKESK recipients against local certificates using `matchRecipients` / `matchRecipientsFromFile`, returning matched primary fingerprints."
  - Keep `parseRecipients` documented only as a lower-level packet-inspection API, not as the app's matching step.

### A-2. Rust crate inventory is stale and still references a missing `uniffi.toml`

- Source document and section:
  - `docs/ARCHITECTURE.md`, Section 2, "Rust Engine (`pgp-mobile/`)"
- Documented claim:
  - The crate tree ends with `uniffi.toml`, and the listed source files are limited to the older subset.
- Actual repository state:
  - `pgp-mobile/uniffi.toml` does not exist.
  - UniFFI scaffolding is proc-macro based (`uniffi::setup_scaffolding!()` in `pgp-mobile/src/lib.rs`), and `pgp-mobile/build.rs` is intentionally empty aside from that explanation.
  - The current crate also contains `cert_signature.rs` and `signature_details.rs`, which are absent from the documented tree.
- Evidence:
  - `pgp-mobile/src/lib.rs`
  - `pgp-mobile/build.rs`
  - `find pgp-mobile -maxdepth 2 -type f | sort`
- Severity:
  - Medium
- Recommended correction:
  - Refresh the crate tree to match the real file set.
  - Remove the `uniffi.toml` entry unless such a file is reintroduced.
  - Mention the proc-macro-based UniFFI setup and the generated binding outputs that the Xcode project consumes.

### A-3. `DiskSpaceChecker` is documented as replacing the fixed 100 MB limit, but it only covers streaming file encryption

- Source document and section:
  - `docs/ARCHITECTURE.md`, Services table, `DiskSpaceChecker`
- Documented claim:
  - `DiskSpaceChecker` "replaces the fixed 100 MB limit."
- Actual repository state:
  - `EncryptionService.encryptFile(...)` still enforces a fixed `100 * 1024 * 1024` size limit for in-memory file encryption.
  - `DiskSpaceChecker.validateForEncryption(...)` is only used in `encryptFileStreaming(...)`.
  - Existing tests still assert the 100 MB limit.
- Evidence:
  - `Sources/Services/EncryptionService.swift`
  - `Sources/Services/DiskSpaceChecker.swift`
  - `Tests/ServiceTests/EncryptionServiceTests.swift`
  - Example command: `rg -n "100 MB|fileTooLarge|validateForEncryption" Sources/Services Tests docs/ARCHITECTURE.md`
- Severity:
  - High
- Recommended correction:
  - Narrow the `DiskSpaceChecker` description to "streaming file encryption preflight disk-space validation."
  - Explicitly state that non-streaming file encryption still has the 100 MB in-memory limit.

### A-4. Storage layout is incomplete and partially outdated

- Source document and section:
  - `docs/ARCHITECTURE.md`, Section 5, "Storage Layout"
- Documented claim:
  - `Documents/contacts/` contains only `.gpg` files.
  - `Documents/revocation/` exists as a managed output directory.
  - `tmp/` includes only `decrypted/`.
  - `com.cypherair.preference.colorTheme` defaults to `"defaultBlue"`.
  - The listed UserDefaults keys are the complete relevant set.
- Actual repository state:
  - Contact storage also includes `contact-metadata.json` for verification state persistence.
  - The codebase includes temp `streaming/` cleanup in startup, not only `decrypted/`.
  - `AppConfiguration.colorTheme` defaults to `.systemDefault`, not `.defaultBlue`.
  - `AppConfiguration` persists `com.cypherair.preference.guidedTutorialCompletedVersion`, which is not documented.
  - UI-test container setup writes `com.cypherair.preference.uiTestBypassAuthentication`.
  - No app-managed `Documents/revocation/` directory was found in the current implementation; revocation export is surfaced through the export controller instead of writing to a persistent app directory.
- Evidence:
  - `Sources/Services/ContactRepository.swift`
  - `Sources/App/AppStartupCoordinator.swift`
  - `Sources/Models/AppConfiguration.swift`
  - `Sources/App/AppContainer.swift`
  - Example command: `rg -n "contact-metadata|guidedTutorialCompletedVersion|uiTestBypassAuthentication|temporaryDirectory|revocation/" Sources Tests docs/ARCHITECTURE.md`
- Severity:
  - Medium
- Recommended correction:
  - Update the storage section to include `contact-metadata.json`, `tmp/streaming/`, and `guidedTutorialCompletedVersion`.
  - Correct the color-theme default to `.systemDefault`.
  - Either document the revocation export as share/export-controller driven or provide the real persistence path if one is later introduced.

### A-5. The URL-import flow omits the current loader/coordinator workflow

- Source document and section:
  - `docs/ARCHITECTURE.md`, Section 3, "URL Scheme Public Key Import"
- Documented claim:
  - `CypherAirApp` calls `QRService.parseImportURL`, `QRService` parses the key details directly, and the app then stores the contact.
- Actual repository state:
  - `QRService.parseImportURL(...)` returns validated public-key bytes only.
  - `PublicKeyImportLoader` performs certificate inspection using `inspectImportablePublicCertificate(...)`.
  - `IncomingURLImportCoordinator` mediates URL handling and can block import while the guided tutorial presentation is active.
  - `ContactImportWorkflow` then manages verified/unverified import and replacement confirmation.
- Evidence:
  - `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift`
  - `Sources/App/Contacts/Import/PublicKeyImportLoader.swift`
  - `Sources/App/Contacts/Import/ContactImportWorkflow.swift`
  - `Sources/Services/QRService.swift`
- Severity:
  - Medium
- Recommended correction:
  - Expand the import flow diagram to show:
    1. URL decode/validation
    2. public-certificate inspection
    3. confirmation workflow
    4. optional key-replacement confirmation
    5. tutorial-time import blocking

### A-6. The memory-zeroing component description no longer matches current file ownership

- Source document and section:
  - `docs/ARCHITECTURE.md`, Security table, `MemoryZeroingUtility`
- Documented claim:
  - `MemoryZeroingUtility` is the component that provides "Extensions on `Data` and `Array<UInt8>` for secure clearing."
- Actual repository state:
  - `Sources/Security/MemoryZeroingUtility.swift` defines `SensitiveData`, an auto-zeroing wrapper object.
  - The `Data.zeroize()` and `Array<UInt8>.zeroize()` extensions live in `Sources/Extensions/Data+Zeroing.swift`.
- Evidence:
  - `Sources/Security/MemoryZeroingUtility.swift`
  - `Sources/Extensions/Data+Zeroing.swift`
- Severity:
  - Medium
- Recommended correction:
  - Either rename the documented component to match the actual file split or document both pieces explicitly:
    - `SensitiveData` in `Sources/Security/MemoryZeroingUtility.swift`
    - `Data` / `Array<UInt8>` zeroing extensions in `Sources/Extensions/Data+Zeroing.swift`

## Testing Findings

### T-1. The test-layer platform description is internally inconsistent

- Source document and section:
  - `docs/TESTING.md`, Section 1, "Test Layers"
- Documented claim:
  - Layer 2 runs on macOS local validation, iOS Simulator, and CI.
  - Layer 3 FFI integration tests run on iOS Simulator plus physical device.
- Actual repository state:
  - `FFIIntegrationTests.swift` is part of the `CypherAirTests` target.
  - `CypherAir-UnitTests.xctestplan` selects only the `CypherAirTests` target and skips device-only test classes.
  - The documented CI and local commands run `CypherAir-UnitTests` on `platform=macOS`.
  - There is no separate physical-device-only FFI integration target or test plan in the current project.
  - Section 2 of the same document already says `CypherAir-UnitTests.xctestplan` covers Layers 2-3, which conflicts with the Layer 3 platform text in Section 1.
- Evidence:
  - `docs/TESTING.md`
  - `CypherAir-UnitTests.xctestplan`
  - `Tests/FFIIntegrationTests/FFIIntegrationTests.swift`
  - `.github/workflows/pr-checks.yml`
  - `.github/workflows/nightly-full.yml`
- Severity:
  - High
- Recommended correction:
  - Reword Layer 3 to say that FFI integration tests live inside the `CypherAirTests` target and therefore run wherever `CypherAir-UnitTests` runs:
    - macOS local validation
    - macOS CI
    - optionally simulator where supported
  - Reserve "physical device only" for Section 4 device-security coverage.

### T-2. Several Testing Guide code examples no longer compile against the current APIs

- Source document and section:
  - `docs/TESTING.md`, Sections 6 and 7
- Documented claim:
  - The provided sample code reflects the current testing surface.
- Actual repository state:
  - The examples use older or nonexistent APIs, including:
    - `pgpMobile.generateKeyPair(...)`
    - `pgpMobile.encrypt(... signingKey:)`
    - `pgpMobile.decrypt(... privateKey:)`
    - `DecryptionService(authenticator: ...)`
    - `decryptionService.decryptAndZeroize(...)`
    - `authManager.checkAndRecoverFromInterruptedRewrap()` with no fingerprint input
  - The current surface uses `PgpEngine.generateKey(...)`, `encrypt(... recipients: signingKey: encryptToSelf:)`, `decrypt(... secretKeys: verificationKeys:)`, and `AuthenticationManager.checkAndRecoverFromInterruptedRewrap(fingerprints:)`.
- Evidence:
  - `docs/TESTING.md`
  - `Tests/FFIIntegrationTests/FFIIntegrationTests.swift`
  - `Sources/Services/DecryptionService.swift`
  - `Sources/Security/AuthenticationManager.swift`
- Severity:
  - High
- Recommended correction:
  - Update or remove the stale snippets.
  - If the goal is pseudocode rather than compilable examples, label them clearly as pseudocode. Otherwise, rewrite them to use the real `PgpEngine`, `DecryptionService`, and `AuthenticationManager` APIs.

### T-3. Mock interface examples no longer match the current protocols

- Source document and section:
  - `docs/TESTING.md`, Section 4, "Mock Patterns"
- Documented claim:
  - The sample protocols represent the current test seams.
- Actual repository state:
  - `KeychainManageable` now includes `exists(...)` and `listItems(...)`.
  - `SecureEnclaveManageable` includes `authenticationContext` parameters and a static `isAvailable`.
  - `AuthenticationEvaluable` is mode-based, not LAPolicy-based, and exposes `isBiometricsAvailable` and `lastEvaluatedContext`.
- Evidence:
  - `Sources/Security/KeychainManageable.swift`
  - `Sources/Security/SecureEnclaveManageable.swift`
  - `Sources/Security/AuthenticationEvaluable.swift`
- Severity:
  - Medium
- Recommended correction:
  - Refresh the protocol examples so they match the current interfaces.
  - This is especially important for AI-assisted contributors who may copy the sample seams directly.

### T-4. Explicit `PgpError -> CypherAirError` mapping coverage is narrower than the guide implies

- Source document and section:
  - `docs/TESTING.md`, Layer 3 description and Section 9, "Every PR Must Include"
- Documented claim:
  - The guide implies that `PgpError` variant mapping is covered comprehensively.
- Actual repository state:
  - `CypherAirError.init(pgpError:)` handles current variants including `OperationCancelled`, `FileIoError`, and `KeyTooLargeForQr`.
  - `ModelTests.swift` includes explicit mapping tests for the older set of variants but does not include dedicated `CypherAirError(pgpError:)` tests for all of those newer cases.
  - There are runtime-level tests for cancellation and streaming failures elsewhere, but the direct mapping coverage is not as explicit as the guide suggests.
- Evidence:
  - `Sources/Models/CypherAirError.swift`
  - `Tests/ServiceTests/ModelTests.swift`
  - Example command: `rg -n "OperationCancelled|FileIoError|KeyTooLargeForQr" Tests Sources/Models/CypherAirError.swift`
- Severity:
  - Medium
- Recommended correction:
  - Either add explicit mapping tests for the missing variants or narrow the wording so the guide does not overstate the current direct mapping coverage.

### T-5. The GitHub Actions runner note over-generalizes which jobs use `macos-26`

- Source document and section:
  - `docs/TESTING.md`, Section 2.1, "GitHub Actions Hosted macOS Limitation"
- Documented claim:
  - "The repository workflows target `macos-26`."
- Actual repository state:
  - The Swift validation jobs use `macos-26`.
  - The `rust-full-tests` job in `.github/workflows/pr-checks.yml` runs on `macos-latest`.
- Evidence:
  - `.github/workflows/pr-checks.yml`
  - `.github/workflows/nightly-full.yml`
- Severity:
  - Low
- Recommended correction:
  - Rephrase this section to say that the Swift/Xcode validation jobs target `macos-26`, while the Rust-only job in `pr-checks.yml` currently uses `macos-latest`.

### T-6. Section numbering is duplicated in the GnuPG section

- Source document and section:
  - `docs/TESTING.md`, headings around Sections 7 and 8
- Documented claim:
  - The numbering is sequential.
- Actual repository state:
  - The document uses `## 7. Recovery-Specific Tests` and later `## 7. GnuPG Interoperability Tests (Profile A Only)`.
- Evidence:
  - `docs/TESTING.md`
- Severity:
  - Low
- Recommended correction:
  - Renumber the later sections so the heading hierarchy is monotonic and easier to reference.

## Cross-Document Consistency Findings

### C-1. `docs/TESTING.md` and `CLAUDE.md` disagree on the complete test-plan picture

- Source document and section:
  - `docs/TESTING.md`, Section 2 and Section 9
  - `CLAUDE.md`, "Testing Requirements"
- Documented claim:
  - `docs/TESTING.md` treats the workspace as having three important test plans and explicitly calls out `CypherAir-MacUITests` for launch/routing/tutorial-host refactors.
  - `CLAUDE.md` lists only `CypherAir-UnitTests.xctestplan` and `CypherAir-DeviceTests.xctestplan`.
- Actual repository state:
  - The scheme includes all three plans, with `CypherAir-UnitTests` as default and `CypherAir-MacUITests` present as a first-class plan.
  - `UITests/MacUISmokeTests.swift` contains real launch, settings, and tutorial smoke coverage.
- Evidence:
  - `CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme`
  - `CypherAir-MacUITests.xctestplan`
  - `UITests/MacUISmokeTests.swift`
  - `CLAUDE.md`
- Severity:
  - Medium
- Recommended correction:
  - Update `CLAUDE.md` so its test-plan overview mentions `CypherAir-MacUITests` and the specific cases where it should be run.
  - Alternatively, soften the Testing Guide wording if the intention is to keep `MacUITests` as a context-specific plan rather than a generally listed one.

## Recommended Corrections

The cleanest update path is:

1. Fix the high-severity inaccuracies first.
   - Replace the old decrypt Phase-1 description with the current `matchRecipients` flow.
   - Correct the Testing Guide's Layer 2/3 platform language.
   - Rewrite stale API examples so they match the current `PgpEngine`, `DecryptionService`, and `AuthenticationManager` surfaces.
   - Narrow the `DiskSpaceChecker` scope to streaming encryption and keep the fixed 100 MB limit documented for in-memory file encryption.

2. Refresh structural inventories and storage details.
   - Update the Rust crate file tree.
   - Remove the missing `uniffi.toml` reference.
   - Add `contact-metadata.json`, `tmp/streaming/`, and `guidedTutorialCompletedVersion` to the storage section.
   - Correct the default color theme.

3. Align the testing guidance with the actual interfaces and coverage.
   - Refresh the mock-interface examples.
   - Either add explicit mapping tests for the newer `PgpError` variants or tone down the current claim.
   - Fix the duplicated section numbering and the over-generalized runner wording.

4. Reconcile duplicated guidance across docs.
   - Bring `CLAUDE.md` into line with the three-plan reality of the scheme, especially around `CypherAir-MacUITests`.

## Verification Appendix

### Static inspection commands used

Representative commands used during this audit:

```bash
rg --files docs Sources Tests UITests pgp-mobile
rg -n "CypherAir-UnitTests|CypherAir-MacUITests|FFIIntegrationTests|matchRecipients|parse_recipients" \
  docs Sources Tests UITests pgp-mobile .github CLAUDE.md
nl -ba docs/ARCHITECTURE.md
nl -ba docs/TESTING.md
nl -ba CypherAir-UnitTests.xctestplan
nl -ba CypherAir-DeviceTests.xctestplan
nl -ba CypherAir-MacUITests.xctestplan
nl -ba CypherAir.xcodeproj/xcshareddata/xcschemes/CypherAir.xcscheme
plutil -p CypherAir.entitlements
```

### Runtime validation status

- `cargo test --manifest-path pgp-mobile/Cargo.toml`: not run for this audit
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`: not run for this audit
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-MacUITests -destination 'platform=macOS'`: not run for this audit

Reason:

- The findings above are documentation-to-repository mismatches that were directly verifiable through static inspection.
- No runtime pass/fail claim is made in this report.

### Workspace mutation scope

- Added:
  - `docs/ARCHITECTURE_TESTING_DOC_REVIEW.md`
- Intentionally not modified:
  - `docs/ARCHITECTURE.md`
  - `docs/TESTING.md`
  - generated UniFFI files
  - Xcode project files
  - security and cryptography implementation files
