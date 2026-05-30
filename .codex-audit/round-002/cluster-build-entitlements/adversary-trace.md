# Adversary Trace: cluster-build-entitlements

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

I did not read `investigator-trace.md`. I only read `investigator.md`.

## Required Inputs

- `docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - `rg -n "CA-(07|26|40|43)" docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - Relevant lines:
    - CA-07: line 45
    - CA-26: line 64
    - CA-40: line 78
    - CA-43: line 81
  - Also inspected `nl`/`awk` range `35-90`.

- `codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - `rg -n "e3704fde333081918a2fc4404432a502|5d51dc7622fc8191b9062c03230f5356|715f18cb62e48191abe332c39da5f2bd|3c77229cc04881919d0060e2d44f8c3d" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Relevant CSV rows:
    - CA-07 URL row: line 8
    - CA-26 URL row: line 27
    - CA-40 URL row: line 41
    - CA-43 URL row: line 44
  - Also inspected `head -n 5` to confirm CSV columns.

- `.codex-audit/round-002/cluster-build-entitlements/investigator.md`
  - `nl -ba .codex-audit/round-002/cluster-build-entitlements/investigator.md`
  - Relevant lines:
    - CA-07: lines 7-18
    - CA-26: lines 20-31
    - CA-40: lines 33-44
    - CA-43: lines 46-57

## CA-07 Evidence Inspected

- `.github/workflows/pr-checks.yml`
  - Lines 1-10: workflow triggers on `pull_request` and `push` with read contents permission.
  - Lines 138-167: `swift-unit-tests-hosted-preview`, non-strict preflight, conditional artifact restore/test, warning-only skip.

- `.github/workflows/nightly-full.yml`
  - Lines 1-16: scheduled/manual workflow and environment.
  - Lines 137-166: same hosted Swift unit-test preview and warning-only skip pattern.

- `scripts/ci_xcode_platform_preflight.sh`
  - Lines 4-16: usage includes `macos-unit-test-preflight [--strict]`.
  - Lines 19-39: mode and strict parsing; strict defaults false.
  - Lines 320-345: hosted Swift readiness checks Xcode/SDK and project `MACOSX_DEPLOYMENT_TARGET`; host below deployment target is recorded as skippable.
  - Lines 347-360: destination check; missing macOS arm64e destination is blocking.
  - Lines 416-423: `macos-unit-test-preflight` dispatch.
  - Lines 439-447: blocking failures emit `::error::` and exit 1.
  - Lines 449-463: non-strict skippable failures set `ready=false`, emit `::warning::`, and exit 0.

- `scripts/tests/test_ci_xcode_platform_preflight.py`
  - Lines 183-197: host below deployment target is expected to exit 0 with `ready=false`.
  - Lines 236-246: strict mode turns the same mismatch into a failure.

- `docs/TESTING.md`
  - Lines 186-198: current GitHub Actions lanes; hosted Swift unit-test preview is documented as warning-skippable on hosted environment mismatch.
  - Lines 218-234: hosted macOS limitation; local macOS validation remains source of truth while hosted image catches up.

## CA-26 Evidence Inspected

- `CypherAir.entitlements`
  - Lines 5-20: hardened process keys include `enhanced-security-version-string` value `1` and `platform-restrictions-string` value `2`.

- `CypherAirMacOS.entitlements`
  - Lines 5-20: macOS entitlement file includes the same hardened-process Enhanced Security keys.
  - Lines 21-28: macOS sandbox and file user-selected read-write keys.

- `CypherAir.xcodeproj/project.pbxproj`
  - Lines 870-878: app Release config points to entitlement files and sets `ENABLE_ENHANCED_SECURITY = YES`.
  - Lines 1096-1104: another app config points to entitlement files and sets `ENABLE_ENHANCED_SECURITY = YES`.
  - Lines 1242-1250: another app config points to entitlement files and sets `ENABLE_ENHANCED_SECURITY = YES`.

- `docs/SECURITY.md`
  - Lines 404-417: project documentation lists the `-string` keys as Xcode-written required keys and tells maintainers to verify `ENABLE_ENHANCED_SECURITY = YES`.

- `docs/ARCHITECTURE.md`
  - Line 605 from `rg`: Enhanced Security capability configured through `ENABLE_ENHANCED_SECURITY = YES` and committed entitlements.

- Command:
  - `plutil -lint CypherAir.entitlements CypherAirMacOS.entitlements`
  - Result: both files reported `OK`.

- Apple Developer official documentation/release-note checks:
  - Web search: `site:developer.apple.com com.apple.security.hardened-process.enhanced-security-version-string entitlement`
  - Web search: `site:developer.apple.com com.apple.security.hardened-process.platform-restrictions-string entitlement`
  - Web search: `site:developer.apple.com/documentation/xcode-release-notes/xcode-26_4-release-notes enhanced-security-version-string platform-restrictions-string`
  - Relevant official Apple URLs:
    - `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process.enhanced-security-version-string`
    - `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process.platform-restrictions-string`
    - `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.hardened-process.enhanced-security-version`
    - `https://developer.apple.com/documentation/xcode-release-notes/xcode-26_4-release-notes`
  - Search-result excerpts indicated:
    - The `-string` entitlement pages are current property-list keys.
    - Xcode adds the `-string` keys when Enhanced Security is added.
    - The unsuffixed `enhanced-security-version` page is deprecated/replaced by the `-string` key.
    - Xcode 26.4 release notes instruct adopters to remove unsuffixed keys and add `enhanced-security-version-string` value `1` plus `platform-restrictions-string` value `2`.

## CA-40 Evidence Inspected

- `project.yml`
  - Command: `ls project.yml`
  - Result: `No such file or directory`; original XcodeGen evidence is stale for current HEAD.

- `CypherAir.xcodeproj/project.pbxproj`
  - Lines 55-59 and 287-305: only `CypherAirTests` has a `Sources` exception set; mocks appear in the synchronized source listing.
  - Lines 398-410: `Sources` is a `PBXFileSystemSynchronizedRootGroup`.
  - Lines 466-483: app target includes the synchronized `Sources` group.
  - Lines 737-750: explicit `PBXSourcesBuildPhase.files` is empty under the filesystem-synchronized layout.
  - `rg -n "Exceptions for \"Sources\" folder|fileSystemSynchronizedGroups|Sources \\*/" CypherAir.xcodeproj/project.pbxproj` confirmed there is no app-target-specific `Sources` exception set.

- `Sources/Security/Mocks/MockAuthenticator.swift`
  - Lines 8-13: mock authenticator class; `shouldSucceed` and biometrics availability default true.
  - Lines 25-33: availability simulation.
  - Lines 36-50: evaluation returns true when `shouldSucceed` is true.

- `Sources/Security/Mocks/MockKeychain.swift`
  - Lines 5-16: in-memory test mock, warning comment.
  - Lines 17-18: storage is a plain dictionary.
  - Lines 56-75: save ignores access-control enforcement and writes to memory.
  - Lines 77-95: load returns in-memory data.
  - Lines 167-172: `MockKeychainError`.
  - Lines 174-234: `MockProtectedDataRootSecretStore` is also in this file.

- `Sources/Security/Mocks/MockSecureEnclave.swift`
  - Lines 8-25: software Secure Enclave mock description and warnings.
  - Lines 47-64: availability true and software P-256 generation.
  - Lines 67-116: software wrap path.
  - Lines 118-178: software unwrap/reconstruct path; line 171 notes authentication context is ignored.

- `Sources/App/AppContainer.swift`
  - Lines 307-316: normal `makeDefault` uses `HardwareSecureEnclave` and `SystemKeychain`.
  - Lines 626-640: `makeUITest` constructs `MockSecureEnclave` and `MockKeychain`, random test suite, bypass preference.
  - Lines 655-687: UI-test container uses temporary document/protected-data directories and mock root-secret store.
  - Lines 777-787: UI-test key management is wired to mocks.
  - Lines 892-925: UI-test container returned with isolated suite name.

- `Sources/App/CypherAirApp.swift`
  - Lines 35-48: app selects `makeUITest` only for UI-test/XCTest launch configuration, otherwise `makeDefault`.
  - Lines 49-52: test bypass records authentication only in UI-test/XCTest mode without manual authentication.

- `Sources/App/AppLaunchConfiguration.swift`
  - Lines 20-29: UI-test mode is driven by `UITEST_ROOT`/`UITEST_SKIP_ONBOARDING`; XCTest host detected separately.
  - Lines 44-50: XCTest host detection.

- `Sources/Security/AuthenticationManager.swift`
  - Lines 208-219: UI-test bypass returns true for private-key auth if the bypass default is set.
  - Lines 361-379: UI-test bypass returns authenticated app-session result if the bypass default is set.

- `Sources/App/Onboarding/TutorialSandboxContainer.swift`
  - Lines 20-23: tutorial sandbox uses real services backed by sandbox storage and mock security primitives.
  - Lines 50-87: creates mock Secure Enclave, Keychain, Authenticator, and AuthManager.
  - Lines 88-153: wires tutorial AppConfiguration, KeyManagementService, contacts sandbox, and services.
  - Lines 178-184: cleanup removes tutorial directory and defaults suite.

- `Sources/App/Onboarding/TutorialSessionStore.swift`
  - Lines 493-506: tutorial container is created when a tutorial session starts.

- `Sources/App/Onboarding/Tutorial/TutorialModels.swift`
  - Lines 198-203: tutorial security simulation stack exposes mock-backed components.

- `docs/ARCHITECTURE.md`
  - Lines 101-109: tutorial is documented as sandboxed, using mock Secure Enclave/Keychain behind real services, with output/file-operation restrictions.

- `Tests/ServiceTests/TutorialSessionStoreTests.swift`
  - Lines 39-57: test asserts tutorial sandbox storage and mocks, empty key/contact state, and not `/Documents/contacts`.

- Production coupling to mock error type:
  - `Sources/Security/KeyMetadataStore.swift` lines 358-370.
  - `Sources/Security/KeyBundleStore.swift` lines 270-280.
  - `Sources/Services/KeyManagement/KeyMutationService.swift` lines 225-235.
  - Additional `rg` hits in `ProtectedDataRightStoreClient.swift`, `ProtectedDataDeviceBinding.swift`, and `LocalDataResetService.swift`.

## CA-43 Evidence Inspected

- `Sources/Security/AuthenticationManager.swift`
  - Lines 1-4: imports `Foundation`, `LocalAuthentication`, and `Security`.
  - Lines 74-84: `@Observable final class AuthenticationManager`.

- Other current `@Observable` examples without explicit `import Observation`:
  - `Sources/Services/EncryptionService.swift` lines 1-11.
  - `Sources/Models/AppConfiguration.swift` lines 1-15.
  - `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift` lines 1-10.
  - `Sources/App/Onboarding/TutorialSessionStore.swift` lines 1-7.
  - `rg -n "@Observable" Sources | head -n 80` showed broad current usage across app, services, models, and security files.

- `CypherAir.xcodeproj/project.pbxproj`
  - Lines 398-410: `Sources` synchronized root group.
  - Lines 466-483: app target includes synchronized `Sources`.

- Swift compiler probes:
  - `swiftc -version`
  - Result: `Apple Swift version 6.3.2`.
  - `printf 'import Foundation\n@Observable final class T {}\n' | swiftc -typecheck -`
  - Result: blocked by sandboxed module-cache write to `/Users/tianren/.cache/clang/ModuleCache`, so not used as proof.
  - `printf '@Observable final class T {}\n' | swiftc -typecheck -`
  - Result: also blocked by the same module-cache permission before a useful macro diagnostic, so not used as proof.

## Other Commands/Notes

- `rg --files` and `find .github -type f -maxdepth 3` were used to orient current repository layout.
- `ls -la .codex-audit/round-002/cluster-build-entitlements` confirmed existing `investigator.md` and `investigator-trace.md`; only `investigator.md` was read.
- `test -e` checks confirmed `adversary.md` and `adversary-trace.md` did not already exist before writing.
- A scoped `git status --short -- ...` command hung without output. I terminated the stuck `git status` process with an escalated `kill 47348`. No evidence from that command was used.
