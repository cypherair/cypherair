# Investigator Trace: cluster-build-entitlements

## Resolution Inputs

- Read index entries with `rg -n "CA-07|CA-26|CA-40|CA-43|finding_url|Enhanced|entitlement|mock|CI|test" docs/CODEX_SECURITY_REVIEW_INDEX.md`.
- Matched by `finding_url` in CSV with `rg -n "e3704fde333081918a2fc4404432a502|5d51dc7622fc8191b9062c03230f5356|715f18cb62e48191abe332c39da5f2bd|3c77229cc04881919d0060e2d44f8c3d" codex-security-findings-2026-05-29T13-11-03.346Z.csv`.
- CSV rows matched:
  - CA-07 -> `https://chatgpt.com/codex/cloud/security/findings/e3704fde333081918a2fc4404432a502`
  - CA-26 -> `https://chatgpt.com/codex/cloud/security/findings/5d51dc7622fc8191b9062c03230f5356`
  - CA-40 -> `https://chatgpt.com/codex/cloud/security/findings/715f18cb62e48191abe332c39da5f2bd`
  - CA-43 -> `https://chatgpt.com/codex/cloud/security/findings/3c77229cc04881919d0060e2d44f8c3d`

## Apple Docs

- Apple docs lookup not available as a dedicated Apple/Xcode documentation tool. `tool_search` exposed XcodeBuildMCP build/project tools, but no Apple `DocumentationSearch`-style tool.
- Used official Apple Developer web search as secondary evidence for CA-26:
  - `site:developer.apple.com com.apple.security.hardened-process.enhanced-security-version-string`
  - `site:developer.apple.com com.apple.security.hardened-process.platform-restrictions-string`
  - Results stated that the `-string` entitlements are Xcode-added Enhanced Security entitlements, type `string`; unsuffixed `enhanced-security-version` and `platform-restrictions` are deprecated/replaced by the `-string` forms.

## CA-07 Evidence

- Files inspected:
  - `scripts/ci_xcode_platform_preflight.sh`
  - `.github/workflows/pr-checks.yml`
  - `.github/workflows/nightly-full.yml`
  - `docs/TESTING.md`
- Important lines:
  - `scripts/ci_xcode_platform_preflight.sh:339-344` reads `MACOSX_DEPLOYMENT_TARGET` from `xcodebuild -showBuildSettings` and records host-below-target as a skippable failure.
  - `scripts/ci_xcode_platform_preflight.sh:449-462` sets `ready=false` and warns unless `--strict` is provided.
  - `.github/workflows/pr-checks.yml:143-167` and `.github/workflows/nightly-full.yml:142-166` call `macos-unit-test-preflight` without `--strict`, only run artifact restore and `xcodebuild test` when `ready == 'true'`, and warn otherwise.
  - `docs/TESTING.md:193-231` documents hosted Swift unit tests as a preview skipped during hosted-image mismatches.

## CA-26 Evidence

- Files inspected:
  - `CypherAir.entitlements`
  - `CypherAirMacOS.entitlements`
  - `CypherAir.xcodeproj/project.pbxproj`
  - `docs/SECURITY.md`
  - `docs/ARCHITECTURE.md`
- Commands:
  - `rg -n "hardened-process|enhanced-security|platform-restrictions|ENABLE_ENHANCED_SECURITY|CODE_SIGN_ENTITLEMENTS|Enhanced Security|Hardware Memory Tagging" ...`
  - `plutil -lint CypherAir.entitlements CypherAirMacOS.entitlements`
  - `rg -n "enhanced-security-version$|platform-restrictions$|enhanced-security-version-string|platform-restrictions-string" ...`
- Important lines/snippets:
  - `CypherAir.entitlements:5-20` includes hardened-process keys plus `enhanced-security-version-string` and `platform-restrictions-string`.
  - `CypherAirMacOS.entitlements:5-27` includes the same Enhanced Security keys plus macOS sandbox/user-selected file entitlements.
  - `CypherAir.xcodeproj/project.pbxproj:870-878`, `1096-1104`, `1242-1250` include `CODE_SIGN_ENTITLEMENTS` and `ENABLE_ENHANCED_SECURITY = YES`.
  - `docs/SECURITY.md:404-417` lists the `-string` keys as Xcode-written required keys.
  - `plutil -lint` output: both entitlement files `OK`.
  - Search for unsuffixed current keys found no current entitlement/doc entries beyond Apple-doc search references to deprecated forms.

## CA-40 Evidence

- Files inspected:
  - `CypherAir.xcodeproj/project.pbxproj`
  - `Sources/Security/Mocks/MockAuthenticator.swift`
  - `Sources/Security/Mocks/MockKeychain.swift`
  - `Sources/Security/Mocks/MockSecureEnclave.swift`
  - `Sources/App/AppContainer.swift`
  - `Sources/App/AppLaunchConfiguration.swift`
  - `Sources/App/CypherAirApp.swift`
  - `Sources/App/Onboarding/TutorialSandboxContainer.swift`
  - `Sources/App/Onboarding/TutorialSessionStore.swift`
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift`
  - production references to `MockKeychainError` in security/settings sources.
- Commands:
  - `rg --files | rg '^project\\.yml$'` returned no file.
  - `rg -n "PBXFileSystemSynchronizedRootGroup|fileSystemSynchronizedGroups|Security/Mocks/Mock..." CypherAir.xcodeproj/project.pbxproj`
  - `rg -n "makeDefault|makeUITest|MockSecureEnclave|MockKeychain|MockAuthenticator|TutorialSandboxContainer" Sources Tests`
- Important lines/snippets:
  - `CypherAir.xcodeproj/project.pbxproj:404-409` defines the synchronized `Sources` root.
  - `CypherAir.xcodeproj/project.pbxproj:481-489` puts `Sources` in the `CypherAir` application target.
  - `CypherAir.xcodeproj/project.pbxproj:56-57`, `301-304` are exceptions for the `CypherAirTests` target, not app target exclusions.
  - `Sources/App/AppContainer.swift:307-316` default app uses `HardwareSecureEnclave` and `SystemKeychain`.
  - `Sources/App/AppContainer.swift:626-642` UI-test app container uses `MockSecureEnclave` and `MockKeychain`.
  - `Sources/App/CypherAirApp.swift:38-45` selects UI-test container only for UI-test/XCTest modes; otherwise default container.
  - `Sources/App/Onboarding/TutorialSandboxContainer.swift:23-152` production guided tutorial sandbox constructs mocks and wires them into tutorial-only services.
  - `Sources/Security/Mocks/MockAuthenticator.swift:10` defaults `shouldSucceed = true`.
  - `Sources/Security/Mocks/MockKeychain.swift:18` stores data in an in-memory dictionary.
  - `Sources/Security/Mocks/MockSecureEnclave.swift:8-25`, `47`, `171` identify software Secure Enclave simulation and ignored authentication context.
  - `Tests/ServiceTests/TutorialSessionStoreTests.swift:39-57` asserts sandbox storage/mocks and not `/Documents/contacts`.
  - `Sources/Security/KeyBundleStore.swift:268-283`, `Sources/Security/KeyMetadataStore.swift:358-367`, and `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift:567-578` reference `MockKeychainError` from production code.

## CA-43 Evidence

- Files inspected:
  - `Sources/Security/AuthenticationManager.swift`
  - `CypherAir.xcodeproj/project.pbxproj`
  - `docs/CONVENTIONS.md`
- Commands:
  - `rg -n "import Observation|@Observable" Sources/Security/AuthenticationManager.swift Sources/Security Sources/App Sources/Services Sources/Models`
  - `rg -n "Observation|Observable|SWIFT|OTHER_SWIFT_FLAGS|compiler" CypherAir.xcodeproj/project.pbxproj docs/CONVENTIONS.md docs/TESTING.md`
  - Direct toolchain probe: `/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc -version`
  - Direct typecheck probe with Foundation import and `@Observable`.
  - Direct typecheck probe with no imports and `@Observable`.
- Important lines/snippets:
  - `Sources/Security/AuthenticationManager.swift:1-3` imports Foundation, LocalAuthentication, Security.
  - `Sources/Security/AuthenticationManager.swift:83` uses `@Observable`.
  - `CypherAir.xcodeproj/project.pbxproj:404-409`, `481-489` include `Sources` in the app target.
  - `docs/CONVENTIONS.md:106-108` records Apple Swift 6.3.2 / Swift 6 language mode and `@Observable` conventions.
  - `swiftc -version` output: Apple Swift 6.3.2.
  - `printf 'import Foundation\n@Observable final class Probe { var value = 0 }\n' | .../swiftc -sdk ... -typecheck -` succeeded.
  - `printf '@Observable final class Probe { var value = 0 }\n' | .../swiftc -sdk ... -typecheck -` failed with `unknown attribute 'Observable'`.
  - Interpretation: the specific "no Observation import causes unknown attribute" mechanism does not apply to `AuthenticationManager.swift` because it imports Foundation on this toolchain.

## Tool/Command Notes

- `xcodebuild -list -project CypherAir.xcodeproj` hung in SDK/platform lookup and was killed; no useful build evidence came from it.
- `/usr/bin` Swift wrapper probes (`swift -e`, `swiftc -version`, `xcrun --find swiftc`) also hung and were killed. Direct toolchain `swiftc` was used instead.
- A first direct `swiftc -typecheck` attempt failed in the sandbox because Swift wanted to write its module cache under `~/.cache/clang/ModuleCache`; reran with escalation for compiler-cache access.
- Output directory was initially empty. Repository files were not edited and the git index was not updated.
