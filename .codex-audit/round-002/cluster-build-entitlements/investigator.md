# Round 2 Investigation: cluster-build-entitlements

Worktree: `/Users/tianren/.codex/worktrees/5de8/cypherair-main`

Resolved CA IDs by matching `docs/CODEX_SECURITY_REVIEW_INDEX.md` `finding_url` values to `codex-security-findings-2026-05-29T13-11-03.346Z.csv`.

## CA-07: PRs can warning-skip hosted Swift unit tests

- Title: PRs can warning-skip hosted Swift unit tests.
- Relevant code locations: `.github/workflows/pr-checks.yml:143-167`; `.github/workflows/nightly-full.yml:142-166`; `scripts/ci_xcode_platform_preflight.sh:339-344`, `scripts/ci_xcode_platform_preflight.sh:449-462`; `docs/TESTING.md:193-231`.
- Mechanism-present status: Present. The PR and nightly hosted Swift unit-test preview call `macos-unit-test-preflight` without `--strict`; when the checked-out project reports a `MACOSX_DEPLOYMENT_TARGET` above the host OS, the script classifies it as skippable, sets `ready=false`, emits a warning, and the workflow skips `xcodebuild test`.
- Shipped reachability: CI-only. This does not alter shipped app runtime behavior, but it can weaken a pull-request validation lane for Swift auth/storage/key-management changes.
- Mitigations: Rust audit/tests and XCFramework packaging remain required. The preflight treats `xcodebuild -showBuildSettings` and `xcodebuild -showdestinations` failures as blocking failures, not skippable hosted-image mismatches. Project docs explicitly frame hosted Swift unit tests as a preview while local macOS validation remains the source of truth during GitHub runner lag.
- Evidence-real: The workflow checks `steps.swift_unit_preflight.outputs.ready == 'true'` before artifact restore and `xcodebuild test`, then warns on `ready != 'true'`. The script reads `MACOSX_DEPLOYMENT_TARGET` from the checked-out project and records `host macOS ... below MACOSX_DEPLOYMENT_TARGET` as a skippable failure.
- Evidence-false-positive: The skip behavior is intentional for hosted-image lag and is not a release/runtime vulnerability. It does not skip all CI, only this hosted Swift test preview.
- Preliminary disposition: Real CI integrity risk, scoped to PR/nightly hosted Swift unit-test gating.
- Confidence: High.
- Open questions: Should PR validation run this preflight in `--strict` mode, use a trusted-base deployment target for readiness, or move required Swift tests to a self-hosted/current macOS runner?

## CA-26: Enhanced Security entitlements renamed to ignored keys

- Title: Enhanced Security entitlements renamed to ignored keys.
- Relevant code locations: `CypherAir.entitlements:5-20`; `CypherAirMacOS.entitlements:5-27`; `CypherAir.xcodeproj/project.pbxproj:870-878`, `CypherAir.xcodeproj/project.pbxproj:1096-1104`, `CypherAir.xcodeproj/project.pbxproj:1242-1250`; `docs/SECURITY.md:404-417`; `docs/ARCHITECTURE.md:603-605`.
- Mechanism-present status: Not present as stated. Current HEAD uses `com.apple.security.hardened-process.enhanced-security-version-string` and `com.apple.security.hardened-process.platform-restrictions-string` with string values, and official Apple Developer search results identify those `-string` entitlements as current Xcode-added Enhanced Security entitlements while the unsuffixed forms are deprecated/replaced.
- Shipped reachability: Build/signing/runtime-hardening surface. If these keys were wrong, signed app binaries could lose Enhanced Security/MIE defense-in-depth, but the current evidence supports the checked-in key names.
- Mitigations: Both iOS/visionOS and macOS entitlement files contain the hardened-process, hardened-heap, dyld-ro, checked-allocations, pure-data, no-tagged-receive, enhanced-security-version-string, and platform-restrictions-string keys. Project build settings keep `ENABLE_ENHANCED_SECURITY = YES` and point app builds at the entitlement files. `plutil -lint` passes for both entitlement files.
- Evidence-real: No current evidence that the `-string` keys are ignored. No built/codesigned app entitlement dump was produced in this investigation.
- Evidence-false-positive: Current repo docs list the same `-string` keys as required. Apple Developer search snippets for `enhanced-security-version-string` and `platform-restrictions-string` say Xcode adds those entitlements for Enhanced Security; snippets for the unsuffixed forms say they are deprecated/replaced by the `-string` forms.
- Preliminary disposition: False positive / stale semantics for current HEAD.
- Confidence: High for key naming; medium-high for final distribution because no archive/code-sign entitlement inspection was run.
- Open questions: For formal release validation, should the release checklist include `codesign -d --entitlements :-` on the archived app to prove the signed product carries these keys?

## CA-40: Production Xcode target compiles security test mocks

- Title: Production Xcode target compiles security test mocks.
- Relevant code locations: `CypherAir.xcodeproj/project.pbxproj:398-409`, `CypherAir.xcodeproj/project.pbxproj:481-489`; `Sources/Security/Mocks/MockAuthenticator.swift:8-46`; `Sources/Security/Mocks/MockKeychain.swift:16-119`; `Sources/Security/Mocks/MockSecureEnclave.swift:8-176`; `Sources/App/AppContainer.swift:307-316`, `Sources/App/AppContainer.swift:626-642`; `Sources/App/Onboarding/TutorialSandboxContainer.swift:23-152`; `Sources/App/CypherAirApp.swift:38-45`; `Sources/Security/KeyBundleStore.swift:268-283`.
- Mechanism-present status: Present, with updated project-layout context. `project.yml` is absent in current HEAD, so the XcodeGen part of the original evidence is stale. However, the app target now uses a filesystem-synchronized `Sources` root with no app-target exclusion for `Sources/Security/Mocks`, so the mocks are compiled into the application target. The empty `PBXSourcesBuildPhase.files` list is not evidence of exclusion under this layout.
- Shipped reachability: Shipped and reachable in bounded flows. The default app container uses `HardwareSecureEnclave` and `SystemKeychain`, but UI/XCTest launch mode uses mocks, and the guided tutorial intentionally creates a `TutorialSandboxContainer` using `MockSecureEnclave`, `MockKeychain`, and `MockAuthenticator` for isolated tutorial storage and simulated security flows.
- Mitigations: The normal app dependency graph wires hardware-backed Secure Enclave and system Keychain. Tutorial state uses a fixed tutorial defaults suite, temporary sandbox directories, in-memory/private tutorial storage, and output interception. Tests assert the tutorial sandbox uses sandbox storage and mocks and does not use `/Documents/contacts`.
- Evidence-real: The app target includes the synchronized `Sources` group. The mock classes default to authentication success, in-memory keychain storage, and software P-256 Secure Enclave simulation. Production code also references `MockKeychainError`, demonstrating production-module coupling to mock types.
- Evidence-false-positive: No current evidence that real user private-key custody or app-access authentication selects these mocks in `AppContainer.makeDefault`. The original claim that a generated `project.yml` placed mocks in the app target is stale because `project.yml` is not present.
- Preliminary disposition: Real build-integration/design risk, but narrower than a direct runtime auth bypass. The mocks are intentionally used for tutorial/UI-test paths; the remaining concern is that unsafe test-named primitives and mock error types are part of the production app module.
- Confidence: High.
- Open questions: Should tutorial simulation primitives be renamed/moved into a production-owned sandbox simulation layer, and should test-only mocks/error types be excluded from the app target after production code stops depending on `MockKeychainError`?

## CA-43: AuthenticationManager target addition breaks builds

- Title: AuthenticationManager target addition breaks builds.
- Relevant code locations: `Sources/Security/AuthenticationManager.swift:1-3`, `Sources/Security/AuthenticationManager.swift:83`; `CypherAir.xcodeproj/project.pbxproj:404-409`, `CypherAir.xcodeproj/project.pbxproj:481-489`; `docs/CONVENTIONS.md:106-108`.
- Mechanism-present status: Not present as a build break in current toolchain evidence. `AuthenticationManager.swift` is in the app target via the synchronized `Sources` root and imports Foundation, LocalAuthentication, and Security before `@Observable`. A direct Apple Swift 6.3.2 typecheck confirmed `import Foundation` makes `@Observable` available; a no-import probe failed, confirming the check was meaningful.
- Shipped reachability: Build integration only. If true, this would prevent app builds rather than ship a vulnerable runtime.
- Mitigations: Current Swift conventions use `@Observable class` broadly across app, service, model, and security files, many of which import Foundation without explicitly importing Observation. This makes CA-43 unlikely to be specific to `AuthenticationManager`.
- Evidence-real: `AuthenticationManager.swift` lacks an explicit `import Observation` and is included in the app target. No full `xcodebuild build/test` was completed during this investigation.
- Evidence-false-positive: Direct `swiftc -typecheck` with `import Foundation` and `@Observable` succeeded on Apple Swift 6.3.2. The same probe with no imports failed with `unknown attribute 'Observable'`, so Foundation visibility is the differentiator. The original "unknown attribute" mechanism is not reproduced for a file that imports Foundation.
- Preliminary disposition: False positive / already non-issue for current HEAD and toolchain.
- Confidence: Medium-high. The specific macro-import mechanism is falsified, but full project build validation was not run because local Xcode metadata/toolchain wrapper probes hung.
- Open questions: None for this finding's stated mechanism; a normal CI/local build remains the broader validation signal.
