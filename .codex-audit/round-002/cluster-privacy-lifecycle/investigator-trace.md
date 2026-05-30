# Investigator Trace

Apple docs lookup: ran tool discovery for `Apple DocumentationSearch Xcode documentation search`; no Apple/Xcode documentation lookup tool was exposed in this session. Apple docs lookup not available.

## Finding Resolution

- `rg -n "CA-(14|15|16|31)" docs/CODEX_SECURITY_REVIEW_INDEX.md`
  - CA-14 -> `https://chatgpt.com/codex/cloud/security/findings/6d9bbb036edc8191bac8bd5eb13ff506`
  - CA-15 -> `https://chatgpt.com/codex/cloud/security/findings/daf3bd3399248191900565067b6785ae`
  - CA-16 -> `https://chatgpt.com/codex/cloud/security/findings/e2433b9357a48191b7ea3c939cad1a4d`
  - CA-31 -> `https://chatgpt.com/codex/cloud/security/findings/6e6da113cfc481919d83defdc698e785`
- `head -1 codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Confirmed CSV columns include `finding_url,title,description,severity,...,relevant_paths`.
- `rg -n "<four finding URL hashes>" codex-security-findings-2026-05-29T13-11-03.346Z.csv`
  - Matched CSV rows by `finding_url`, not by inferred line number.

## Commands And Files Inspected

- `rg --files | rg 'CODEX_SECURITY_REVIEW_INDEX|codex-security-findings|Authentication|Privacy|Lifecycle|Scene|background|blur'`
- `rg -n "AuthenticationShield|ultraThinMaterial|PrivacyScreen|scenePhase|handleResume|warmUpAfterAppUnlock|operationAuthentication|generation|didResign|didBecome|background|inactive" Sources/...`
- `rg -n "privacy screen|PrivacyScreen|authentication|background|scene|protected data|launch|resume" docs/SECURITY.md docs/ARCHITECTURE.md docs/TESTING.md docs/CONVENTIONS.md`
- `rg -n "AuthenticationShield|PrivacyScreen|PromptCoordinator|warmUpAfterAppUnlock|scenePhase|requireAuthOnLaunch|background" Tests`
- Targeted reads with `awk`:
  - `Sources/App/Common/AuthenticationShieldOverlayView.swift:1-170`
  - `Sources/App/Common/AuthenticationShieldHost.swift:17-95`
  - `Sources/App/Common/PrivacyScreenModifier.swift:1-155,269-345`
  - `Sources/App/Common/PrivacyScreenLifecycleGate.swift:1-190`
  - `Sources/Security/AuthenticationPromptCoordinator.swift:1-130,150-230`
  - `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:1-140,120-190,160-245,227-385,390-445,500-540`
  - `Sources/App/CypherAirApp.swift:300-430,445-510,600-628`
  - `Sources/App/AppContainer.swift:120-180,450-575,780-855,989-1003`
  - `Sources/App/Settings/MainWindowSettingsRootView.swift:1-40`
  - `Sources/App/Settings/ProtectedSettingsHost.swift:320-374`
  - `Sources/Security/AuthenticationManager.swift:210-455`
  - `Sources/Services/KeyManagement/PrivateKeyAccessService.swift:1-45`
  - `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift:220-245`
  - `Tests/ServiceTests/CommonHelpersTests.swift:389-505`
  - `Tests/ServiceTests/ProtectedDataFrameworkTests.swift:1800-1900,1901-2050,2206-2325,2479-2566`
  - `Tests/ServiceTests/AuthLifecycleTraceStoreTests.swift:735-780`

## Evidence Snippets

- CA-14:
  - `AuthenticationShieldOverlayView.swift:12-14`: full-screen `Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()`.
  - `AuthenticationShieldOverlayView.swift:142-145`: shield card background uses `.regularMaterial`.
  - `AppContainer.swift:145-150` and `989-1000`: prompt coordinator shield events call `AuthenticationShieldCoordinator.begin/end`.
  - `CypherAirApp.swift:488-492`: main content installs `authenticationShieldHost(..., handlesLifecycleEvents: true)`.

- CA-15:
  - `AuthenticationPromptCoordinator.swift:53-60`: operation prompt generation is monotonic.
  - `AuthenticationPromptCoordinator.swift:197-202`: generation increments on operation prompt begin.
  - `PrivacyScreenLifecycleGate.swift:54-66`: observing newer generation arms `.promptLifecycle` suppression.
  - `PrivacyScreenLifecycleGate.swift:83-99`: inactive/resign returns `.suppress` for prompt-lifecycle suppression.
  - `PrivacyScreenModifier.swift:71-78` and `98-112`: suppressed inactive/resign skips `handleSceneDidResignActive`.
  - `PrivacyScreenLifecycleGate.swift:101-114`: background clears suppression and handles.
  - `ProtectedDataFrameworkTests.swift:1980-2048`: late lifecycle after ended operation prompt asserts no auth, no relock, and `isPrivacyScreenBlurred == false`.

- CA-16:
  - `AppSessionOrchestrator.swift:285-329`: after successful auth, `handleResume` awaits `postAuthenticationHandler`, records completion, then sets `isPrivacyScreenBlurred = false`.
  - `AppSessionOrchestrator.swift:213-224`: background handler sets `isPrivacyScreenBlurred = true`.
  - `PrivacyScreenModifier.swift:318-345`: resume work runs in an untracked `Task`.
  - `AppContainer.swift:508-550`: production post-auth handler opens ProtectedData domains, contacts, protected ordinary settings availability, and private-key-control recovery.
  - `MainWindowSettingsRootView.swift:17-20`: Settings host refresh now observes `postAuthenticationGeneration`; no `warmUpAfterAppUnlock` symbol found in current HEAD.

- CA-31:
  - `AppSessionOrchestrator.swift:21`: `isPrivacyScreenBlurred` defaults to `false`.
  - `PrivacyScreenModifier.swift:20-31`: overlay is conditional on `isPrivacyScreenBlurred`.
  - `PrivacyScreenModifier.swift:131-140` and `282-309`: initial auth is scheduled from `.onAppear` using a `Task`.
  - `AppSessionOrchestrator.swift:181-189`: initial appearance sets blur only after the on-appear path runs.
  - `CypherAirApp.swift:396-417`: `mainWindowContent` is composed before `.privacyScreen()`.
  - `AppContainer.swift:493-508`: production bypass is `false` and app session auth evaluates configured policy.

No tests were run; this was a read-only investigation with no repository source edits.
