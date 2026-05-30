# Round 2 Adversary Trace: cluster-privacy-lifecycle

## Boundary Notes

- Did not edit repository source files.
- Did not update the git index.
- Did not close Codex findings.
- Did not read `.codex-audit/round-002/cluster-privacy-lifecycle/investigator-trace.md`.
- Wrote only:
  - `.codex-audit/round-002/cluster-privacy-lifecycle/adversary.md`
  - `.codex-audit/round-002/cluster-privacy-lifecycle/adversary-trace.md`

## Commands Inspected

Read-only orientation and source lookup:

- `pwd && ls -la .codex-audit/round-002/cluster-privacy-lifecycle`
- `find .codex-audit/round-002/cluster-privacy-lifecycle -maxdepth 1 -type f -print`
- `git status --short`
- `rg -n "CA-14|CA-15|CA-16|CA-31|privacy|lifecycle|snapshot|background|transluc|glass|blur|redact|screen" docs/CODEX_SECURITY_REVIEW_INDEX.md codex-security-findings-2026-05-29T13-11-03.346Z.csv .codex-audit/round-002/cluster-privacy-lifecycle/investigator.md`
- `sed -n '1,260p' .codex-audit/round-002/cluster-privacy-lifecycle/investigator.md`
- `nl -ba .codex-audit/round-002/cluster-privacy-lifecycle/investigator.md | sed -n '1,170p'`
- `sed -n '1,220p' docs/CODEX_SECURITY_REVIEW_INDEX.md`
- `nl -ba docs/CODEX_SECURITY_REVIEW_INDEX.md | sed -n '48,56p'`
- `nl -ba docs/CODEX_SECURITY_REVIEW_INDEX.md | sed -n '66,71p'`
- `nl -ba codex-security-findings-2026-05-29T13-11-03.346Z.csv | sed -n '14,18p'`
- `nl -ba codex-security-findings-2026-05-29T13-11-03.346Z.csv | sed -n '31,33p'`

Read-only implementation and test inspection:

- `nl -ba Sources/App/Common/AuthenticationShieldOverlayView.swift | sed -n '1,220p'`
- `nl -ba Sources/App/Common/AuthenticationShieldHost.swift | sed -n '1,140p'`
- `nl -ba Sources/App/Common/AuthenticationShieldCoordinator.swift | sed -n '1,260p'`
- `nl -ba Sources/App/Common/AuthenticationShieldCoordinator.swift | sed -n '257,345p'`
- `nl -ba Sources/App/Common/PrivacyScreenModifier.swift | sed -n '1,380p'`
- `nl -ba Sources/App/Common/PrivacyScreenLifecycleGate.swift | sed -n '1,240p'`
- `nl -ba Sources/Security/AuthenticationPromptCoordinator.swift | sed -n '1,260p'`
- `nl -ba Sources/Security/ProtectedData/AppSessionOrchestrator.swift | sed -n '1,380p'`
- `nl -ba Sources/Security/ProtectedData/AppSessionOrchestrator.swift | sed -n '380,620p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '120,170p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '158,260p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '300,435p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '430,490p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '470,570p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '740,850p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '980,1015p'`
- `nl -ba Sources/App/AppContainer.swift | sed -n '1060,1105p'`
- `nl -ba Sources/App/CypherAirApp.swift | sed -n '1,120p'`
- `nl -ba Sources/App/CypherAirApp.swift | sed -n '300,365p'`
- `nl -ba Sources/App/CypherAirApp.swift | sed -n '360,520p'`
- `nl -ba Sources/App/CypherAirApp.swift | sed -n '600,640p'`
- `nl -ba Sources/App/AppStartupCoordinator.swift | sed -n '1,130p'`
- `nl -ba Sources/Models/AppConfiguration.swift | sed -n '1,220p'`
- `nl -ba Sources/Models/ProtectedOrdinarySettingsCoordinator.swift | sed -n '1,110p'`
- `nl -ba Sources/App/ContentView.swift | sed -n '1,260p'`
- `nl -ba Sources/App/Shell/SharedIOSTabShellView.swift | sed -n '1,180p'`
- `nl -ba Sources/App/AppShellComposition.swift | sed -n '1,240p'`
- `nl -ba Sources/App/HomeView.swift | sed -n '1,260p'`
- `nl -ba Sources/App/Shell/AppShellTabs.swift | sed -n '1,100p'`
- `nl -ba Sources/App/Keys/MyKeysView.swift | sed -n '1,160p'`
- `nl -ba Sources/Services/KeyManagementService.swift | sed -n '1,190p'`
- `nl -ba Sources/Services/KeyManagementService.swift | sed -n '184,250p'`
- `nl -ba Sources/Services/KeyManagementService.swift | sed -n '600,660p'`
- `nl -ba Sources/Services/ContactService.swift | sed -n '1,120p'`
- `nl -ba Sources/Services/ContactService.swift | sed -n '800,850p'`
- `nl -ba Sources/App/Settings/MainWindowSettingsRootView.swift | sed -n '1,60p'`
- `nl -ba Sources/App/Settings/ProtectedSettingsHost.swift | sed -n '320,390p'`
- `nl -ba Sources/App/Settings/SettingsView.swift | sed -n '1,120p'`
- `nl -ba Sources/App/Settings/SettingsScreenHostView.swift | sed -n '1,120p'`
- `nl -ba Sources/App/Settings/SettingsScreenModel.swift | sed -n '1,130p'`
- `nl -ba Sources/App/Settings/SettingsSecuritySection.swift | sed -n '1,100p'`
- `nl -ba Sources/Security/ProtectedData/ProtectedDataPostUnlockCoordinator.swift | sed -n '1,280p'`
- `nl -ba Sources/Security/AuthenticationEvaluable.swift | sed -n '360,430p'`
- `nl -ba Tests/ServiceTests/CommonHelpersTests.swift | sed -n '360,520p'`
- `nl -ba Tests/ServiceTests/ProtectedDataFrameworkTests.swift | sed -n '1800,2490p'`
- `nl -ba Tests/ServiceTests/AuthenticationShieldCoordinatorTests.swift | sed -n '1,130p'`
- `nl -ba Tests/ServiceTests/AuthenticationShieldCoordinatorTests.swift | sed -n '220,270p'`

Read-only searches:

- `rg -n "postAuthenticationHandler|postAuthenticationGeneration|warmUpAfterAppUnlock|openRegisteredDomains|relockCurrentSession|privacyScreen|isPrivacyScreenBlurred" Sources Tests docs`
- `rg -n "makeProtectedSettingsPostUnlockOpener|makeProtectedDataFrameworkSentinelPostUnlockOpener|make.*PostUnlockOpener|ProtectedDataPostUnlockDomainOpener" Sources/App/AppContainer.swift Sources -g'*.swift'`
- `rg -n "appSessionAuthenticationPolicy|gracePeriod|AppConfiguration" Sources/Models Sources/App Sources/Security docs/PRD.md docs/SECURITY.md docs/ARCHITECTURE.md`
- `rg -n "background|privacy screen|privacy|snapshot|blur|App Access|ProtectedData|Protected Data|session" docs/PRD.md docs/SECURITY.md docs/ARCHITECTURE.md docs/CONVENTIONS.md`
- `rg -n "struct ContentView|struct MacAppShellView|NavigationStack|selected|KeyList|Contacts|Encrypt|Decrypt|Sign" Sources/App -g'*.swift'`
- `rg -n "@Published|@Observable|keys|contacts|loadKeys|openContactsAfterPostUnlock|relock\\(|contentClearGeneration" Sources/Services Sources/App/Keys Sources/App/Contacts Sources/Models -g'*.swift'`
- `rg -n "relockProtectedData|markKeyMetadataLocked|completeKeyMetadataLoad|openDomainIfNeeded" Sources/Services/KeyManagementService.swift Sources/App/AppContainer.swift Sources/Security/ProtectedData/KeyMetadataDomainStore.swift`
- `rg --files Sources/App | rg "SharedIOSTabShellView|AppShellComposition|AppShellTab|HomeView"`
- `rg -n "makeShieldEventHandler|AuthenticationShieldKind|isVisible|noteRenderVisible|sceneDidResignActive|sceneDidEnterBackground" Sources/App Sources/Security Tests -g'*.swift'`
- `rg -n "@SceneStorage|sceneStorage|NSUserActivity|restoration|NavigationPath|navigationState|selectedTab" Sources/App Sources/Models Sources/Services -g'*.swift'`
- `rg -n "@State private var .*input|ciphertext|plaintext|message|selectedFileName|decrypted" Sources/App/Encrypt Sources/App/Decrypt Sources/App/Sign -g'*.swift'`
- `rg -n "privacySensitive|isPrivacyScreenBlurred|ultraThinMaterial|regularMaterial|thinMaterial" Sources/App Sources/Services Sources/Security Tests -g'*.swift'`

## Source References Used

### Original Finding and Investigator Sources

- `docs/CODEX_SECURITY_REVIEW_INDEX.md:52` schedules CA-14.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:53` schedules CA-15.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:54` schedules CA-16.
- `docs/CODEX_SECURITY_REVIEW_INDEX.md:69` schedules CA-31.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:15` contains the original CA-14 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:16` contains the original CA-15 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:17` contains the original CA-16 description.
- `codex-security-findings-2026-05-29T13-11-03.346Z.csv:32` contains the original CA-31 description.
- `.codex-audit/round-002/cluster-privacy-lifecycle/investigator.md:16-39` contains the investigator CA-14 position.
- `.codex-audit/round-002/cluster-privacy-lifecycle/investigator.md:55-80` contains the investigator CA-15 position.
- `.codex-audit/round-002/cluster-privacy-lifecycle/investigator.md:94-118` contains the investigator CA-16 position.
- `.codex-audit/round-002/cluster-privacy-lifecycle/investigator.md:133-157` contains the investigator CA-31 position.

### CA-14 References

- `Sources/App/Common/AuthenticationShieldOverlayView.swift:10-15` shows the shield background as `.ultraThinMaterial`.
- `Sources/App/Common/AuthenticationShieldOverlayView.swift:25-31` contains the accessibility label/value saying secure content is hidden.
- `Sources/App/Common/AuthenticationShieldOverlayView.swift:142-145` shows the central card uses `.regularMaterial`.
- `Sources/App/Common/AuthenticationShieldHost.swift:32-46` shows the shield is layered above content with z-index and identity insertion.
- `Sources/App/Common/AuthenticationShieldHost.swift:53-84` shows lifecycle notification wiring for shield dismissal handling.
- `Sources/App/AppContainer.swift:140-155` creates the authentication prompt and shield coordinators.
- `Sources/App/AppContainer.swift:989-1000` wires shield prompt events to `AuthenticationShieldCoordinator.begin/end`.
- `Sources/App/CypherAirApp.swift:488-492` installs the authentication shield host on the main scene.
- `Sources/App/Common/PrivacyScreenModifier.swift:6-13` documents the privacy screen as a blur/material overlay.
- `Sources/App/Common/PrivacyScreenModifier.swift:20-31` shows the privacy screen also uses `.ultraThinMaterial`.
- `docs/PRD.md:213-218` specifies a blur overlay for background privacy.

### CA-15 References

- `Sources/Security/AuthenticationPromptCoordinator.swift:53-60` exposes the operation prompt generation.
- `Sources/Security/AuthenticationPromptCoordinator.swift:134-151` begins an operation prompt, yields, awaits work, ends the prompt, and ends the shield.
- `Sources/Security/AuthenticationPromptCoordinator.swift:197-202` increments the operation prompt generation on begin.
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:54-66` arms prompt-lifecycle suppression when observing a newer generation.
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:68-99` suppresses inactive/resign-active when `.promptLifecycle` is armed.
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:101-114` clears suppression on background.
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:126-165` consumes suppression on active and suppresses `.promptLifecycle` active.
- `Sources/App/Common/PrivacyScreenModifier.swift:60-95` handles UIKit `scenePhase`; `.background` clears suppression and blurs.
- `Sources/App/Common/PrivacyScreenModifier.swift:97-129` handles macOS resign/become notifications without a background clearing path.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:192-224` shows resign-active and background privacy blur behavior; resign-active ignores active operation prompts.
- `Tests/ServiceTests/CommonHelpersTests.swift:426-440` asserts observed operation generation suppresses late inactive and activation.
- `Tests/ServiceTests/CommonHelpersTests.swift:458-477` asserts background clears prompt suppression.
- `Tests/ServiceTests/ProtectedDataFrameworkTests.swift:1980-2048` asserts a late lifecycle cycle after an ended operation prompt skips auth/relock and remains unblurred.
- `Tests/ServiceTests/ProtectedDataFrameworkTests.swift:2206-2237` asserts background during an external operation prompt blurs.

### CA-16 References

- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:213-224` sets the privacy screen on background.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:226-329` performs resume authentication, awaits post-auth work, then clears the blur.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:285-293` clears content/relocks, starts auth, and sets blur.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:317-329` awaits `postAuthenticationHandler`, records completion, and sets `isPrivacyScreenBlurred = false`.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:523-533` increments `postAuthenticationGeneration`.
- `Sources/App/Common/PrivacyScreenModifier.swift:79-83` runs background handling.
- `Sources/App/Common/PrivacyScreenModifier.swift:312-349` launches resume work in an untracked `Task`.
- `Sources/App/AppContainer.swift:451-480` wires the key metadata post-unlock opener.
- `Sources/App/AppContainer.swift:493-557` constructs production `AppSessionOrchestrator` with the post-auth handler.
- `Sources/App/AppContainer.swift:508-550` shows post-auth work opening private-key control, protected domains, contacts, ordinary settings, and recovery state.
- `Sources/Security/ProtectedData/ProtectedDataPostUnlockCoordinator.swift:89-191` opens registered protected domains and may perform authorization/domain open work.
- `Sources/Services/ContactService.swift:31-68` opens contacts after post-unlock.
- `Sources/Services/ContactService.swift:810-838` applies or clears protected runtime contact state.
- `Sources/Services/ContactService.swift:841-845` clears contacts on relock.
- `Sources/App/Settings/MainWindowSettingsRootView.swift:17-20` refreshes protected settings after post-auth generation.
- `Sources/App/Settings/ProtectedSettingsHost.swift:354-372` refreshes settings after app authentication generation.
- `Tests/ServiceTests/ProtectedDataFrameworkTests.swift:2281-2321` tests post-auth generation after handler, but not background interleaving.

### CA-31 References

- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:21` initializes `isPrivacyScreenBlurred` to false.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:149-189` sets blur in `handleInitialAppearance` before delegating to resume, but only when called.
- `Sources/App/Common/PrivacyScreenModifier.swift:20-31` makes the overlay conditional on `isPrivacyScreenBlurred`.
- `Sources/App/Common/PrivacyScreenModifier.swift:131-140` calls initial appearance handling from `.onAppear`.
- `Sources/App/Common/PrivacyScreenModifier.swift:282-309` schedules initial auth in an async `Task`.
- `Sources/App/CypherAirApp.swift:396-417` composes `mainWindowContent` before applying `.privacyScreen()`.
- `Sources/App/CypherAirApp.swift:307-333` shows main window scene construction.
- `Sources/App/CypherAirApp.swift:337-363` shows the standalone macOS Settings scene has an authentication shield host but no privacy screen modifier in that scene.
- `Sources/App/AppContainer.swift:493-508` sets production `shouldBypassPrivacyAuthentication` to false and app-session evaluation.
- `Sources/Models/AppConfiguration.swift:74-81` defaults app-session policy to `.userPresence`.
- `Sources/App/AppStartupCoordinator.swift:20-84` performs pre-auth bootstrap and records key metadata / contacts load as deferred.
- `Sources/Services/KeyManagementService.swift:11-15` starts with empty keys and metadata locked.
- `Sources/App/AppContainer.swift:418-430` creates production key management without a production pre-auth `loadKeys()` call.
- `Sources/App/HomeView.swift:15-40` shows the home screen renders locked/loading/recovery placeholders unless metadata is loaded.
- `Sources/App/Keys/MyKeysView.swift:20-45` shows keys render locked/loading/recovery placeholders unless metadata is loaded.
- `Sources/Services/ContactService.swift:13-15` starts contacts availability locked with no runtime snapshot/search index.
- `Sources/Services/ContactService.swift:834-838` clears contact runtime state.
- `Sources/App/ContentView.swift:6-12` initializes the iOS selected tab to home in memory.
- `Sources/App/Settings/SettingsSecuritySection.swift:10-27` exposes app access policy selection pre-auth.
- `docs/SECURITY.md:331-344` documents protected-domain post-auth rules and `appSessionAuthenticationPolicy` as an early-readable boot-auth exception.
