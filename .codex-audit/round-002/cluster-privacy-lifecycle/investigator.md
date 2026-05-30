# Round 2 Investigator: cluster-privacy-lifecycle

Scope: CA-14, CA-15, CA-16, CA-31. Current HEAD was inspected read-only except for this audit output.

## CA-14

Title: Authentication shield now uses translucent material

Relevant code locations:
- `Sources/App/Common/AuthenticationShieldOverlayView.swift:10-15`
- `Sources/App/Common/AuthenticationShieldOverlayView.swift:142-145`
- `Sources/App/Common/AuthenticationShieldHost.swift:32-46`
- `Sources/App/AppContainer.swift:140-150`
- `Sources/App/CypherAirApp.swift:488-492`

Mechanism-present status: Present. The full-screen authentication shield is a `Rectangle().fill(.ultraThinMaterial)`, and its central card uses `.regularMaterial`.

Shipped reachability: Reachable in production. `AppContainer` wires `AuthenticationPromptCoordinator` shield events to `AuthenticationShieldCoordinator`; `CypherAirApp` installs `authenticationShieldHost` on the main scene and macOS Settings; app-session authentication and private-key/protected-data operation prompts use the coordinator.

Mitigations:
- The shield is full-screen, ignores safe areas, uses z-index above content, and is inserted with identity transition.
- Sensitive text-entry views also use `.privacySensitive()`, but that does not make the shield opaque.

Evidence-real:
- The overlay source uses `.ultraThinMaterial`, not an opaque `Color` or image-backed privacy cover.
- The shield's own accessibility value says secure content is hidden, but the visual implementation remains material-backed.
- The same material pattern is also used by `PrivacyScreenModifier`, so this is consistent with the reported privacy-shield opacity concern.

Evidence-false-positive:
- No current-code evidence shows an opaque backing layer behind the material.
- No test or platform-specific branch verifies that high-contrast underlying content is unreadable through the material.

Preliminary disposition: Evidence-real / confirmed.

Confidence: High.

Open questions:
- Product/design decision: should authentication and privacy shields be fully opaque on all supported platforms, or is blur-only considered acceptable?
- Visual validation is still needed on iOS 26.5, macOS 26.5, and visionOS 26.5 because material opacity is platform-rendered.

## CA-15

Title: Stale operation prompt generation can disable privacy blur

Relevant code locations:
- `Sources/Security/AuthenticationPromptCoordinator.swift:53-60`
- `Sources/Security/AuthenticationPromptCoordinator.swift:197-202`
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:54-66`
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:68-99`
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift:126-165`
- `Sources/App/Common/PrivacyScreenModifier.swift:61-95`
- `Sources/App/Common/PrivacyScreenModifier.swift:98-129`
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:192-224`

Mechanism-present status: Present. Observing a newer operation-authentication generation arms `.promptLifecycle` suppression even when the operation prompt has already ended; the next inactive/resign event can then be suppressed.

Shipped reachability: Reachable. Operation prompts are used for private-key unwrap and protected-data root-secret access. The privacy lifecycle gate is installed on the main scene for UIKit `scenePhase` changes and macOS `NSApplication.didResignActive` / `didBecomeActive` notifications.

Mitigations:
- If a real `.background` event arrives, `shouldHandleBackground()` clears suppression and `handleSceneDidEnterBackground()` blurs.
- If the operation prompt is still in progress, suppressing transient lifecycle notifications is intentional.
- Existing tests cover prompt suppression and background clearing.

Evidence-real:
- `syncOperationAuthenticationAttemptGeneration(_:)` arms prompt suppression solely from a new generation.
- `shouldHandleInactive` returns `.suppress` for `.promptLifecycle`; `PrivacyScreenModifier` returns before calling `handleSceneDidResignActive`.
- On macOS, the app has resign/become notifications but no paired background event in this path.
- `test_lateLifecycleAfterOperationPromptEnds_doesNotTriggerPrivacyResumeAuthentication` currently asserts `isPrivacyScreenBlurred == false` after a late inactive/active cycle following an ended operation prompt.

Evidence-false-positive:
- The iOS `.background` path reduces exposure when background is delivered after inactive.
- This does not refute macOS resign-active reachability or inactive-only timing before a background snapshot.

Preliminary disposition: Evidence-real / confirmed.

Confidence: High.

Open questions:
- What precise lifecycle ordering should be considered benign system-auth prompt cleanup versus real focus loss on each Apple platform?
- Should stale operation generation be consumed only by callbacks known to belong to the prompt lifecycle, rather than by the first later inactive/resign event?

## CA-16

Title: Post-auth warm-up can clear background privacy blur

Relevant code locations:
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:285-329`
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:213-224`
- `Sources/App/Common/PrivacyScreenModifier.swift:312-345`
- `Sources/App/AppContainer.swift:508-550`
- `Sources/App/Settings/MainWindowSettingsRootView.swift:17-20`
- `Sources/App/Settings/ProtectedSettingsHost.swift:354-372`

Mechanism-present status: Present in current form. The exact historical `runPostAuthenticationWarmUpIfNeeded` / `ProtectedSettingsHost.warmUpAfterAppUnlock` path is gone, but `handleResume` still awaits async post-authentication work and then unconditionally sets `isPrivacyScreenBlurred = false`.

Shipped reachability: Reachable. Production post-authentication work opens registered ProtectedData domains, contacts, protected settings availability, and private-key-control recovery. A background event can run while `handleResume` is suspended in this async handler.

Mitigations:
- `handleSceneDidEnterBackground()` itself fail-closed sets `isPrivacyScreenBlurred = true`.
- Successful app authentication performs content clear and protected-data relock before evaluating the prompt.
- ProtectedSettingsHost refresh now observes `postAuthenticationGeneration` separately rather than being directly awaited inside `handleResume`.

Evidence-real:
- After `await postAuthenticationHandler(...)`, `handleResume` records post-auth completion and clears `isPrivacyScreenBlurred` without checking scene foreground/background state or a lifecycle generation.
- `PrivacyScreenModifier` launches `handleResume` in an untracked `Task`; background handling does not cancel that task.
- There is no foreground-state guard in `AppSessionOrchestrator` around the final blur clear.

Evidence-false-positive:
- The finding's named warm-up method does not exist in current HEAD, and the Settings host refresh is now triggered after `postAuthenticationGeneration`.
- This narrows the historical mechanism but does not eliminate the underlying async-resume/background race.

Preliminary disposition: Evidence-real / confirmed, with mechanism wording updated for current HEAD.

Confidence: Medium-high.

Open questions:
- Is `AppSessionOrchestrator` intended to own explicit foreground/background state, or should `PrivacyScreenModifier` cancel and restart resume tasks across scene transitions?
- A regression test with a suspended `postAuthenticationHandler` and an intervening `handleSceneDidEnterBackground()` would make the race concrete.

## CA-31

Title: Launch auth can show content before blur is enabled

Relevant code locations:
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:21`
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift:149-189`
- `Sources/App/Common/PrivacyScreenModifier.swift:20-31`
- `Sources/App/Common/PrivacyScreenModifier.swift:131-140`
- `Sources/App/Common/PrivacyScreenModifier.swift:282-309`
- `Sources/App/CypherAirApp.swift:396-417`
- `Sources/App/AppContainer.swift:493-508`

Mechanism-present status: Present. `isPrivacyScreenBlurred` initializes to `false`; the privacy overlay is conditional; initial launch authentication is scheduled only from `.onAppear` via an async `Task`.

Shipped reachability: Reachable in production. Normal `AppContainer` sets `shouldBypassPrivacyAuthentication: { false }`, and `AppConfiguration` defaults app-session authentication policy to `.userPresence`. The main window content is composed before `.privacyScreen()` schedules initial authentication.

Mitigations:
- `handleInitialAppearance` sets the blur before delegating to `handleResume`.
- ProtectedData domains remain locked before app authentication, reducing the amount of protected persisted data available to pre-auth views.
- UI-test containers can bypass authentication, but production does not.

Evidence-real:
- The first render path can evaluate `mainWindowContent` while `isPrivacyScreenBlurred == false`.
- `.onAppear` increments state and starts the initial auth task after the view has appeared.
- There is no constructor-time or pre-render initialization that sets the app privacy gate locked for the normal production policy.

Evidence-false-positive:
- ProtectedData locking may limit sensitive domain contents on cold launch.
- It does not address visual exposure of the app shell, navigation state, load warnings, or any non-ProtectedData state before the first `.onAppear` update.

Preliminary disposition: Evidence-real / confirmed.

Confidence: High.

Open questions:
- Should production initialize the privacy overlay to locked by default and then explicitly clear it only for authenticated/bypass states?
- Do macOS Settings and alternate launch roots need the same first-frame launch-auth treatment?
