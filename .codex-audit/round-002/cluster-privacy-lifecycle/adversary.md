# Round 2 Adversary: cluster-privacy-lifecycle

Scope: CA-14, CA-15, CA-16, CA-31. This pass challenges the investigator result against current source, product docs, and the original finding text.

## CA-14

### Challenge Summary

The investigator correctly identifies the mechanism: the authentication shield and privacy screen are material-backed, not opaque. The impact conclusion is stronger than the evidence supports. Current product text promises a "Blur overlay" for background privacy, and no visual evidence demonstrates that underlying text or metadata is actually readable through `.ultraThinMaterial` on the supported OS versions. This is a confidentiality-hardening concern, not yet a demonstrated readable-content leak.

### Strongest Evidence Against Real Impact

- The shield is full-screen, ignores safe areas, sits above content, and is inserted without an initial opacity transition, so there is no obvious uncovered frame in the shield itself.
- SwiftUI material is blurred/translucent, but the finding does not include screenshots, pixel checks, or platform-specific validation showing readable plaintext, key metadata, filenames, or contact names.
- The PRD describes the background protection as a blur overlay, not an opaque cover. Treating all blur translucency as a security failure may exceed the documented product requirement.
- Most protected app data is locked or relocked around app-session authentication; during many privacy-auth paths the app is showing the overlay before protected key/contact metadata is available.

### Strongest Evidence Supporting Real Impact

- The shield background is explicitly `.ultraThinMaterial`, and the central card is `.regularMaterial`, so the implementation is not opaque.
- The shield is used for privacy and operation prompts, including times when decrypted text, selected filenames, key rows, contact names, or signing/decryption state may already be visible behind it.
- The accessibility copy says secure content is hidden, which is a stronger guarantee than "blurred."
- `.ultraThinMaterial` can preserve color, layout, and large high-contrast shapes even when text is not cleanly readable.

### Practical Shipped Scenario

A user starts an operation prompt while a high-contrast decrypted message, selected filename, or key/contact row is visible. A nearby observer may infer layout, colors, row counts, or possibly large text through the material. I do not see evidence that ordinary body text is reliably readable, so the practical scenario is shoulder-surf inference rather than direct plaintext extraction.

### Final Recommendation

`real-low`

### Confidence

Medium.

### Questions For Main Codex/User Discussion

- Is the intended privacy boundary "blurred enough for app switcher and casual shoulder surfing" or "opaque with no visual inference"?
- Should authentication/operation shields use a more opaque background than the general PRD background blur?
- Do we want platform screenshots before deciding whether `.ultraThinMaterial` is acceptable on iOS, macOS, and visionOS?

## CA-15

### Challenge Summary

The stale-generation mechanism is real, but the shipped impact is narrower than the investigator framing. On iOS/visionOS, a real `.background` event clears suppression and blurs. The clearest remaining shipped exposure is macOS app deactivation, or inactive-only transitions, after an operation prompt that did not already produce a lifecycle callback observed by the privacy gate.

### Strongest Evidence Against Real Impact

- Suppression for operation prompts is intentional: system authentication prompts can produce transient inactive/resign-active events that should not force app-session reauthentication.
- If the real focus loss includes a `.background` callback, `shouldHandleBackground()` clears suppression and `handleSceneDidEnterBackground()` sets the privacy screen.
- The stale generation is consumed after one inactive/active cycle, so it does not permanently disable the lifecycle gate.
- The finding depends on a specific ordering: an operation prompt must complete without the gate seeing a prompt-related lifecycle notification, and the first later lifecycle callback must be a genuine focus loss.

### Strongest Evidence Supporting Real Impact

- `syncOperationAuthenticationAttemptGeneration(_:)` arms `.promptLifecycle` suppression solely because the generation increased, without knowing whether the prompt is still in progress.
- When `.promptLifecycle` is armed, the next inactive/resign-active event is suppressed and does not call `handleSceneDidResignActive()`.
- macOS uses `NSApplication.didResignActive` / `didBecomeActive` in this path and has no paired background event to clear the stale suppression.
- Current tests explicitly assert that a late inactive/active cycle after an ended operation prompt leaves `isPrivacyScreenBlurred == false` and skips relock/authentication.

### Practical Shipped Scenario

On macOS, the user completes a Touch ID/passcode operation prompt, then later switches to another app. If the operation prompt did not already produce a lifecycle callback that consumed the generation, the real `didResignActive` can be suppressed. The CypherAir window can remain unblurred while inactive, exposing whatever unlocked app state is visible in that window.

### Final Recommendation

`real-needs-fix`

### Confidence

Medium-high.

### Questions For Main Codex/User Discussion

- Which lifecycle callbacks are actually produced by LocalAuthentication prompts on macOS 26.5 and iOS/visionOS 26.5?
- Should operation-prompt suppression expire by time, prompt context, or explicit prompt-end state instead of the next arbitrary lifecycle event?
- Is blur-on-macOS-resign-active a strict privacy requirement, or only a best-effort companion to iOS background snapshots?

## CA-16

### Challenge Summary

The exact historical "warm-up" method named in the finding is gone, but the core async race still exists: `handleResume` can authenticate, await post-auth domain opening, and later clear `isPrivacyScreenBlurred` without checking whether the scene entered background while it was suspended. The investigator is right on mechanism, but the snapshot impact remains timing-dependent and unproven without a regression test or platform trace.

### Strongest Evidence Against Real Impact

- `handleSceneDidEnterBackground()` immediately sets the privacy screen to true, so the common iOS background-snapshot path is protected if the snapshot happens promptly after the background event.
- iOS/visionOS may suspend app work quickly after backgrounding, which can prevent the suspended resume task from reaching the final unblur assignment until foreground.
- The old `ProtectedSettingsHost.warmUpAfterAppUnlock()` path is no longer present; protected settings refresh is now triggered by `postAuthenticationGeneration` after `handleResume` completes.
- No current test demonstrates the interleaving with a suspended post-auth handler and an intervening background event.

### Strongest Evidence Supporting Real Impact

- `handleResume` unconditionally sets `isPrivacyScreenBlurred = false` after `await postAuthenticationHandler(...)` succeeds.
- The post-auth handler opens protected domains, contacts, ordinary settings, and recovery state before the blur is cleared.
- `PrivacyScreenModifier` launches resume work in untracked `Task` blocks; background handling neither cancels those tasks nor gives `AppSessionOrchestrator` a foreground/background generation.
- If backgrounding occurs while post-auth work is suspended and the task later resumes before the next foreground auth, it can undo the background blur.

### Practical Shipped Scenario

The user unlocks the app and immediately backgrounds it while post-auth domain opening, migration, or recovery is still running. Background handling blurs first, but the in-flight resume task completes later and clears the blur while key/contact/settings state may now be loaded. If the OS captures or refreshes a background/app-switcher snapshot after that point, sensitive UI can be visible.

### Final Recommendation

`real-needs-fix`

### Confidence

Medium.

### Questions For Main Codex/User Discussion

- Can we collect an auth lifecycle trace proving whether iOS/visionOS snapshots can happen after the final unblur in this interleaving?
- Should `AppSessionOrchestrator` own scene activity/generation, or should `PrivacyScreenModifier` cancel resume tasks on background?
- Should the post-auth handler be allowed to finish in background while keeping the overlay locked until a fresh active-scene resume?

## CA-31

### Challenge Summary

The first-frame mechanism is real: the privacy overlay starts false and initial auth is scheduled from `.onAppear`. The claimed privacy impact is much weaker in current HEAD because cold-start key metadata and contacts are not loaded before app-session authentication. The likely first-frame exposure is app chrome, locked placeholders, and documented boot-auth settings, not the key/contact metadata or decrypted content described in the original finding.

### Strongest Evidence Against Real Impact

- Production startup defers key metadata and contacts until post-unlock protected-domain opening.
- `KeyManagementService` starts with `metadataLoadState = .locked` and an empty key list; Home and Keys render "locked" placeholder states before auth.
- `ContactService` starts locked and clears runtime snapshots on relock.
- No `@SceneStorage` or comparable restoration path was found for selected tab, navigation path, plaintext, decrypted text, or file names in the main app shell.
- `AppSessionAuthenticationPolicy` is a documented early-readable boot-authentication exception, so seeing that policy in Settings is not itself a protected-data leak.

### Strongest Evidence Supporting Real Impact

- `isPrivacyScreenBlurred` initializes to false, and the overlay is conditional on that state.
- `mainWindowContent` is composed before `.privacyScreen()` schedules `handleInitialAppearance` in an asynchronous `Task`.
- `handleInitialAppearance` does set the blur before calling `handleResume`, but only after the view appears.
- The app shell, tabs/sidebar, launch root, load/recovery placeholders, and possibly macOS Settings UI can be visible for at least one pre-auth render.

### Practical Shipped Scenario

On a true cold launch, a person with access to the unlocked device may briefly see CypherAir's shell and locked-state placeholders before the privacy overlay/auth prompt appears. I did not find a current cold-launch path that exposes protected key metadata, contact metadata, decrypted plaintext, or restored navigation state in that first frame.

### Final Recommendation

`real-low`

### Confidence

Medium-high.

### Questions For Main Codex/User Discussion

- Is launch auth intended to hide all CypherAir chrome, or only protected content?
- Should first-frame lock default to true anyway as defense-in-depth against future pre-auth UI state?
- Should the standalone macOS Settings scene participate in the same app-session privacy overlay, or is its pre-auth content intentionally limited to safe boot settings?
