# Tutorial Mode Issues

## Purpose

This document is the problem baseline for a future tutorial rebuild spec. It captures how the current tutorial implementation behaves, where that behavior diverges from the product promise, and which design boundaries the rebuild spec must lock down before implementation starts.

This document is intentionally not a redesign. It does not defend the current implementation, and it does not break the work down into patch-sized tasks. Its job is to answer three questions for each issue:

1. How does the tutorial work today?
2. Why does that behavior conflict with the intended tutorial experience?
3. Which boundary must the rebuild spec decide up front?

The current review list contains 13 issues across iOS, iPadOS, and macOS.

## Scope And Evidence Rules

- Scope is limited to the currently identified tutorial and onboarding issues. This is not a general UX audit of the full app.
- Code evidence is the primary source of truth for this document.
- Items that need runtime reproduction to fully confirm visual severity are marked as `Evidence status: code-strong, runtime repro material pending`.
- No public APIs, data models, or project structure are changed by this document.

## Severity Legend

- `P0`: Trust or product-promise break. The tutorial teaches something false or unsafe.
- `P1`: High-impact flow break. Users can be blocked, mislabeled, or routed incorrectly.
- `P2`: Major UX or platform-coherence problem. The feature works, but the guidance model or host model is unstable.
- `P3`: Testability and regression debt. The product remains vulnerable to repeat breakage.

## Primary Evidence Chain

The core tutorial behavior is anchored in these files:

- `Sources/App/Onboarding/TutorialView.swift`
- `Sources/App/Onboarding/OnboardingView.swift`
- `Sources/App/CypherAirApp.swift`
- `Sources/App/Shell/MacPresentationHost.swift`

Those files define the tutorial promise, entry flows, presentation hosts, and finish/return semantics. Each issue below adds supporting evidence from the specific shell, route, modal, or test implementation involved.

## 1. Trust Boundary And Sandbox

### P0. Sandbox promise and shell capability do not match

- Platforms: iOS, iPadOS, macOS
- User symptom:
  The tutorial repeatedly promises that real keys, settings, files, and exports are never touched, but the tutorial shell still exposes real system import and export affordances.
- Code evidence:
  - Promise copy: `Sources/App/Onboarding/TutorialView.swift:123`, `Sources/App/Onboarding/TutorialView.swift:126`, `Sources/App/Onboarding/TutorialSandboxAcknowledgementView.swift:17`, `Sources/App/Onboarding/TutorialSandboxAcknowledgementView.swift:29`, `Sources/App/Onboarding/Tutorial/TutorialGuidanceResolver.swift:191`
  - Real sandbox container exists: `Sources/App/Onboarding/TutorialSandboxContainer.swift:17`
  - Tutorial shell reuses broad app roots: `Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift:57`
  - Route destinations often fall back to unrestricted views when the active task does not match: `Sources/App/Onboarding/Tutorial/TutorialRouteDestinationView.swift:18`
  - File import and export entry points remain in tutorial-reused views:
    - `Sources/App/Encrypt/EncryptView.swift:263`, `Sources/App/Encrypt/EncryptView.swift:326`, `Sources/App/Encrypt/EncryptView.swift:364`
    - `Sources/App/Decrypt/DecryptView.swift:211`, `Sources/App/Decrypt/DecryptView.swift:254`, `Sources/App/Decrypt/DecryptView.swift:303`
    - `Sources/App/Contacts/AddContactView.swift:148`, `Sources/App/Contacts/AddContactView.swift:198`, `Sources/App/Contacts/AddContactView.swift:219`
    - `Sources/App/Keys/BackupKeyView.swift:142`
    - `Sources/App/Keys/KeyDetailView.swift:171`, `Sources/App/Keys/KeyDetailView.swift:288`
- Current behavior:
  The tutorial does have a real isolation layer for `UserDefaults`, contacts storage, and security primitives. `TutorialSandboxContainer` swaps in tutorial-specific defaults, a temporary contacts directory, and mock secure enclave / keychain / authenticator instances.

  That isolation layer is not the same thing as a safe tutorial shell. The shell still reuses broad production views and routes, many of which keep system `fileImporter`, `fileExporter`, and photo-picker surfaces enabled. Some tutorial tasks narrow configuration for a specific task instance, but the shell as a whole still exposes routes and views whose real-world file capabilities remain live.
- Conflict with tutorial promise:
  The copy currently claims a stronger guarantee than the implementation enforces. "Sandbox data is isolated" is true. "Real files and exports are never touched" is not a safe promise while the tutorial still exposes production file import/export entry points.
- Rebuild spec constraints:
  The rebuild spec must define a tutorial-shell capability whitelist. Data isolation alone is insufficient. The spec must decide which views, routes, and system pickers are allowed inside tutorial mode and what the safe replacement behavior is for disallowed operations.
- Recommended direction:
  Treat tutorial safety as a shell-level contract, not just a container-level one. Either:
  - shrink tutorial mode to a clearly defined safe subset with sandbox-only import/export behavior, or
  - explicitly downgrade tutorial copy to match the real behavior until the shell is rebuilt.

## 2. Lifecycle And Completion State

### P1. Guided tutorial writes global completion too early

- Platforms: iOS, iPadOS, macOS
- User symptom:
  A user can be marked as having completed the tutorial as soon as the final task completes, even if they never see the completion view, never finish cleanup, and never complete the final handoff.
- Code evidence:
  - Completion state is written inside task completion: `Sources/App/Onboarding/TutorialSessionStore.swift:254`
  - Actual finish and cleanup happen later: `Sources/App/Onboarding/TutorialView.swift:313`
  - Current test suite locks in the existing behavior: `Tests/ServiceTests/TutorialSessionStoreTests.swift:138`
- Current behavior:
  `TutorialSessionStore.complete(_:)` marks a task complete, sets the prompt state, and immediately calls `markGuidedTutorialCompletedCurrentVersion()` once all tasks are complete. The actual end-of-flow cleanup lives in `TutorialView.finishTutorial()`, which dismisses the completion view, cleans up the sandbox, and marks onboarding complete for first-run presentation.
- Conflict with tutorial goal:
  The product conceptually has three distinct facts:
  - all tasks are complete,
  - the completion view is being shown,
  - the tutorial has been successfully finished and cleaned up.

  The current code collapses the first and third facts into the same write. That makes analytics-free local state still semantically wrong: a user is globally labeled "completed" before the tutorial truly finishes.
- Rebuild spec constraints:
  The rebuild spec must define separate lifecycle facts for:
  - task completion,
  - completion-view eligibility,
  - final tutorial completion,
  - cleanup success.
- Recommended direction:
  Move the global completion write to the true finish point. Task completion should only unlock the completion view and any in-session continuation state.

## 3. Onboarding To Tutorial Handoff

### P1. Onboarding page 3 copy, CTA labels, and actual handoff are misaligned

- Platforms: iOS, iPadOS, macOS
- User symptom:
  The third onboarding page reads like a key-generation page, but its primary action opens the tutorial instead. The secondary action says "Get Started" even though it is the path that actually skips the tutorial and enters the app.
- Code evidence:
  - Page 3 title and body still describe key generation: `Sources/App/Onboarding/OnboardingView.swift:146`, `Sources/App/Onboarding/OnboardingView.swift:149`
  - Primary button opens tutorial: `Sources/App/Onboarding/OnboardingView.swift:155`
  - Secondary button marks onboarding complete and dismisses: `Sources/App/Onboarding/OnboardingView.swift:165`
- Current behavior:
  The user is told they are about to generate a key, then the primary CTA opens tutorial mode. The alternate CTA directly exits onboarding. The page's copy, hierarchy, and real behavior describe different outcomes.
- Conflict with tutorial goal:
  First-run onboarding must teach a clear choice. The current page instead mixes "key generation", "tutorial entry", and "enter the app" into one screen, which obscures what happens next.
- Rebuild spec constraints:
  The rebuild spec must define the onboarding-to-tutorial decision point as a first-class product choice, including the correct page intent, button order, and fallback behavior when a user skips the tutorial.
- Recommended direction:
  Replace the current page-3 messaging with tutorial-specific copy and explicit dual-path CTA semantics:
  - learn and start the tutorial
  - skip the tutorial and enter the app

### P1. iOS handoff from onboarding sheet to tutorial is structurally fragile

- Platforms: iOS and iPadOS, especially iPhone
- User symptom:
  Tapping the tutorial CTA can appear to do nothing, or the handoff can feel unreliable.
- Code evidence:
  - Onboarding is presented as a sheet while tutorial is presented as a full-screen cover from the same host: `Sources/App/CypherAirApp.swift:86`, `Sources/App/CypherAirApp.swift:89`
  - The page-3 button presents tutorial directly without first dismissing onboarding: `Sources/App/Onboarding/OnboardingView.swift:199`
- Evidence status: code-strong, runtime repro material pending
- Current behavior:
  iOS keeps a single `activeIOSPresentation` state that can drive either the onboarding sheet or the tutorial full-screen cover. From inside the onboarding sheet, page 3 directly requests tutorial presentation rather than explicitly closing onboarding first and then opening tutorial as a separate transition.
- Conflict with tutorial goal:
  The first-run handoff should be a clear, deterministic transition. The current setup depends on cross-presenting from within a still-active onboarding presentation, which is exactly the kind of structure that tends to create weak or inconsistent tap results on iOS.
- Rebuild spec constraints:
  The rebuild spec must define a single handoff model for first run on iOS:
  - either onboarding dismisses before tutorial starts,
  - or tutorial owns the whole first-run flow and onboarding does not present it as a nested transition.
- Recommended direction:
  Do not switch to tutorial in place from the onboarding sheet. Close onboarding first, then launch tutorial explicitly.

## 4. Layout And Accessibility

### P1. Tutorial home screen does not show an accessibility-size-specific layout

- Platforms: iOS, especially iPhone with very large Dynamic Type
- User symptom:
  The tutorial home screen is likely to become top-heavy under large accessibility sizes: the hero card remains large, title lines are expensive, and the phase list loses first-screen visibility.
- Code evidence:
  - Tutorial home is a single scroll stack with large hero first: `Sources/App/Onboarding/TutorialView.swift:90`
  - Hero card has no Dynamic Type branch or compacted layout: `Sources/App/Onboarding/TutorialView.swift:114`
  - Dynamic Type adaptation exists for the inline in-task header, but not for tutorial home: `Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift:10`
- Evidence status: code-strong, runtime repro material pending
- Current behavior:
  The tutorial home screen uses one hero block followed by phase cards. The hero title/body/actions do not define an accessibility-specific variant, while the only visible Dynamic Type tailoring in the tutorial codebase is for the in-task inline header.
- Conflict with tutorial goal:
  The tutorial home screen is the map of the experience. At accessibility sizes, it must preserve scanability and immediate orientation. A hero-first layout that expands without a separate accessibility treatment will undermine that goal.
- Rebuild spec constraints:
  The rebuild spec must include a dedicated accessibility-size home layout, not just typography scaling.
- Recommended direction:
  Define a lighter accessibility hero, allow title wrapping explicitly, and preserve at least part of the phase/task map in the first screenful.

### P2. Compact and regular iOS layouts produce materially different guidance strength

- Platforms: iOS and iPadOS
- User symptom:
  The same task can feel tightly guided on iPhone but weak and spatially disconnected on iPad regular width.
- Code evidence:
  - Compact and regular paths diverge for key tasks: `Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift:22`
  - Guidance text also changes by size class: `Sources/App/Onboarding/Tutorial/TutorialGuidanceResolver.swift:58`
  - UIKit tutorial surfaces rely on a generic top inline header rather than a regular-width-specific guidance container: `Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift:167`
- Evidence status: code-strong, runtime repro material pending
- Current behavior:
  Compact mode routes several tutorial tasks through Home shortcuts, which naturally keeps the tutorial prompt close to the action. Regular width instead routes those tasks into broader tool destinations, but still uses the same generic top guidance treatment instead of a layout designed to keep guidance adjacent to the target area.
- Conflict with tutorial goal:
  The tutorial should teach the same product model across form factors. It can adapt, but it should not feel like a strong, task-bound walkthrough on one class of device and a loose banner hint on another.
- Rebuild spec constraints:
  The rebuild spec must define separate guidance placement rules for compact and regular iOS layouts.
- Recommended direction:
  Give regular width its own guidance container model, such as a constrained side rail, nearby floating guidance panel, or target-adjacent assist layout.

## 5. Modal And Guidance Continuity

### P2. Opening a tutorial modal removes all guidance context

- Platforms: iOS, iPadOS, macOS
- User symptom:
  When a tutorial modal opens, the guidance disappears entirely. This is especially harmful during high-security mode confirmation, where the user loses the "why am I here and what happens next?" context.
- Code evidence:
  - Guidance resolver returns `nil` whenever a modal is active: `Sources/App/Onboarding/Tutorial/TutorialGuidanceResolver.swift:10`
  - Shell-level guidance is suppressed while a modal is active: `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift:18`
  - Inline in-task header is also suppressed when a modal is active: `Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift:185`
  - Spotlight overlay also disappears because current guidance becomes `nil`: `Sources/App/Onboarding/Tutorial/TutorialSandboxChromeView.swift:39`
- Current behavior:
  Tutorial guidance is treated as something that belongs only to the underlying surface. Once a modal appears, the tutorial model effectively removes all task framing from the UI.
- Conflict with tutorial goal:
  Important confirmations are part of the tutorial, not interruptions to it. The tutorial should stay legible at the exact moment a user must confirm something risky or unfamiliar.
- Rebuild spec constraints:
  The rebuild spec must define a modal guidance contract. Critical tutorial modals need a minimal persistent context model.
- Recommended direction:
  Keep a reduced tutorial context inside tutorial-owned modals: task title, why the confirmation exists, and what the next step will be.

### P2. Tutorial auth confirmation is missing stable markers and unused anchor wiring remains unresolved

- Platforms: iOS, iPadOS, macOS
- User symptom:
  The auth-mode confirmation shown inside tutorial mode has no stable screen-ready marker, no stable confirm identifier, and no connected tutorial anchor for the confirm action.
- Code evidence:
  - Tutorial auth confirmation view lacks `screenReady`, `accessibilityIdentifier`, and tutorial anchor usage: `Sources/App/Onboarding/TutorialAuthModeConfirmationView.swift:10`
  - Production auth confirmation does include them: `Sources/App/Settings/AuthMode/AuthModeChangeConfirmation.swift:37`
  - The anchor enum reserves `settingsModeConfirmButton`, but no production or tutorial view attaches it: `Sources/App/Onboarding/TutorialSpotlightOverlay.swift:11`
- Current behavior:
  The tutorial modal uses a separate view from the production auth confirmation sheet, but it does not carry over the same test hooks or anchorability.
- Conflict with tutorial goal:
  The confirmation step is a key tutorial step, especially for "Enable High Security." It should be one of the easiest tutorial states to identify, anchor, and regress-test.
- Rebuild spec constraints:
  The rebuild spec must define stable markers and anchor coverage for tutorial-critical modals, not just full screens.
- Recommended direction:
  Treat tutorial auth confirmation as a first-class tutorial surface with explicit markers and anchor targets.

## 6. macOS Host And Window Model

### P1. macOS tutorial currently has three host modes with inconsistent close semantics

- Platforms: macOS
- User symptom:
  "Done", "Close", and "Return" semantics depend on which outer host launched the tutorial rather than the tutorial owning a single host model.
- Code evidence:
  - Tutorial can be the root view of the app window: `Sources/App/CypherAirApp.swift:180`
  - Tutorial can be presented as an app-internal sheet: `Sources/App/Shell/MacPresentationHost.swift:47`
  - Tutorial can also be presented from onboarding as a nested sheet: `Sources/App/Onboarding/OnboardingView.swift:178`
  - Finish logic branches on host availability and optional callbacks: `Sources/App/Onboarding/TutorialView.swift:313`
  - Close logic also changes by presentation context: `Sources/App/Onboarding/TutorialView.swift:330`
- Current behavior:
  macOS has no single tutorial-host contract. Depending on entry path, tutorial dismissal may be handled by root-window navigation, a sheet dismissal, or a callback passed in from onboarding.
- Conflict with tutorial goal:
  The tutorial should feel like one product surface on macOS. Host ambiguity makes the exit model harder to reason about, test, and explain.
- Rebuild spec constraints:
  The rebuild spec must choose one primary macOS host strategy and define the semantics of:
  - close,
  - done,
  - return to overview,
  - return to app context.
- Recommended direction:
  Standardize on one macOS tutorial host model and make all tutorial exit actions resolve through that model.

### P2. macOS launch-time auth confirmation is injected before Settings has stable context

- Platforms: macOS
- User symptom:
  A user can land in Settings and immediately get a confirmation sheet without first seeing the page that explains where they are.
- Code evidence:
  - `MacSettingsRootView` injects auth confirmation from `.task`: `Sources/App/Settings/SettingsView.swift:410`
- Current behavior:
  The view can present auth-mode confirmation as soon as the settings root appears, before the root page has established context.
- Conflict with tutorial goal:
  A tutorial confirmation should be contextualized by the screen that led to it. Presenting the modal at launch time makes the confirmation feel detached from the tutorial narrative.
- Rebuild spec constraints:
  The rebuild spec must decide whether confirmation is user-triggered only or whether any automated tutorial step may present it after a defined contextual staging state.
- Recommended direction:
  Make the confirmation a second-stage action after Settings is visibly established.

### P2. macOS tutorial width budget is structurally too tight

- Platforms: macOS
- User symptom:
  Form-heavy tutorial tasks are likely to feel cramped in the detail column, especially once the sidebar and inspector are both visible.
- Code evidence:
  - Main app default window is `900x650`: `Sources/App/CypherAirApp.swift:157`
  - Tutorial shell sheet minimum is `880x640`: `Sources/App/Onboarding/TutorialView.swift:62`
  - Tutorial sidebar is `220-260` wide: `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift:63`
  - Inspector is `260-360` wide: `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift:53`
- Current behavior:
  The macOS tutorial layout reserves substantial fixed width for navigation chrome on top of a relatively narrow overall window baseline. That leaves the detail area as the part that absorbs the compression.
- Conflict with tutorial goal:
  The tutorial should privilege the task surface. A cramped detail pane works against a teaching-oriented experience, especially for forms and multi-step explanations.
- Rebuild spec constraints:
  The rebuild spec must define a minimum usable detail width for tutorial tasks and size the host around that requirement.
- Recommended direction:
  Either enlarge the tutorial host window or rebalance sidebar and inspector widths so the task surface wins.

### P2. macOS tutorial inspector has no obvious recovery affordance once closed

- Platforms: macOS
- User symptom:
  If the user hides the inspector, the primary guidance surface disappears and there is no clear tutorial-owned way to bring it back.
- Code evidence:
  - Inspector visibility is stored in tutorial state: `Sources/App/Onboarding/TutorialSessionStore.swift:204`
  - The split view binds directly to that state: `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift:132`
  - No tutorial-specific "Show Guidance" affordance exists in the tutorial shell codebase; search only finds the state wiring and inspector content, not a restore control.
- Current behavior:
  Guidance on macOS is primarily housed in the inspector. If the inspector is dismissed, the tutorial shell does not expose a dedicated restore entry point.
- Conflict with tutorial goal:
  The guidance model should be recoverable by design, not dependent on a platform inspector affordance the tutorial itself does not explain.
- Rebuild spec constraints:
  The rebuild spec must define a fallback guidance recovery path on macOS.
- Recommended direction:
  Add an explicit tutorial-owned restore mechanism or preserve a lightweight fallback guidance strip in the detail area when the inspector is hidden.

## 7. Testability And Automation Debt

### P3. Onboarding and tutorial lack stable page- and modal-level markers

- Platforms: iOS, iPadOS, macOS
- User symptom:
  Several high-value tutorial states cannot be targeted reliably in UI automation because they do not expose stable ready markers or identifiers.
- Code evidence:
  - `OnboardingView.swift` has no page-level `screenReady` markers or page identifiers.
  - Tutorial auth confirmation lacks stable identifiers and ready markers: `Sources/App/Onboarding/TutorialAuthModeConfirmationView.swift:10`
  - The reserved tutorial anchor `settingsModeConfirmButton` is still unused: `Sources/App/Onboarding/TutorialSpotlightOverlay.swift:11`
  - Production surfaces show the intended pattern: `Sources/App/Settings/AuthMode/AuthModeChangeConfirmation.swift:41`, `Sources/App/Shell/ScreenReadyModifier.swift:4`
- Current behavior:
  The project uses a workable `screenReady` pattern for many screens, but onboarding pages and some tutorial-critical modal states never adopted it.
- Conflict with tutorial goal:
  The first-run path and tutorial modals are exactly the surfaces that most need stable regression hooks.
- Rebuild spec constraints:
  The rebuild spec must define a marker contract for:
  - onboarding pages,
  - tutorial overview,
  - tutorial completion,
  - tutorial-owned modals,
  - tutorial anchor targets.
- Recommended direction:
  Make ready markers and tutorial anchors part of the tutorial surface contract, not optional follow-up polish.

### P3. iOS has no end-to-end onboarding/tutorial UI automation coverage

- Platforms: iOS and iPadOS
- User symptom:
  The most failure-prone first-run paths have no automated regression coverage.
- Code evidence:
  - The repository currently contains only one UI test file: `UITests/MacUISmokeTests.swift`
  - There is no iOS onboarding/tutorial UI test suite in `UITests/`
- Current behavior:
  iOS tutorial quality currently depends on manual verification for critical paths such as onboarding page 3 handoff, sandbox acknowledgement, and tutorial auth confirmation.
- Conflict with tutorial goal:
  The first-run tutorial is a primary teaching surface. A product-critical flow without automated regression coverage will keep rediscovering the same breakages.
- Rebuild spec constraints:
  The rebuild spec must identify a minimum iOS tutorial regression pack, not just individual hooks.
- Recommended direction:
  Define at least three stable iOS UI journeys as mandatory regression coverage:
  - onboarding page 3 to tutorial handoff
  - sandbox acknowledgement and return behavior
  - auth-mode confirmation inside tutorial

### P3. Existing macOS smoke coverage is useful but brittle and incomplete

- Platforms: macOS
- User symptom:
  The current macOS smoke suite validates only a narrow subset of tutorial behavior and mixes stable routes with timing- or auth-sensitive routes that are more likely to flap.
- Code evidence:
  - Current smoke suite exists only on macOS: `UITests/MacUISmokeTests.swift:4`
  - It skips onboarding by default via launch environment: `UITests/MacUISmokeTests.swift:123`, `UITests/MacUISmokeTests.swift:135`, `UITests/MacUISmokeTests.swift:143`
  - Tutorial coverage is limited to the generate-key path and a few destination opens: `UITests/MacUISmokeTests.swift:93`
- Current behavior:
  The suite provides useful app-shell sanity coverage, but it does not exercise the real onboarding path and does not cover several tutorial-specific weak points called out in this review.
- Conflict with tutorial goal:
  A macOS smoke suite should protect stable top-level flows, while more fragile flows should be isolated behind better-controlled tests. The current split is not explicit enough.
- Rebuild spec constraints:
  The rebuild spec must separate:
  - stable smoke journeys,
  - environment-controlled auth/timing journeys,
  - tutorial-specific regression journeys.
- Recommended direction:
  Keep true smoke tests narrow and dependable. Move fragile tutorial/auth flows into smaller, explicitly staged UI tests.

## Rebuild Spec Must Decide These Contracts

The future tutorial rebuild spec must explicitly decide the following contracts before implementation begins:

1. Tutorial shell safety contract
   - Which routes, views, importers, exporters, pickers, and share flows are allowed in tutorial mode?
   - Which operations need sandbox-specific replacements rather than being hidden?

2. Tutorial lifecycle contract
   - What is the difference between "task completed", "completion view unlocked", and "tutorial finished"?
   - When is global completion written?
   - What cleanup must succeed before tutorial completion is final?

3. First-run handoff contract
   - Is tutorial a branch of onboarding, or does it take over the first-run flow as its own host?
   - How does "skip tutorial" behave?
   - How does "return from tutorial to onboarding" behave, if that path still exists?

4. Tutorial guidance contract
   - Where does guidance live on compact iPhone, regular iPad, and macOS?
   - What minimum context survives inside tutorial-owned modals?
   - How is guidance restored if an auxiliary UI surface is hidden?

5. macOS host contract
   - Is tutorial always a sheet, always a root experience, or a different single model?
   - What are the precise semantics of close, done, and return actions?
   - What width budget is guaranteed for the task surface?

6. Tutorial testability contract
   - Which tutorial surfaces require `screenReady` markers?
   - Which controls require stable `accessibilityIdentifier`s?
   - Which tutorial anchor IDs are required and where are they attached?
   - Which iOS and macOS journeys are mandatory regression coverage?

## Validation Carried Forward

The current code investigation also confirmed:

- `xcodebuild test -scheme CypherAir -destination 'platform=macOS' -only-testing:CypherAirTests/TutorialSessionStoreTests` succeeds locally.
- That suite currently codifies the early-completion behavior through `test_tutorialSessionStore_finalCompletion_marksCurrentTutorialVersion`, so any lifecycle fix must update tests alongside the implementation.

