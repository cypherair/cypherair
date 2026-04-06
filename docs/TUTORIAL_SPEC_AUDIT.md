# Tutorial Spec Audit

Date: 2026-04-06

Source spec: `docs/TUTORIAL_REBUILD_SPEC.md`

Audit scope:
- This audit evaluates tutorial compliance against Spec sections 2 through 10.
- Section 1 is used as intent calibration only and is not scored independently.
- Status legend: `符合`, `部分符合`, `不符合`, `无法验证`
- Acceptance scenario legend: `已验证`, `被证伪`, `尚未验证`

Evidence sources:
- Static implementation review across tutorial host, onboarding, sandbox container, guidance chrome, real page configuration seams, and security/auth flows
- Existing unit tests, especially `Tests/ServiceTests/TutorialSessionStoreTests.swift`
- `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'`
  - Result: `354` tests passed, `0` failures

Limitations:
- No interactive manual smoke walkthrough was performed in this environment
- No iPhone, iPad, or physical-biometric runtime verification was performed
- Visual, Dynamic Type, and width-budget conclusions are therefore limited to static evidence unless noted otherwise

## Executive Summary

Overall conclusion:
- The current tutorial implementation is structurally close to the rebuild spec and already satisfies most of the core product-model, sandbox-isolation, and host-lifecycle requirements.
- The largest gaps are not in basic tutorial flow correctness. They are in automation/test coverage, helper-modal continuity, and a few places where the host still blocks or hides more UI than the spec prefers.

Highest-signal findings:
- Core lifecycle semantics are implemented correctly: unified 7-module flow, skip path, finish semantics, same-run resume, fresh replay session, and completion-version persistence only on explicit finish.
- Sandbox isolation is materially implemented through `TutorialSandboxContainer`, isolated `UserDefaults`, temporary contacts storage, mock secure enclave/keychain, and tutorial-scoped dependency injection.
- The biggest spec misses are in section 9: onboarding/helper-modal ready markers and identifiers are incomplete, tutorial UI regression journeys are not automated, and there is no dedicated tutorial UI suite.
- Helper-modal continuity is weaker than the spec requires. Tutorial modals exist, but they do not consistently preserve current module title, next action, and stable automation hooks.
- The host currently hides or blocks `Sign` and `Verify` root tabs to keep the tutorial focused. That diverges from the spec's preference to block only unsafe routes/actions rather than broadly hiding non-task pages.

## Clause Matrix

### 1. Product Model

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 2.1 | One unified tutorial product, not split core/advanced tracks | `TutorialModuleID`, `TutorialView`, `TutorialSessionStore`, single hub/workspace/completion flow | 符合 | None | None |
| 2.2 | Fixed seven-module first-run order | `TutorialModuleID.allCases`, sequential unlock logic in `TutorialSessionStore.canOpen(_:)` | 符合 | None | None |
| 2.3 | Entry points: first-run onboarding, Settings replay, completion surface | `OnboardingView`, `SettingsView.presentTutorial()`, `TutorialView.completionView` | 符合 | None | None |
| 2.4 | Replay opens the same product; completed users may enter any module directly; replay uses a fresh sandbox session | `TutorialView` hub behavior, `TutorialSessionStore.isReplayUnlocked`, `handlePrimaryHeroAction()`, `prepareForPresentation()` | 符合 | None | None |
| 2.5 | Skip path must not mark tutorial finished or create sandbox data | `OnboardingPageThree.skipTutorial()`, deferred session creation in `TutorialSessionStore.ensureSession()` | 符合 | None | None |
| 2.6 | Lifecycle semantics: `notStarted`, `inProgress`, `stepsCompleted`, `finished`; completion version only written on explicit finish; progress survives only current app run | `TutorialLifecycleState`, `markFinishedTutorial()`, `finishAndCleanupTutorial()`, `TutorialSessionStoreTests` | 符合 | None | None |
| 2.7 | Tutorial should continuously map lessons to real app use; final next step is create a real key | `TutorialModuleID.realAppLocation`, `TutorialGuidanceResolver`, completion surface next-step copy | 符合 | None | None |

### 2. Cross-Platform Host Model

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 3.1 | Host owns sandbox isolation, navigation limits, exit semantics, and guidance while keeping production pages mostly tutorial-agnostic | `TutorialView`, `TutorialSessionStore`, `TutorialShellDefinitionsBuilder`, `TutorialConfigurationFactory` | 符合 | None | None |
| 3.2 | Onboarding page 3 must be tutorial decision page with start/skip semantics and explicit sandbox messaging | `OnboardingPageThree` | 符合 | None | Add automation hooks required by section 9 |
| 3.3 | iPhone/iPad first-run tutorial launch must be one-way handoff after onboarding dismiss, then full-screen tutorial host | `IOSPresentation`, `TutorialOnboardingHandoffState`, `CypherAirApp` `sheet` plus `fullScreenCover`, handoff tests | 符合 | None | Add UI regression coverage |
| 3.4 | macOS tutorial must run in dedicated main-window workspace, not Settings sheet or onboarding-nested sheet | `MacPresentationHost` overlay for `.tutorial` | 符合 | None | Add runtime smoke coverage |
| 3.5 | `Return`, `Close`, `Finish` semantics must behave exactly as specified | `returnToOverview()`, `closeTutorial()`, `presentLeaveConfirmation`, `finishTutorial()` | 符合 | None | Add UI assertions for toolbar controls |
| 3.6 | In-progress close must show tutorial-owned leave confirmation inheriting guidance and automation contract | `TutorialLeaveConfirmationView` exists with continue/leave actions and ready marker | 部分符合 | P1 | Add helper-modal identifiers and richer continuity context |

### 3. Tutorial Safety Contract

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 4.1 | Tutorial promise must remain literally true | Promise copy in tutorial hub matches spec class of promise | 符合 | None | None |
| 4.2 | Safety must be enforced at host level, not only by swapping dependency containers | Host-level state, route blocklist, side-effect interceptor, tutorial-owned chrome, URL suppression while tutorial live | 符合 | None | None |
| 4.3 | Block only unsafe routes/actions; avoid broad allowlist behavior | `TutorialUnsafeRouteBlocklist` blocks unsafe routes, but also hides `Sign` and `Verify` root tabs because they are outside the path | 部分符合 | P1 | Replace broad non-task root blocking with narrower route/action restrictions or explicitly justify the deviation |
| 4.4 | No real file import/export, share, clipboard, photo picker, URL handoff, real workspace mutation, or real security-asset usage | Config seams disable risky import/export modes; side-effect interceptor blocks clipboard and export; tutorial uses isolated services and ignores inbound URLs during tutorial | 部分符合 | P1 | Add runtime coverage proving all disallowed side effects are intercepted on every relevant page |
| 4.5 | Preserve real auth feel while routing into isolated tutorial security plumbing; allow fallback only in simulator/UI automation when needed | `TutorialSandboxContainer` uses real `AuthenticationManager` plus mock secure enclave/keychain; `mockAuthenticator` exists but is not wired into runtime tutorial flows | 部分符合 | P1 | Define and test explicit simulator/UI automation fallback behavior for tutorial auth-sensitive steps |
| 4.6 | Replace only dangerous side effects, not whole pages or workflows | Real views reused for key generation, contact import, encrypt, decrypt, backup, auth-mode switch; backup uses tutorial artifact sink | 符合 | None | None |
| 4.7 | Sandbox guarantees apply to entire tutorial and replay always starts fresh sandbox session | Fresh tutorial container per reset/replay, ephemeral sandbox artifacts, persistent completion state only | 符合 | None | None |

### 4. Guidance Model

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 5.1 | Guidance stays close to task, explains one next action, maps to real app, survives context changes, and is recoverable | Inline header on iPhone, rail on iPad/macOS, `Show Guidance` restore on macOS | 部分符合 | P1 | Preserve task context more consistently across helper modals and auth-sensitive transitions |
| 5.2 | Tutorial has hub, workspace, and completion surfaces; hub is structured dashboard, not marketing hero | `TutorialView` host surfaces and hub layout | 符合 | None | None |
| 5.3 | First unfinished run unlocks sequentially; return to hub allowed; completed replay can enter any module | `canOpen(_:)`, hub module rows, macOS module navigator | 符合 | None | None |
| 5.4 | iPhone uses persistent inline task header on active task surfaces | `TutorialSurfaceView` plus `tutorialInlineHeaderHost` | 符合 | None | Add runtime snapshot coverage |
| 5.5 | iPad regular width uses content plus dedicated guidance rail | `TutorialShellTabsView` regular-width iOS layout | 符合 | None | Add iPad UI validation |
| 5.6 | macOS uses module navigator, content area, dedicated rail, and explicit restore affordance | `TutorialShellTabsView.macOSLayout` | 符合 | None | Add macOS UI validation |
| 5.7 | Helper modals must preserve module title, why modal exists, expected action, and what happens next | Tutorial helper modals exist, but `TutorialAuthModeConfirmationView`, `TutorialLeaveConfirmationView`, and reused `ImportConfirmView` do not consistently include all required continuity context | 部分符合 | P1 | Introduce a shared tutorial modal shell or explicit continuity metadata |
| 5.8 | Primary target anchors required; max one spotlight target; helper-modal confirm anchors required when guidance refers to them | Primary page anchors exist for many task steps; helper-modal confirm anchors/ids are incomplete | 部分符合 | P2 | Add anchors and stable identifiers for tutorial helper-modal actions and return affordances |

### 5. Experience Contract By Tutorial Segment

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 6.1 | Overview must teach unified path and visible module map with completion criteria | Hub contains promise, time, progress, primary CTA, module list | 符合 | None | None |
| 6.2 | Sandbox module must explicitly explain isolation and complete only on acknowledgement | `TutorialSandboxAcknowledgementView`, `confirmSandboxAcknowledgement()` | 符合 | None | None |
| 6.3 | Demo identity module must use real key-generation page and generate sandbox key at runtime | `KeyGenerationView` reused through `TutorialRouteDestinationView` and `TutorialConfigurationFactory.keyGenerationConfiguration` | 符合 | None | None |
| 6.4 | Demo contact module must use real contact-import flow with dangerous import surfaces disabled/intercepted | `AddContactView` reused with `.paste` only and verified import confirmation flow | 符合 | None | None |
| 6.5 | Encrypt module must use real encrypt page and intercept dangerous clipboard/export effects | `EncryptView` reused with tutorial config and side-effect interceptor | 符合 | None | None |
| 6.6 | Decrypt module must use real decrypt page and preserve auth-sensitive flow semantics | `DecryptView` reused with tutorial config and sandbox dependencies; real biometric runtime behavior not exercised here | 部分符合 | P1 | Add auth-sensitive runtime/UI coverage for tutorial decrypt path |
| 6.7 | Backup module must use real backup page and replace export sink with tutorial-local artifact | `BackupKeyView` reused with `resultSink: .tutorialArtifact` and tutorial export callback | 符合 | None | None |
| 6.8 | High Security module must use real settings/auth flow with isolated security plumbing and auth-sensitive continuity | `SettingsView` reused inside tutorial with tutorial config and isolated `AuthenticationManager`; continuity and runtime auth proof remain incomplete | 部分符合 | P1 | Add explicit tutorial auth-flow validation and modal continuity improvements |
| 6.9 | Completion surface must confirm completion, untouched real workspace, and next real step | `TutorialView.completionView` | 符合 | None | None |

### 6. Accessibility And Visual System

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 7.1 | System text styles, 44x44 targets, VoiceOver labels on tutorial-owned CTAs and helper controls, no color-only security meaning | Many views use SwiftUI text styles and labeled controls, but identifier/label coverage is incomplete and no focused accessibility audit exists | 部分符合 | P2 | Run dedicated accessibility pass and add missing labels/traits on tutorial-owned controls |
| 7.2 | Compact iPhone accessibility Dynamic Type must keep promise, primary CTA, and module map visible in first screenful | No automated or manual validation present | 无法验证 | P2 | Add manual screenshots or UI assertions at accessibility sizes |
| 7.3 | iPad regular-width guidance must remain adjacent and content width must stay usable | Layout exists statically, but no runtime validation | 无法验证 | P2 | Add iPad smoke validation |
| 7.4 | macOS default width budget must prioritize content area and open wide enough | App window default size and rail widths are defined, but no runtime proof of usable content width | 无法验证 | P2 | Add macOS layout validation |
| 7.5 | Liquid Glass should style control chrome only, not readability-first security content | Tutorial chrome uses material on cards, banners, and rails, but no visual audit was performed | 部分符合 | P2 | Perform manual visual review on all platforms |

### 7. Technical Architecture Expectations

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 8.1 | Tutorial should be host-driven, sandboxed, and reuse real pages and real service flows | Overall host and view reuse architecture | 符合 | None | None |
| 8.2 | Contract-level interfaces for host, container, blocklist, interceptor, surface config, guidance model, security simulation, automation | Most responsibilities exist, but automation coverage is incomplete and guidance responsibilities are split across resolver, payload, and chrome rather than a single explicit contract object | 部分符合 | P2 | Strengthen guidance/automation boundary documentation or types |
| 8.3 | Low-intrusion architecture, avoid pervasive tutorial-only branches in production pages | Mostly achieved through config/env seams, but some page-level tutorial checks remain and broad root-tab blocking still leaks product policy into host chrome | 部分符合 | P1 | Continue moving from page-specific checks to shared host-level policy where practical |
| 8.4 | State model must include spec version, launch origin, active module, lifecycle, session id, per-module progress, current guidance | `TutorialSessionState` includes all required fields | 符合 | None | None |
| 8.5 | Only completion history persists across app restarts; sandbox artifacts and unfinished progress stay ephemeral | `AppConfiguration.guidedTutorialCompletedVersion`, ephemeral tutorial container/session state | 符合 | None | None |
| 8.6 | Hub/completion/leave confirmation/guidance are tutorial-owned; guided tasks should remain real production pages | Host-owned surfaces exist and most task views are real production pages; broad blocking of `Sign`/`Verify` weakens the "block only unsafe" preference | 部分符合 | P1 | Narrow the host restrictions to unsafe surfaces rather than non-task surfaces |
| 8.7 | Dangerous side effects should be intercepted at host/shared infrastructure level whenever possible | Clipboard/export interception is centralized through environment seam, but some behavior is still disabled directly in page code | 部分符合 | P2 | Consolidate more restrictions into shared policy/interceptor seams |
| 8.8 | Tutorial helper modals belong to tutorial host; system biometric prompts remain system-owned | Tutorial modals are presented by `TutorialView`; biometric prompts are still produced by `AuthenticationManager` | 符合 | None | None |

### 8. Testability And Automation Contract

| Spec | Requirement | Evidence | Status | Risk | Next |
|---|---|---|---|---|---|
| 9.1 | Stable ready markers required for onboarding pages, hub, sandbox acknowledgement, each module root, helper modals, completion, leave confirmation | Hub, sandbox acknowledgement, module roots, completion, and leave confirmation have markers; onboarding pages and tutorial helper modals such as import/auth confirmation do not | 部分符合 | P1 | Add ready markers for onboarding decision page and tutorial-owned helper modals |
| 9.2 | Stable identifiers required for onboarding CTAs, hub controls, module launch controls, return/close/finish controls, helper-modal confirm/cancel actions | Hub primary CTA and module launch ids exist; onboarding CTAs, finish/close/return controls, and helper-modal action ids are incomplete | 部分符合 | P1 | Add stable identifiers for all tutorial-critical controls |
| 9.3 | Stable anchors required for current primary target, helper-modal confirm actions, and persistent return/restore guidance affordances | Main task anchors exist for page targets; helper-modal confirm anchors and return/restore anchors are incomplete | 部分符合 | P2 | Expand anchor coverage to modal and chrome controls |
| 9.4 | Mandatory regression journeys for iOS/iPadOS/macOS must exist | Only unit-level state and flow tests are present; no tutorial UI regression suite exists in `Tests` | 不符合 | P1 | Add UI regression coverage for mandatory journeys |
| 9.5 | Tutorial smoke and deeper suites should be separated, especially for auth-sensitive flows and leave confirmation | No dedicated tutorial UI smoke or deeper suite exists | 不符合 | P1 | Create tutorial-focused smoke and auth-sensitive UI suites |

## Acceptance Scenario Mapping

| # | Acceptance scenario | Evidence | Mapping | Notes |
|---|---|---|---|---|
| 1 | First-run iPhone user reaches onboarding page 3, chooses tutorial, onboarding disappears, tutorial host appears | Static handoff implementation plus `TutorialOnboardingHandoffState` tests | 已验证 | Verified statically and by handoff unit tests, not by interactive UI run |
| 2 | First-run user chooses skip and enters real app without tutorial completion being recorded | `OnboardingPageThree.skipTutorial()`, deferred tutorial session creation | 已验证 | Static verification only |
| 3 | First-run user leaves tutorial after one-way handoff and lands in main app, not onboarding | One-way handoff plus tutorial dismiss behavior | 已验证 | Static verification only |
| 4 | User generates sandbox key through real key-generation flow without touching real key data | Tutorial key-generation config plus sandbox container tests | 已验证 | Static plus unit evidence |
| 5 | User imports sandbox contact through real contact flow without touching real contact storage | Real `AddContactView` plus tutorial sandbox container and full-flow test | 已验证 | Static plus unit evidence |
| 6 | User encrypts and decrypts sandbox message through real service path without touching real workspace data | Real `EncryptView` and `DecryptView` plus full-flow tutorial store test | 已验证 | Static plus unit evidence |
| 7 | User completes backup through real backup flow without real exporter writing outside sandbox | `BackupKeyView` tutorial artifact sink and interceptor wiring | 已验证 | Static verification only |
| 8 | User reaches High Security through real settings flow while private-key security path stays isolated | Real `SettingsView` in tutorial plus isolated auth manager and mocks | 已验证 | Static verification only; runtime auth behavior still unverified |
| 9 | User sees real system biometric interaction where supported while tutorial still isolates real assets | Auth manager is real and security backing is mocked, but no physical-device proof exists | 尚未验证 | Needs physical-device validation |
| 10 | User who leaves tutorial during current app run can return and continue in-memory progress | `returnToOverview` and `prepareForPresentation_afterReopen` tests | 已验证 | Unit-tested |
| 11 | User who kills app and later reopens tutorial starts from beginning unless already finished | Session state is in-memory only; finished replay reset is tested | 已验证 | Mostly static plus partial unit evidence |
| 12 | Finished user can reopen tutorial from Settings and directly enter any module | Replay unlock logic and tests | 已验证 | Unit-tested |
| 13 | iPad regular-width user sees guidance adjacent to the guided task surface | Static regular-width layout exists | 尚未验证 | No iPad runtime proof |
| 14 | macOS user sees dedicated tutorial workspace and can restore collapsed guidance | Static `MacPresentationHost` and macOS layout implementation | 尚未验证 | No interactive macOS walkthrough |
| 15 | No tutorial flow performs real import/export/share/clipboard/photo/URL/workspace mutation | Strong static evidence exists, but no end-to-end runtime audit exists for every surface | 尚未验证 | Needs UI/runtime interception validation |

## Risk-Ranked Findings

### P1

- Broad root-tab blocking diverges from the spec's "block only unsafe routes/actions" posture. `Sign` and `Verify` are hidden because they are outside the learning path, not because they are intrinsically unsafe.
- Tutorial helper modals do not fully satisfy the continuity contract. The user is not always shown current module identity, why the modal exists, the exact expected action, and what happens next.
- Authentication-sensitive tutorial behavior is only partially proven. The isolated security plumbing is present, but real-device biometric behavior and explicit tutorial fallback semantics for simulator/UI automation are not validated end to end.
- Tutorial automation/test contract is incomplete. Ready markers and stable identifiers are missing for onboarding CTAs, helper modals, and some return/finish/close actions.
- Mandatory regression journeys in section 9.4 are not implemented as UI tests.

### P2

- Anchor coverage is incomplete for helper-modal confirm actions and persistent restore/return affordances.
- Accessibility and visual-system requirements are only partially evidenced; Dynamic Type, iPad/macOS width budgets, and VoiceOver-specific tutorial coverage remain unverified.
- Guidance responsibilities are centralized enough to work, but the contract is still spread across resolver, payload, and chrome instead of a more explicit overlay model boundary.
- Some tutorial restrictions are still enforced directly in production page code via tutorial-specific environment checks rather than through a more centralized host/interceptor layer.

## Verification Gaps

Missing automated coverage:
- Onboarding page ready markers and CTA identifiers
- Helper-modal ready markers for tutorial-owned import/auth confirmation flows
- Stable identifiers for tutorial return, close, and finish controls
- Dedicated tutorial UI smoke suite
- Dedicated auth-sensitive and leave-confirmation UI suite
- Platform-specific iPad regular-width and macOS workspace layout assertions

Missing runtime/manual validation:
- iPhone compact Dynamic Type accessibility layout
- iPad regular-width guidance rail behavior
- macOS dedicated tutorial workspace width budget
- Physical-device LocalAuthentication behavior in decrypt and High Security modules
- End-to-end proof that every disallowed side effect is intercepted on every reachable tutorial page

Recommended next validation pass:
- Add a tutorial UI smoke target that covers onboarding decision page, first-run handoff, skip path, hub launch, sequential module progression, completion, and same-run resume
- Add deeper auth-sensitive UI flows for decrypt and High Security
- Add a small platform matrix for iPhone compact, iPad regular width, and macOS regular window width
- Add explicit helper-modal automation hooks before expanding the UI suite
