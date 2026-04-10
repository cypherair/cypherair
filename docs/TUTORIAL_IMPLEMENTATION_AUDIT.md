# Tutorial Implementation Audit

Date: 2026-04-10

Source spec: `docs/TUTORIAL_REBUILD_SPEC.md`

Supersedes:
- `docs/TUTORIAL_SPEC_AUDIT.md` (2026-04-06 snapshot)

Audit posture:
- This document verifies the current tutorial implementation against the active rebuild spec.
- It distinguishes confirmed implementation issues from validation gaps.
- It replaces the older audit because several of that document's conclusions are no longer current.

Evidence sources:
- Static review of tutorial host, onboarding, sandbox container, route blocklist, guidance chrome, helper modals, and auth-sensitive wiring
- Existing unit tests, especially `Tests/ServiceTests/TutorialSessionStoreTests.swift`
- Current repository test inventory under `Tests/`

Limitations:
- No new `xcodebuild test` run was executed for this refresh
- No interactive iPhone, iPad, macOS, or physical-biometric walkthrough was performed in this pass
- Accessibility, layout, and real biometric conclusions remain limited to static evidence unless otherwise noted

## Executive Summary

Overall conclusion:
- The guided tutorial is still broadly aligned with the rebuild spec's core product direction.
- The implementation remains host-driven, sandbox-isolated, and built around reusing real production pages through configuration seams rather than forking a separate tutorial UI stack.
- The previous audit is stale in at least two material ways: `Sign` and `Verify` root tabs are no longer hidden, and the output-page tutorial coupling called out there has since been explicitly removed and regression-tested.

Highest-signal current issues:
- The automation contract is still incomplete for onboarding CTAs, tutorial close/finish/return controls, and tutorial-owned auth/leave modal actions.
- Guidance continuity still drops when tutorial helper modals appear. The host intentionally suppresses guidance while a modal is active, but the modal surfaces do not fully replace that context.
- There is still no dedicated tutorial UI smoke or regression suite. Current coverage is strong at the session-store and configuration level, but weak at end-to-end UI level.
- Auth-sensitive tutorial paths are only partially validated. The sandbox keeps real `AuthenticationManager` behavior over isolated storage, but tutorial-specific simulator/UI-automation fallback expectations are not documented or covered as a tutorial contract.

## Verified Current-State Alignment

These areas remain aligned with the rebuild spec and should not be treated as stale design:

- One unified tutorial product with a fixed seven-module flow remains implemented through `TutorialModuleID`, `TutorialView`, and `TutorialSessionStore`.
- First-run onboarding and in-app replay entry points remain present in `Sources/App/Onboarding/OnboardingView.swift` and `Sources/App/Settings/SettingsView.swift`.
- Finish semantics still require explicit completion handling through `markFinishedTutorial()` and `finishAndCleanupTutorial()` in `Sources/App/Onboarding/TutorialSessionStore.swift`.
- Sandbox isolation remains real: `TutorialSandboxContainer` creates isolated `UserDefaults`, a temporary contacts directory, a tutorial-scoped `AppConfiguration`, mock Secure Enclave and Keychain primitives, and tutorial-local services.
- Tutorial hosting still reuses real production pages through `TutorialConfigurationFactory`, `TutorialRouteDestinationView`, and `TutorialShellDefinitionsBuilder`.
- The tutorial no longer broad-blocks root tabs. `TutorialUnsafeRouteBlocklist.blockedRoot(for:)` returns `nil`, and `TutorialShellDefinitionsBuilder` builds all `AppShellTab` roots.

## Confirmed Remaining Issues

| Area | Status | Evidence | Why it still matters |
|---|---|---|---|
| Automation hooks | Confirmed issue | `Sources/App/Onboarding/OnboardingView.swift` has no stable ready marker or CTA identifiers for the tutorial decision page. `Sources/App/Onboarding/TutorialView.swift` exposes module launch identifiers and the primary CTA, but the hub close button, completion close button, finish button, and return controls still lack stable identifiers. `Sources/App/Onboarding/TutorialAuthModeConfirmationView.swift` has no ready marker, action identifiers, or tutorial anchors for auth confirmation. | The rebuild spec still expects stable automation coverage for first-run launch, return, close, finish, and helper-modal actions. |
| Helper-modal continuity | Confirmed issue | `Sources/App/Onboarding/Tutorial/TutorialGuidanceResolver.swift` returns `nil` whenever `navigation.activeModal != nil`. `Sources/App/Onboarding/Tutorial/TutorialShellTabsView.swift` and `Sources/App/Onboarding/Tutorial/TutorialSurfaceView.swift` both hide tutorial guidance while a modal is active. `Sources/App/Onboarding/TutorialAuthModeConfirmationView.swift` and `Sources/App/Contacts/ImportConfirmView.swift` do not restate module identity, expected next action, or what happens after confirm/cancel. | The user loses task context exactly when the tutorial interrupts the main flow, which is the moment the spec most wanted the host to preserve continuity. |
| Tutorial UI regression coverage | Confirmed issue | The `Tests/` tree contains service, device-security, and FFI suites, but no dedicated tutorial UI smoke or regression suite. Current tutorial coverage lives primarily in `Tests/ServiceTests/TutorialSessionStoreTests.swift`. | The main tutorial lifecycle is reasonably unit-tested, but first-run handoff, modal continuity, compact-width navigation, and completion behavior are not protected by end-to-end UI tests. |
| Auth-sensitive tutorial validation | Confirmed validation gap | `Sources/App/Onboarding/TutorialSandboxContainer.swift` wires tutorial services through a real `AuthenticationManager`, not through `mockAuthenticator`, which is good for realism. But the only explicit bypass path found in this pass is the generic UI-test bypass in `Sources/App/AppContainer.swift`, and there is no tutorial-specific smoke coverage for decrypt/auth-mode flows. | This is not evidence that the auth flow is wrong. It is evidence that the tutorial-specific fallback and runtime validation story is still incomplete. |
| Platform and accessibility verification | Confirmed validation gap | No current tutorial-specific UI suite exercises compact accessibility Dynamic Type, iPad regular-width rail behavior, or macOS tutorial workspace sizing in this pass. | These may already be acceptable in practice, but there is still no current proof in repo automation. |

## Findings From The Previous Audit That Are No Longer Current

These older conclusions should not be carried forward:

- `Sign` and `Verify` root tabs are no longer hidden in the tutorial shell.
  Evidence:
  `Sources/App/Onboarding/Tutorial/TutorialModels.swift` keeps `blockedRoot(for:)` returning `nil`.
  `Sources/App/Onboarding/Tutorial/TutorialShellDefinitionsBuilder.swift` builds roots for `.sign` and `.verify`.
  `Tests/ServiceTests/TutorialSessionStoreTests.swift` asserts that regular-width iOS tutorial definitions match `AppShellTab.allCases`.

- The production output pages no longer appear to own tutorial-specific output interception logic directly.
  Evidence:
  `Tests/ServiceTests/TutorialSessionStoreTests.swift` explicitly checks that `EncryptView`, `DecryptView`, `SignView`, `KeyDetailView`, and `BackupKeyView` do not reference `tutorialSideEffectInterceptor`, and that `BackupKeyView` does not expose `tutorialArtifact`.

- Helper-modal automation coverage has improved in one narrow area.
  Evidence:
  `Sources/App/Contacts/ImportConfirmView.swift` now has root and action identifiers (`importconfirm.root`, `importconfirm.verified`, `importconfirm.unverified`), so the old audit's broad helper-modal statement now needs to be narrowed to tutorial-owned modal surfaces and missing ready/anchor coverage.

## Recommended Next Steps

1. Add stable identifiers and ready markers for onboarding start/skip, tutorial close/finish/return controls, and tutorial auth/leave modal actions.
2. Introduce a small tutorial modal shell or metadata layer so auth/import/leave modals preserve module title and next-step context when guidance is suppressed.
3. Add a dedicated tutorial UI smoke suite covering first-run handoff, skip path, sequential completion, return-to-hub, and completion exit.
4. Add one auth-sensitive tutorial UI path for decrypt or High Security mode, and document how simulator/UI automation is expected to bypass or simulate authentication.
