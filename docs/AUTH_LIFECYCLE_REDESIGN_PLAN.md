# Authentication / Privacy / Lifecycle Redesign — Technical Plan & Validation

> Status: Draft proposal / active roadmap. This document describes proposed future work and
> does **not** describe current shipped behavior. Shipped behavior remains as documented in
> [SECURITY.md](SECURITY.md) and [PRD.md](PRD.md) until these phases land.
> Date: 2026-06-05.
> Purpose: Detailed technical planning, the pre-implementation validation (PoC) checklist,
> phasing, current→target component map, test strategy, and risks for the redesign.
> Audience: Swift implementers, security reviewers, architecture reviewers, test owners, AI coding tools.
> Companion: [Design](AUTH_LIFECYCLE_REDESIGN_DESIGN.md) (architecture & UX; principles; verified APIs).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [TESTING.md](TESTING.md), [CODE_REVIEW.md](CODE_REVIEW.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: PoC results, any phase completion, a changed phase boundary, a changed
> red-line surface, or a changed validation minimum.

## 1. P0 — pre-implementation validation (macOS PoC)

A small, throwaway macOS spike to de-risk the in-app authentication direction **before** the
rewrite. It must run on a real Mac with Touch ID. Acceptance items:

1. **No resign.** An inline `LAAuthenticationView` driving `evaluateAccessControl` /
   `evaluatePolicy` does **not** post `NSApplication.didResignActiveNotification` (and
   `NSApplication.shared.isActive` stays `true`) for the full prompt lifecycle. (If this fails,
   the macOS "Immediately" model must be revisited.)
2. **Per-operation context consumption — software path.** A context authenticated via
   `evaluateAccessControl(accessControl, operation:, …)` satisfies
   `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:, authenticationContext: ctx)`
   with **no second prompt**, for the app's exact wrapping access-control flags
   (`.biometryAny` and, in Standard mode, `.or .devicePasscode`) and the correct
   `LAAccessControlOperation`. Confirm the reconstruct + unwrap then succeed.
3. **Per-operation context consumption — custody path.** The same context drives a custody
   `SecKey` operation (`SecKeyCreateSignature` / `SecKeyCopyKeyExchangeResult`) loaded with
   `kSecUseAuthenticationContext: ctx`, no second prompt.
4. **No cross-operation reuse.** With reuse-duration `0`, a *second* operation requires a *new*
   authentication (confirm the prior context does not silently authorize it).
5. **In-app password fallback — feasibility decision.** Determine whether a safe in-app password /
   login-password path exists through public APIs (credential verification without weakening the
   model or logging secrets). **Decision rule (pre-approved):** if it is not safely achievable,
   drop the Standard-mode password fallback on macOS for this flow and require biometrics on macOS
   (and update SECURITY.md §4). Either outcome unblocks P4/P5.
6. **Mode-switch / rewrap under the presenter.** Validate the `AuthenticationManager` re-wrap flow's
   per-key authentication when presented in-app on macOS: one in-window prompt per required
   authentication, no resign, and the SECURITY.md §4 atomicity / crash-recovery semantics preserved.
7. **visionOS — deferred (no hardware).** visionOS follows the iOS direction by decision; on-device
   Optic-ID + `ScenePhase` confirmation is deferred until hardware is available and tracked as an
   unvalidated assumption, not a design fork.

PoC findings are recorded back into this document and the design before P1 begins.

## 2. Phasing (each phase is its own PR)

- **P0 — Validation PoC** (above). No production code.
- **P1 — macOS single window.** Remove the standalone `Settings { }` scene; route macOS settings
  into the main window. Independent of the auth rework; ships first to simplify the surface. (§3.4)
- **P2 — `AppLockController` + stop reacting to `.active`.** Introduce the explicit lock state
  machine and the per-platform away-event rule; decouple operation prompts from lock; keep the
  current lock UI temporarily (derived from the new state); extend tracing to the new states.
  This is the core behavioral fix.
- **P3 — Decoupled cosmetic cover.** Extract the cover into its own modifier keyed only to scene
  activity; remove the cosmetic responsibility from the lock overlay. Cover trigger is **decided:
  `.inactive`** for now (a later move to `.background`-only on iOS is an optional refinement).
- **P4 — macOS in-app auth surfaces.** Embedded unlock screen + in-app password fallback;
  explanatory pages for App Access change & mode switch; introduce `AuthenticationPresenting`.
- **P5 — macOS in-app per-operation auth.** Route per-op auth through the presenter using
  `evaluateAccessControl` + `authenticationContext` / `kSecUseAuthenticationContext`.
- **P6 — iOS / iPadOS / visionOS custom lock screen + auto-invoke.**
- **P7 — Delete dead machinery.** Remove `PrivacyScreenLifecycleGate`, the union-snapshot
  plumbing, and the `AuthenticationShield*` dismissal machinery once unused; keep a lock-state
  trace; complete on-device custody verification.

Order and grouping are negotiable; phases may merge or split. P2 must keep the current
grace=0 protection working until P3–P7 supersede it (no interim regression window).

## 3. Current → target component map

### 3.1 Lock / lifecycle
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift` (red line) — its resume / grace /
  blur / settle responsibilities move into the new `AppLockController`; the orchestrator either
  becomes that controller or a thin adapter. Its `handleResumeForLifecycle` `.active`-driven
  re-evaluation is replaced by away-event-driven transitions.
- `Sources/App/Common/PrivacyScreenModifier.swift` — splits into (a) a dumb cosmetic-cover
  modifier and (b) thin lifecycle wiring that feeds away events to `AppLockController`. The
  iOS `.onChange(of: scenePhase)` and macOS `NSApplication` observers stay but stop consulting a gate.
- `Sources/App/Common/PrivacyScreenLifecycleGate.swift` — **deleted** in P7 (its sole job, the
  `.active` disambiguation, no longer exists).
- `Sources/Security/AuthenticationPromptCoordinator.swift` — the union-snapshot plumbing added
  for the grace=0 fix is removed in P7; any remaining operation-progress signal is presentational only.
- `Sources/App/Common/AuthenticationShield*` (`AuthenticationShieldCoordinator`,
  `AuthenticationShieldHost`, `AuthenticationShieldOverlayView`) — superseded by the in-app
  auth surfaces (macOS) and the lock screen; removed/slimmed in P7.

### 3.2 macOS in-app authentication (new)
- New `AuthenticationPresenting` protocol + a macOS implementation hosting `LAAuthenticationView`
  (or `LARight.authorize(in:)`), plus iOS/visionOS pass-through.
- New in-app lock screen views (macOS embedded; iOS/visionOS custom) and explanatory-page views
  for App Access change & mode switch.
- `Sources/Security/AuthenticationManager.swift` (red line) — `evaluateAppSession` and the
  mode-switch flow adopt the presenter on macOS; `LAPolicy` selection unchanged.

### 3.3 Private-key operation auth (new wiring)
- `Sources/Services/KeyManagement/PrivateKeyAccessService.swift` and the custody bridges
  (`PGPExternalP256SigningProviderBridge`, `PGPExternalP256KeyAgreementProviderBridge`) accept a
  pre-authenticated `LAContext` from the presenter; software path passes it to the CryptoKit SE
  key init (`authenticationContext:`), custody path via `kSecUseAuthenticationContext`.
- `Sources/Security/SecureEnclaveManager.swift` (red line) — `reconstructKey` gains an
  optional authenticated `LAContext`.

### 3.4 macOS single-window
- `Sources/App/CypherAirApp.swift` — remove the `Settings { }` scene (≈ lines 342–377) and its
  second `authenticationShieldHost(handlesLifecycleEvents:false)`; preserve Cmd-, via
  `CommandGroup(replacing: .appSettings)` that routes to the in-main-window settings.
- `Sources/App/Settings/MacSettingsRootView.swift`, `Sources/App/Settings/ProtectedSettingsHost.swift`
  — drop `MacPresentationHostMode.settingsScene` / `.settingsSceneProxy` and the
  `openMainWindowAction` proxy; always `.mainWindow` / `.mainWindowLive` (reuse
  `MainWindowSettingsRootView`).
- Remove/repurpose the `UITEST_ROOT="settings"` launch path.

## 4. Test strategy

- **`AppLockController` unit tests** — the lock machine is pure and fully unit-testable (no
  lifecycle timing): genuine away → lock; biometric `.inactive`/`.active` → no lock; within /
  over interval; macOS screen-lock / explicit; "Immediately" semantics per platform. This
  replaces the fragile gate-timing tests and the on-device-trace dependence.
- **Cosmetic cover tests** — cover shown iff not active; no auth side effects.
- **macOS UI tests** — update the six `launchSettings()` tests in `UITests/MacUISmokeTests.swift`
  to `launchMain() + openSettingsTab()`; add in-app-unlock and explanatory-page coverage.
- **Device biometric tests** (`CypherAir-DeviceTests`) — in-app unlock; per-operation inline
  auth (single prompt, no resign, content preserved); custody route verification.
- **Auth-trace assertions** — lock-state transitions and away/lock triggers, captured via
  `CYPHERAIR_DEBUG_AUTH_TRACE` during P2–P6.
- **visionOS** — build probe (no test plan); manual Optic-ID validation.
- Per [TESTING.md](TESTING.md): `cargo +stable test` (no Rust change expected), the
  `CypherAir-UnitTests` and `CypherAir-MacUITests` plans, and the visionOS build probe each phase.

## 5. Risks & red lines

- **Red-line review.** `AppSessionOrchestrator`, `Sources/Security/ProtectedData/*`,
  `AuthenticationManager`, `SecureEnclaveManager`, and entitlements require human security review
  per [SECURITY.md](SECURITY.md) §10. Each touching phase carries positive + negative + round-trip tests.
- **No interim regression.** The merged grace=0 fix must keep working until superseded; P2 lands
  the new model behind the same observable behavior before P7 removes the old machinery.
- **macOS PoC dependency.** P4/P5 depend on the P0 "no-resign" and "per-op context consumption"
  results. If "no-resign" fails, revisit the macOS away-event model before building P4/P5.
- **macOS Standard-mode fallback (decided, conditional).** Preferred is a safe in-app password
  field; if P0 shows that is not achievable through public APIs, the **pre-approved** outcome is to
  remove the Standard-mode password fallback on macOS for this flow (biometrics required on macOS)
  and update SECURITY.md §4. iOS / iPadOS / visionOS keep the system passcode fallback. Any in-app
  password field must validate credentials safely (no secret logging; correct failure mapping).
- **Security posture unchanged.** One biometric per operation; the unlock context is never reused
  for operations; reuse-duration `0`; relock fail-closed; Phase 1/2 boundary intact.

## 6. SE-custody prompt — tracking

Verified (grep, 2026-06-05): operation/custody services have **no** direct references to
`AppSessionOrchestrator` / `requestContentClear` / relock / blur. The only coupling to lock is
`withOperationPrompt` → the coordinator snapshot, read **only** by `PrivacyScreenModifier`
(feeding the gate) and the orchestrator resume guards — i.e. the `.active`-evaluation path.

Consequences for tracking (do not drop):
- Once lock stops reacting to `.active` (P2), no path remains for a custody/operation biometric
  to trigger lock / content-clear / re-prompt — the original custody duplicate-auth gap is closed
  for the lock concern.
- **Transitional ordering:** this holds only after P2; custody stays production-blocked
  (`PGPKeyCapabilityResolver.production`) throughout, so there is no user-facing exposure, but
  the ordering is tracked.
- **On-device verification** (P7): custody signing/key-agreement under the new model performs a
  single in-app prompt with no content clear / relock.
- The already-shipped off-main custody hop stays (responsiveness; independent of this work).

## 7. Decisions & remaining validation items

Folding in the reviewer's direction (2026-06-05).

**Decided (folded into the design):**
1. **macOS embedded mechanism.** `LAAuthenticationView` + `LAContext` (`evaluateAccessControl` /
   `evaluatePolicy`) is the primary direction and the one to validate first — it stays on the
   `LAContext` path used today and only changes the macOS presentation. `LARight.authorize(in:)` is
   a secondary fallback, used only if the primary cannot meet a need.
2. **macOS auto-lock interval.** Reuse the existing grace setting as the unified auto-lock interval
   for now. A separate macOS-specific setting is an optional future study, out of scope here.
3. **iOS cover trigger.** `.inactive` for now (snapshot-safe; accepts a brief cosmetic flash behind
   a biometric sheet). A later move to `.background`-only is an optional refinement.
4. **visionOS.** Follow the iOS direction. On-device validation is deferred (no visionOS hardware);
   iOS-equivalent behavior is tracked as an unvalidated assumption, not a design fork.
5. **Password fallback (conditional, pre-approved).** Prefer a safe in-app password field; if P0
   shows it is not achievable through public APIs, remove the Standard-mode password fallback on
   macOS for this flow (biometrics required on macOS) and update SECURITY.md §4.

**Remaining validation items (P0 / technical validation):**
1. **In-app password-field feasibility** — whether a safe public-API credential path exists; drives
   decision (5) above. (P0 item 5)
2. **Mode-switch / rewrap under the presenter** — the `AuthenticationManager` re-wrap flow's per-key
   in-app authentication on macOS, with atomicity + crash recovery preserved. (P0 item 6)
3. **visionOS on-device behavior** — Optic-ID + `ScenePhase`, confirmed when hardware is available.
   (P0 item 7)

---

*This is a proposal / roadmap. Phases change shipped behavior only when implemented, tested, and
reviewed; update [SECURITY.md](SECURITY.md) and [PRD.md](PRD.md) as each phase lands.*
