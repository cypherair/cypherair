# Authentication / Privacy / Lifecycle Redesign — Migration Roadmap

> Status: **Complete — record of the migration** (P5 doc cutover, 2026-06-11). All phases are on
> `main`: P0 (validation PoC; frozen #469; in-window results invalidated on macOS 27 — §1 addendum),
> P1 (lock foundation + obsolete-cluster removal; PR #472), P2 (macOS single-window unification;
> PR #475), P3′ (stages 0–2′ + the uniform operation-prompt-session enrollment; stage 0 PR #493,
> stage 1 PR #494, stage 2 PR #495 **withdrawn** after the maintainer's manual gate and redone as
> stage 2′ — §3), P4 (the opaque app-identified lock surface, all platforms), and P5 (this cutover).
> The original P3 (macOS in-window authentication cutover) was **retired** — PR #491 closed unmerged
> after macOS 27 was found to deny embedded LocalAuthentication UI to non-Apple-signed processes, and
> the stall problem that motivated it no longer reproduces on macOS 27. Its replacement **P3′**
> (§3) completed the explicit lock-state architecture on the system authentication sheet.
> [SECURITY.md](SECURITY.md) §4–§5 and [PRD.md](PRD.md) §4.9 state the shipped model.
> Date: 2026-06-11 (re-scoped 2026-06-10; originally 2026-06-07).
> Purpose: The migration from the pre-P1 entangled privacy/lock/shield machinery to the target in
> [Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md): phasing, the P0 results and their
> macOS 27 addendum, the current→target component map, tests, and decisions.
> Audience: Swift implementers, security reviewers, architecture reviewers, test owners, AI coding tools.
> Companion: [Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md) (the end state; the two-subsystem boundary).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [TESTING.md](TESTING.md), [CODE_REVIEW.md](CODE_REVIEW.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: a phase completion, a changed phase boundary, a changed red-line surface, a changed
> validation minimum, or a change in the macOS embedded-UI availability (§1 addendum).

Source anchoring: this roadmap names shipped types and functions by **symbol**, not line number (line numbers
drift). All claims are grounded in a first-hand read of the shipped `main` sources.

## 1. P0 validation results (inlined) — with the macOS 27 addendum

A throwaway macOS validation spike (P0) on a real Mac with Touch ID de-risked the in-window direction before
the rewrite (frozen PoC branch `poc/auth-lifecycle-macos`, PR #469; none of its code merges to `main`).
Validated results, as measured on **macOS 26.x (2026-06-06)**:

- **No resign.** An inline `LAAuthenticationView` driving `evaluatePolicy` / `evaluateAccessControl` does not
  post `NSApplication.didResignActiveNotification` for the full prompt lifecycle.
- **Per-operation context consumption (software path).** A context authenticated via
  `evaluateAccessControl(accessControl, operation: .useKeyKeyExchange)` satisfies
  `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:authenticationContext:)` reconstruction
  with no second prompt. The biometric-gated SE operation is the wrapping key's self-ECDH
  (`.useKeyKeyExchange`) for both signing and decryption.
- **Custody context compatibility (narrow).** The same approach drives a custody `SecKey` sign / ECDH loaded
  with `kSecUseAuthenticationContext`, one prompt each — a technical-compatibility result only.
- **Single-prompt mode-switch / re-wrap.** The re-wrap flow authenticates **once** for the whole action
  (one prompt for an N-key re-wrap) by threading `lastEvaluatedContext` into every per-key SE operation,
  with atomicity / crash-recovery semantics preserved.
- **No in-window password field.** The embedded `LAAuthenticationView` exposes biometric / companion
  policies only.
- **Unlock-vs-key-use is a code-routing requirement**, guaranteed by structure and review, not a runtime
  experiment.

### Addendum (2026-06-10): macOS 27 invalidates the in-window mechanism; the stall motivation is resolved

Measured on this project's development Mac after its upgrade to **macOS 27.0 Golden Gate developer beta
(26A5353q)**, with a probe suite retained by the maintainer for re-testing on new macOS builds
(kept untracked as `Tests/ServiceTests/InWindowAuthProbeTests.swift`):

- **Embedded LocalAuthentication UI is denied to non-Apple-signed processes.** Every combination —
  AppKit `LAAuthenticationView` and SwiftUI `LocalAuthenticationView`, paired with `evaluatePolicy` and
  with `evaluateAccessControl`, view detached / attached / visible — fails immediately with
  `LAError` **-1007**, `NSDebugDescription: "Caller is not Apple signed."`. An entitlement A/B
  (`enhanced-security-version-string` 2→1) showed the denial is **independent of the app's
  hardened-process entitlements**: the gate is the OS. Neither SDK (26.5 or 27.0) documents the
  restriction; the documented no-view fallback is the standard alert, not a denial.
- **The system-sheet routes are fully functional** on macOS 27, including
  `evaluateAccessControl(.useKeyKeyExchange)` pre-authentication — so per-operation context threading
  (the P0 result above) remains available via the system sheet.
- **The original stall no longer reproduces.** The prolonged post-authentication unresponsiveness that
  motivated the in-window direction (pre-P1, the app could stay stuck for seconds-to-minutes after the
  detached sheet) is not observed under the P1 lock model on macOS 27 (field observation 2026-06-10; one
  ~2 s settle seen once). Two contributors changed together: P1 deleted the app-side shield/settle
  machinery, and macOS 27 reworked the system authentication window. Formal trace-based validation is
  the stage-3 trace checklist; the macOS 26.5 validation pass was **dropped by the release decision**
  (§3 stage 3, §7): the release ships against macOS 27 only.

**Consequence:** the in-window cutover is retired; presentation stays with the system sheet. The redesign's
remaining work is the explicit lock-state architecture (P3′), not the prompt.

## 2. Migration principle

**Authentication presentation belongs to the system; the lock lifecycle belongs to an explicit state
machine.** The app never infers lock state from lifecycle noise around authentication. Concretely:

- The system authentication sheet presents all authentication, for both subsystems, on every platform.
  Both app-session policies and both private-key modes remain user-selectable everywhere — **no pinning,
  no migrations, no access-control changes** (TARGET §1).
- App-driven authentication windows are **explicit state**: `AppLockController.lockState ==
  .authenticating` for app-session unlock, and the `AuthenticationPromptCoordinator` operation-prompt
  session for every other auth-sheet-capable user action — **the uniform enrollment rule** (TARGET §3):
  each such action (private-key operations, key provisioning, key-expiry modification, the mode-switch
  re-wrap, the App Access Protection policy change, Local Data Reset) is wrapped in one session for its
  full duration, and privacy prompts deliberately do not count toward the lock controller's mirror. The
  macOS away-event rule is filtered through that state (the `.authenticating` rule, TARGET §3) instead
  of heuristics.
- **Single prompt per user action** (TARGET §4): flows that would prompt twice in one action thread one
  authenticated subsystem-B `LAContext` into both SE operations (the shipped
  `PrivateKeyRewrapWorkflow` pattern). Explicit pre-authentication is not generalized beyond that.
- **Out of scope (passphrase text entry, not authentication surfaces):** import-S2K passphrase entry and
  standalone password-message / SKESK encrypt + decrypt are SwiftUI `SecureField` text entry, not
  private-key biometric surfaces. Password-message encryption that **also signs** routes through the same
  private-key seam as every other signing operation.

## 3. Phases (PR-sized steps)

- **P0 — Validation PoC (DONE; frozen #469).** Results and the macOS 27 addendum inlined in §1.

- **P1 — Lock foundation + decisive removal of the obsolete lifecycle/shield cluster (DONE; PR #472).**
  Introduced `AppLockController` (the explicit lock state machine: `.locked` / `.authenticating` /
  `.unlocked`) and the decoupled cosmetic cover; adopted the per-platform away-event rule (iOS =
  `ScenePhase.background`; macOS = resign ∪ screen-lock ∪ "Lock Now"). Deleted the cluster that existed
  only to disambiguate the system-sheet `.inactive` → `.active` cycle
  (`AuthenticationShield{Coordinator,Host,OverlayView}`, `PrivacyScreenLifecycleGate`, the union prompt
  snapshot, the settle window, the `isPrivacyScreenBlurred` overload). Because macOS keeps the detached
  sheet, P1 shipped with an **interim macOS resign-suppression guard** (`isDrivingAppSessionAuth`) so the
  away rule does not misfire on the unlock sheet's own resign; P3′ stage 1 replaces that guard with the
  designed `.authenticating` rule. *(The original "P1–P3 ship as one coupled macOS release" constraint is
  superseded: the coupling existed for the in-window cutover. The macOS release gate is now P3′ stages
  1 + 3.)*

- **P2 — macOS single-window unification (DONE; PR #475).**
  Removed the standalone macOS `Settings { }` scene; routed settings into the main window; preserved Cmd-,
  via `CommandGroup(replacing: .appSettings)`; retired the `UITEST_ROOT="settings"` launch path; the
  `LocalDataResetRestartGate` settings-scene mount went with the scene.

- **P3 (original) — macOS in-window authentication cutover. RETIRED 2026-06-10.**
  Implemented through its first PR (#491: the `AuthenticationPresenting` seam + the per-operation
  private-key route) and closed unmerged when the maintainer's manual gate caught the macOS 27
  embedded-UI denial (§1 addendum). With the stall motivation also resolved by macOS 27, the cutover —
  including the macOS biometric-only pinning, both one-time migrations, and the mode-picker removal — is
  withdrawn rather than deferred. The seam/host implementation is parked on branch
  `feat/p3-in-window-auth-pr1` for the contingency that Apple restores embedded UI (§7).

- **P3′ — Auth-lifecycle completion on the system sheet (DONE; replaces P3).**
  Stages 0–1 landed as individual PRs; the remainder landed as one PR with per-stage commits. The goal
  was architecture (explicit, simple, maintainable), not a behavior rescue:
  - **Stage 0 — Secure Enclave call-site hygiene (DONE; PR #493; salvaged from #491).** Deleted the two
    nil-context convenience overloads in `SecureEnclaveManageable` 🔴 and made every
    `generateWrappingKey` / `reconstructKey` call site state `authenticationContext:` explicitly
    (production + tests), so a reviewer sees at each SE operation whether a context is threaded or
    implicit system authentication is intended. `MockSecureEnclave` records the received context for
    tests. No behavior change (all pre-existing sites pass `nil`).
  - **Stage 1 — The `.authenticating` rule 🔴 (DONE; PR #494).** Replaced the P1-interim
    `isDrivingAppSessionAuth` resign-suppression guard in `AppLockController` with the designed rule
    (TARGET §3): an app-resign attributable to an in-flight app-driven authentication (app-session
    unlock in `.authenticating`, or an open operation-prompt session per the main-actor counter
    mirrored from `AuthenticationPromptCoordinator`) is not an away event; the operation-prompt case is
    decided at the session's end (deferred, fail-closed if still away); screen-lock and "Lock Now"
    always win immediately. Pure-state-machine unit tests for every interleaving, including the
    hop-delay TOCTOU integration pin.
  - **Stage 2′ — Single-prompt key-expiry modification 🔴 (DONE; redo of withdrawn PR #495).**
    `KeyMutationService.modifySoftwareExpiry` prompted twice in one user action (unwrap with the old
    wrapping key; first use of the new wrapping key inside `wrap`). It now authenticates **once** via
    system-sheet `evaluateAccessControl(.useKeyKeyExchange)` against the persisted mode's access
    control and threads that context into both SE operations (the `PrivateKeyRewrapWorkflow` pattern;
    macOS-27-validated via the probe suite); journal/promote atomicity untouched. **#495 was withdrawn
    at the maintainer's manual gate:** its pre-authentication ran *outside* any operation-prompt
    session, so the pre-auth sheet's own resign locked the app mid-action at grace=Immediately. The
    redo wraps the whole action in one session and adds the missing test class — composition tests
    (lock controller + coordinator + real flow) that pin in-session enrollment and the deferred-resign
    decision. The misleading `noMatchingKey` reuse in the modify flow's catalog guard was replaced by
    the honest `keyMetadataUnavailable` error at the same time.
  - **Uniform enrollment (DONE; the #495-class closure).** The session-wrap principle generalized:
    every auth-sheet-capable user action runs inside one operation-prompt session for its full
    duration (TARGET §3) — the mode-switch re-wrap (`AuthenticationManager.switchMode`), the App
    Access Protection policy change (extracted into `AppAccessPolicySwitchWorkflow`), Local Data Reset
    (`SettingsScreenModel.confirmLocalDataReset`), and key provisioning
    (`KeyProvisioningService.generateKey` / `importKey`, whose wrap prompt was previously unenrolled).
    Privacy prompts deliberately do not count toward the lock controller's mirror. Each flow carries a
    composition regression test on a shared harness.
  - **Stage 3 — Release-gate verification (DONE, folded into the finish PR).** The standard lanes,
    plus a consolidated manual handoff: per-flow smoke scenarios and the trace-based confirmation
    checklist for the `.authenticating` rule on macOS 27 (including the deferred post-auth fan-out
    watch item from the #494 review). The previously planned **macOS 26.5 validation pass was
    dropped**: the release decision (2026-06-10) ships ~September against **macOS 27 only**, removing
    26.5 from the support matrix (the deployment-target bump happens at release prep and is
    maintainer-owned).

- **P4 — Custom lock surface (DONE; broadened from iOS/iPadOS/visionOS to all platforms by maintainer
  decision).** One shared **opaque** lock surface — a text-only header (app name + locked-state
  caption; no decorative lock imagery, by maintainer review decision) — with the
  biometric auto-invoked, retry and biometrics-locked-out messaging preserved, driven by
  `AppLockController`. The platform authentication model is otherwise unchanged. visionOS remains an
  unvalidated assumption (no hardware).

- **P5 (last) — Verification + current-state doc cutover (DONE).** Full-lane verification of the new
  model; [SECURITY.md](SECURITY.md) §4–§5, [PRD.md](PRD.md) §4.9, and the two redesign docs flipped
  from forward-looking to current-state. Substantially smaller than originally planned: there was **no
  access-control model change, no migration, and no settings-surface removal** to document.

## 4. Secure Enclave context-threading inventory (private-key)

Two distinct Secure-Enclave seams — they must not be collapsed:

**Software / SE-wrapped path** (through `SecureEnclaveManager`):
- **(a) Already threads a context** — `PrivateKeyRewrapWorkflow` (the mode-switch re-wrap) passes its
  authenticated `LAContext` into both `reconstructKey(…authenticationContext:)` and
  `generateWrappingKey(…authenticationContext:)`. This is the pattern stage 2′ adopted.
- **(b) The shared read seam** — `PrivateKeyAccessService.unwrapPrivateKey` → `reconstructKey` with
  `authenticationContext: nil` (explicit after stage 0): the Secure Enclave authenticates implicitly via
  the system prompt, once per user-initiated operation. **Unchanged by design** (per-op posture, TARGET
  §4). Covers signing (including password-message encryption that signs), message decrypt, file-streaming
  decrypt, certification, revocation export, and S2K export/backup.
- **(c) The key-expiry duplicate** — `KeyMutationService.modifySoftwareExpiry` unwrapped (prompt 1) then
  re-wrapped via `generateWrappingKey` + `wrap`, whose first self-ECDH on the new key prompted again
  (prompt 2). **Fixed in stage 2′** with one threaded context, inside one operation-prompt session.
- **Provisioning** — `KeyProvisioningService.generateKey` / `importKey` produce a single prompt (the new
  wrapping key's first use inside `wrap`). Already single-prompt; **now enrolled** in one
  operation-prompt session per action (uniform enrollment) so the wrap prompt's own resign cannot lock
  the app mid-provisioning.

**Custody path** (separate; hidden / test-only): `SystemSecureEnclaveCustodyKeyStore.loadKeys` with
`kSecUseAuthenticationContext`, then `SecKeyCreateSignature` / `SecKeyCopyKeyExchangeResult`. It does **not**
go through `SecureEnclaveManager` and is untouched by this roadmap; it adopts the same explicit-context
principle through its own seam when productized.

## 5. Current → target component map

| Current | Target |
|---|---|
| `AuthenticationShield{Coordinator,Host,OverlayView}` (both mounts) | **removed (P1, shipped)** |
| `PrivacyScreenLifecycleGate`, union snapshot, settle window | **removed (P1, shipped)** |
| `isPrivacyScreenBlurred` overload + settle-blur | **removed (P1, shipped)** |
| macOS standalone `Settings { }` scene | **removed (P2, shipped)** |
| `isDrivingAppSessionAuth` interim resign-suppression guard | **replaced (P3′ stage 1, shipped)** by the designed `.authenticating` rule in `AppLockController` |
| `SecureEnclaveManageable` nil-context convenience overloads | **removed (P3′ stage 0, shipped)** — every call site states `authenticationContext:` explicitly |
| Key-expiry double prompt (`modifySoftwareExpiry`) | **single prompt (P3′ stage 2′, shipped)** via one threaded context, inside one operation-prompt session |
| Auth-sheet actions outside the unwrap seam (mode switch / policy switch / Local Data Reset / provisioning) | **wrapped in operation-prompt sessions (uniform enrollment, shipped)** |
| Minimal P1 lock surface (`.ultraThinMaterial`) | **opaque app-identified lock surface (P4, shipped)** — one shared surface, all platforms |
| macOS detached system-sheet authentication | **retained** — the system presents authentication; the lock model is correct around it by design |
| App Access Protection options / Private Key Protection modes | **retained everywhere** — no pinning, no migrations |
| `LocalDataResetRestartGate` | **retained** — one mount (P2); system-sheet authentication |
| In-window presentation seam (`AuthenticationPresenting` + macOS presenter/host) | **parked** on `feat/p3-in-window-auth-pr1` (closed #491); contingent on Apple restoring embedded UI |

## 6. Red lines & tests

- **Red-line review.** `AppLockController` and `Sources/Security/ProtectedData/*` (stage 1),
  `SecureEnclaveManageable` (stage 0), and the stage-2′ context threading
  (`KeyMutationService`, `SecureEnclaveManager` call sites) require human security review per
  [SECURITY.md](SECURITY.md) §10, with positive + negative tests. Entitlements are **not** touched by any
  P3′ stage.
- **Tests.**
  - Stage 1: `AppLockController` pure-state-machine tests — auth-driven resign during `.authenticating`
    does not lock; genuine background/screen-lock/Lock-Now during `.authenticating` discards the in-flight
    unlock and fails closed; grace=0 produces no double-auth; session-mirror suppression covered for
    the same interleavings; the hop-delay TOCTOU integration pin; lock-state trace assertions.
  - Stage 2′ + uniform enrollment: unit tests — single prompt with the SAME context instance asserted
    on both SE operations and invalidated exactly once; a declined/cancelled authentication aborts
    before any SE mutation or journal entry and the flow stays usable; the un-wired path keeps nil
    contexts; the mid-action catalog relock surfaces `keyMetadataUnavailable`. **Composition
    regression tests** (the class #495 was missing — lock controller + prompt coordinator + the real
    flow on a shared harness, `OperationPromptLockHarness`): each enrolled flow asserts its prompt
    runs with an open operation-prompt session and that a resign during the prompt is deferred and
    decided at the session's end (`ModifyExpiryOperationPromptCompositionTests`,
    `ModeSwitchOperationPromptCompositionTests`, `AppAccessPolicySwitchWorkflowTests`,
    `KeyProvisioningOperationPromptCompositionTests`, plus the Local Data Reset tests in
    `SettingsScreenModelTests`).
  - Stage 3: the standard lanes (`CypherAir-UnitTests`, `CypherAir-MacUITests`, visionOS build probe,
    `CypherAir-DeviceTests` for SE/biometric coverage) plus the maintainer's manual smoke pass and the
    macOS 27 trace checklist (the 26.5 validation pass was dropped by the release decision, §7).
- **Invariants under test throughout:** subsystem A/B context separation; AEAD hard-fail; no partial
  plaintext; no secret logging; zero network; access-control flags byte-identical before/after.

## 7. Decisions & validation status

- **Presentation (decided 2026-06-10, reversing the 2026-06-07 decision):** the system authentication
  sheet, on every platform. In-window presentation is **parked**, not chosen: macOS 27 denies embedded LA
  UI to third-party processes (§1 addendum), and the stall that motivated in-window is resolved. Re-probe
  embedded UI on each new macOS build (`InWindowAuthProbeTests`); if Apple restores it, in-window may
  return as an optional enhancement through the parked seam.
- **Both postures retained (decided 2026-06-10, reversing the biometric-only pin):** macOS keeps
  `.userPresence` (password fallback is a normal product feature) and `.standard`; no migrations. The
  biometric-only decision's premise (no in-window password entry) disappeared with in-window presentation.
- **Single-prompt-per-action (decided):** fix the one duplicate (key expiry); do **not** generalize
  explicit pre-authentication to already-single-prompt operations — if ever wanted, that is a separate
  future proposal.
- **Uniform session enrollment (decided 2026-06-11, after the #495 withdrawal):** every user action
  that can present an authentication sheet while unlocked runs inside one operation-prompt session for
  its full duration; enrollment is the wrapped action. **Privacy prompts do not count toward the lock
  controller's mirror** — making the mirror count them would entangle arm (a)'s unlock with arm (b)'s
  deferral.
- **Release gate (decided 2026-06-10):** ship ~September against **macOS 27 only**; macOS 26.5 leaves
  the support matrix and its stage-3 validation pass is dropped (no VM, no second machine). The
  deployment-target bump (26.5 → 27) happens at release prep and is maintainer-owned.
- **Companion devices:** under `.userPresence`, `LAPolicy.deviceOwnerAuthentication` already includes
  Apple Watch on macOS — system behavior, not a CypherAir feature decision. A dedicated
  biometrics-or-Watch (no password) option is an optional future study.
- **Auto-lock interval (decided):** reuse the existing grace setting as the unified interval.
- **visionOS (decided):** follow the iOS direction; on-device confirmation remains the one unvalidated
  assumption (no hardware), tracked as such, not a design fork.

---

*All phases are on `main`; this roadmap is the record of the migration. The current-state docs
([SECURITY.md](SECURITY.md) §4–§5, [PRD.md](PRD.md) §4.9, and the
[Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md)) describe shipped behavior.*
