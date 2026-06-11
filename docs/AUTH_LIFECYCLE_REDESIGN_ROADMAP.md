# Authentication / Privacy / Lifecycle Redesign — Migration Roadmap

> Status: Active roadmap, **re-scoped 2026-06-10**, partially landed. P0 (validation PoC; frozen #469;
> in-window results invalidated on macOS 27 — §1 addendum), P1 (lock foundation + obsolete-cluster
> removal; PR #472), and P2 (macOS single-window unification; PR #475) are implemented on `main`.
> The original P3 (macOS in-window authentication cutover) is **retired** — PR #491 closed unmerged
> after macOS 27 was found to deny embedded LocalAuthentication UI to non-Apple-signed processes, and
> the stall problem that motivated it no longer reproduces on macOS 27. Its replacement **P3′**
> (§3) completes the explicit lock-state architecture on the system authentication sheet. P4–P5
> remain proposed. Phases that have not landed do **not** describe current shipped behavior — shipped
> behavior remains as documented in [SECURITY.md](SECURITY.md) and [PRD.md](PRD.md), and the
> current-state docs flip at P5.
> Date: 2026-06-10 (originally 2026-06-07).
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
  P3′ stage 1; macOS 26.5 validation is the release gate (P3′ stage 3).

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
  depth for private-key operations. The macOS away-event rule is filtered through that state (the
  `.authenticating` rule, TARGET §3) instead of heuristics.
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

- **P3′ — Auth-lifecycle completion on the system sheet (IN PROGRESS; replaces P3).**
  One PR series, per-stage commits; the goal is architecture (explicit, simple, maintainable), not a
  behavior rescue:
  - **Stage 0 — Secure Enclave call-site hygiene (salvaged from #491).** Delete the two nil-context
    convenience overloads in `SecureEnclaveManageable` 🔴 and make every `generateWrappingKey` /
    `reconstructKey` call site state `authenticationContext:` explicitly (production + tests), so a
    reviewer sees at each SE operation whether a context is threaded or implicit system authentication is
    intended. `MockSecureEnclave` records the received context for tests. No behavior change (all
    existing sites pass `nil`).
  - **Stage 1 — The `.authenticating` rule 🔴.** Replace the P1-interim `isDrivingAppSessionAuth`
    resign-suppression guard in `AppLockController` with the designed rule (TARGET §3): an app-resign
    attributable to an in-flight app-driven authentication (app-session unlock in `.authenticating`, or a
    private-key operation prompt in flight per the `AuthenticationPromptCoordinator` depth) is not an
    away event; genuine away events during authentication still win and fail closed. Pure-state-machine
    unit tests for every interleaving; a trace-enabled validation session on macOS 27.
  - **Stage 2 — Single-prompt key-expiry modification 🔴.** `KeyMutationService.modifySoftwareExpiry`
    currently prompts twice in one user action (unwrap with the old wrapping key; first use of the new
    wrapping key inside `wrap`). Authenticate **once** via system-sheet
    `evaluateAccessControl(.useKeyKeyExchange)` against the persisted mode's access control and thread
    that context into both SE operations (the `PrivateKeyRewrapWorkflow` pattern; macOS-27-validated via
    the probe suite). Journal/promote atomicity untouched. This is the only flow with a duplicate prompt;
    provisioning (generate/import) is already single-prompt and is not changed.
  - **Stage 3 — Release-gate verification.** The standard lanes, plus: trace-based confirmation of the
    `.authenticating` rule on macOS 27, and a validation pass of the auth flow on **macOS 26.5** (VM or
    second machine — the development Mac can no longer run it) before the next release ships. If 26.5
    behavior is unacceptable and unfixable app-side, the release alternative is to require macOS 27;
    that is a release decision, not a design fork.

- **P4 — iOS / iPadOS / visionOS custom lock surface.** A custom opaque lock surface with the biometric
  auto-invoked, retry and biometrics-locked-out messaging preserved, driven by `AppLockController`. The
  platform authentication model is otherwise unchanged. Depends only on P1. visionOS remains an
  unvalidated assumption (no hardware).

- **P5 (last) — Verification + current-state doc cutover.** Full-matrix verification of the new model;
  then flip [SECURITY.md](SECURITY.md) §4, [PRD.md](PRD.md) §4.9, and the two redesign-doc status blocks
  from forward-looking to current-state. Substantially smaller than originally planned: there is **no
  access-control model change, no migration, and no settings-surface removal** to document.

## 4. Secure Enclave context-threading inventory (private-key)

Two distinct Secure-Enclave seams — they must not be collapsed:

**Software / SE-wrapped path** (through `SecureEnclaveManager`):
- **(a) Already threads a context** — `PrivateKeyRewrapWorkflow` (the mode-switch re-wrap) passes its
  authenticated `LAContext` into both `reconstructKey(…authenticationContext:)` and
  `generateWrappingKey(…authenticationContext:)`. This is the pattern stage 2 adopts.
- **(b) The shared read seam** — `PrivateKeyAccessService.unwrapPrivateKey` → `reconstructKey` with
  `authenticationContext: nil` (explicit after stage 0): the Secure Enclave authenticates implicitly via
  the system prompt, once per user-initiated operation. **Unchanged by design** (per-op posture, TARGET
  §4). Covers signing (including password-message encryption that signs), message decrypt, file-streaming
  decrypt, certification, revocation export, and S2K export/backup.
- **(c) The key-expiry duplicate** — `KeyMutationService.modifySoftwareExpiry` unwraps (prompt 1) then
  re-wraps via `generateWrappingKey` + `wrap`, whose first self-ECDH on the new key prompts again
  (prompt 2). **Fixed in stage 2** with one threaded context.
- **Provisioning** — `KeyProvisioningService.generateKey` / `importKey` produce a single prompt (the new
  wrapping key's first use inside `wrap`). Already single-prompt; **not changed**.

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
| `isDrivingAppSessionAuth` interim resign-suppression guard | **replaced (P3′ stage 1)** by the designed `.authenticating` rule in `AppLockController` |
| `SecureEnclaveManageable` nil-context convenience overloads | **removed (P3′ stage 0)** — every call site states `authenticationContext:` explicitly |
| Key-expiry double prompt (`modifySoftwareExpiry`) | **single prompt (P3′ stage 2)** via one threaded context |
| macOS detached system-sheet authentication | **retained** — the system presents authentication; the lock model is correct around it by design |
| App Access Protection options / Private Key Protection modes | **retained everywhere** — no pinning, no migrations |
| `LocalDataResetRestartGate` | **retained** — one mount (P2); system-sheet authentication |
| In-window presentation seam (`AuthenticationPresenting` + macOS presenter/host) | **parked** on `feat/p3-in-window-auth-pr1` (closed #491); contingent on Apple restoring embedded UI |

## 6. Red lines & tests

- **Red-line review.** `AppLockController` and `Sources/Security/ProtectedData/*` (stage 1),
  `SecureEnclaveManageable` (stage 0), and the stage-2 context threading
  (`KeyMutationService`, `SecureEnclaveManager` call sites) require human security review per
  [SECURITY.md](SECURITY.md) §10, with positive + negative tests. Entitlements are **not** touched by any
  P3′ stage.
- **Tests.**
  - Stage 1: `AppLockController` pure-state-machine tests — auth-driven resign during `.authenticating`
    does not lock; genuine background/screen-lock/Lock-Now during `.authenticating` discards the in-flight
    unlock and fails closed; grace=0 produces no double-auth; per-op prompt-depth suppression covered for
    the same interleavings; lock-state trace assertions.
  - Stage 2: device tests — modify-expiry is a single prompt end-to-end; round-trip (the re-wrapped key
    decrypts/signs); negative: a declined/cancelled authentication aborts before any SE mutation and the
    journal recovers; the threaded context is created for and confined to the one action (never stored,
    invalidated after).
  - Stage 3: the standard lanes (`CypherAir-UnitTests`, `CypherAir-MacUITests`, visionOS build probe,
    `CypherAir-DeviceTests` for SE/biometric coverage) plus the macOS 26.5 validation pass.
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
- **Companion devices:** under `.userPresence`, `LAPolicy.deviceOwnerAuthentication` already includes
  Apple Watch on macOS — system behavior, not a CypherAir feature decision. A dedicated
  biometrics-or-Watch (no password) option is an optional future study.
- **Auto-lock interval (decided):** reuse the existing grace setting as the unified interval.
- **visionOS (decided):** follow the iOS direction; on-device confirmation remains the one unvalidated
  assumption (no hardware), tracked as such, not a design fork.

---

*Phases land individually (P0–P2 are on `main`; P3′ is in progress). Un-landed phases remain proposals and
do not change shipped behavior until implemented and reviewed; the current-state docs are updated at P5.*
