# Authentication / Privacy / Lifecycle Redesign — Migration Roadmap

> Status: Draft / active roadmap. This document describes **proposed migration work** and does **not**
> describe current shipped behavior. Shipped behavior remains as documented in [SECURITY.md](SECURITY.md)
> and [PRD.md](PRD.md) until these phases land.
> Date: 2026-06-07.
> Purpose: The decisive migration from the current entangled privacy/lock/shield machinery to the target
> in [Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md): phasing, the validated P0 results, the
> in-window authentication seam inventory, the current→target component map, tests, and decisions.
> Audience: Swift implementers, security reviewers, architecture reviewers, test owners, AI coding tools.
> Companion: [Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md) (the end state; the two-subsystem boundary).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [TESTING.md](TESTING.md), [CODE_REVIEW.md](CODE_REVIEW.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: a PoC result, a phase completion, a changed phase boundary, a changed red-line surface, or a
> changed validation minimum.

Source anchoring: this roadmap names shipped types and functions by **symbol**, not line number (line numbers
drift). All claims are grounded in a first-hand read of the shipped `main` sources.

## 1. P0 validation results (inlined)

A throwaway macOS validation spike (P0) on a real Mac with Touch ID de-risked the in-window direction before
the rewrite. It was the most-faithful practical reproduction of the real production path; none of its code
merges to `main`. The full evidence is archived on the frozen PoC branch `poc/auth-lifecycle-macos` (PR #469)
and is **not** reproduced or linked here. Validated results:

- **No resign.** An inline `LAAuthenticationView` driving `evaluatePolicy` / `evaluateAccessControl` does not
  post `NSApplication.didResignActiveNotification` (and `NSApplication.shared.isActive` stays `true`) for the
  full prompt lifecycle. This is what makes the macOS "Immediately" lock model sound.
- **Per-operation context consumption (software path).** A context authenticated in-window via
  `evaluateAccessControl(accessControl, operation:)` satisfies `SecureEnclave.P256.KeyAgreement.PrivateKey(
  dataRepresentation:authenticationContext:)` reconstruction with no second prompt.
- **Custody context compatibility (narrow).** The same approach drives a custody `SecKey` sign / ECDH loaded
  with `kSecUseAuthenticationContext`, one prompt each, no resign — a technical-compatibility result only; full
  custody product-flow validation remains deferred (custody is not productized).
- **Single-prompt mode-switch / re-wrap.** The re-wrap flow authenticates **once** for the whole action under
  the presenter (one in-window prompt for an N-key re-wrap), with the atomicity / crash-recovery semantics
  preserved.
- **No safe in-window password field.** The embedded `LAAuthenticationView` exposes biometric / companion
  policies only; there is no inline passcode entry → macOS authenticated flows become biometric-only.
- **Shield occlusion / deadlock (finding F1).** The legacy `AuthenticationShield` raises at `.zIndex(10)` and
  occludes / deadlocks in-window authentication — a functional blocker for in-window auth, not a cosmetic flash.
- **Unlock-vs-key-use is a code-routing requirement, not a runtime experiment.** The app-unlock authentication
  is never reused to authorize a private-key operation; this is guaranteed by code structure and review.
- **Pending:** visionOS on-device confirmation is deferred (no hardware).

## 2. Migration principle

**The macOS *authentication presentation* moves in-window; in-window local biometric is the ONLY macOS
authentication path.** A lock *surface* hosted in the window is not the same as the *authentication* rendering
in-window — the target moves the authentication prompt itself in-window via `LAAuthenticationView`.

Corollaries:
- **No companion.** macOS uses `deviceOwnerAuthenticationWithBiometrics` (local biometric); the companion /
  Apple-Watch policies are out of scope (unvalidated; different security semantics).
- **Two subsystems each drop their passcode-fallback path on macOS** — app-session `.userPresence` and
  private-key `.standard` — described separately and never conflated (see [Target Design](AUTH_LIFECYCLE_REDESIGN_TARGET_DESIGN.md) §1).
- **The obsolete lifecycle/shield cluster is removed *as* the lock foundation lands** — not deferred to a final
  cleanup.
- **No transitional permanent exceptions.** Every shipped macOS authentication surface moves in-window in one
  decisive cutover; the Secure Enclave Custody path (hidden / test-only) follows the same principle through its
  own seam when productized.
- **Out of scope (passphrase text entry, not authentication surfaces):** import-S2K passphrase entry
  (`ImportKeyView` / `CypherSecureTextField`) and **standalone** password-message / SKESK encrypt + decrypt are
  SwiftUI `SecureField` text entry, not private-key biometric (password decrypt verifies signatures with *public*
  keys only) — they are not authentication surfaces and are not exceptions.
- **In scope (a private-key signing surface):** password-message encryption that **also signs**
  (`PrivateKeyPasswordMessageEncryptionService` with a `signerFingerprint`) is a private-key signing operation. It
  routes through the same signing seam as ordinary encrypt-and-sign (software
  `PrivateKeyAccessService.unwrapPrivateKey` → `SecureEnclaveManager.reconstructKey`; custody external-P256-signer /
  `loadKeys`), so its signing authorization uses the **same macOS in-window presenter / threaded-context path as
  every other private-key signing operation** (§3 P3 / §4). Only the SKESK passphrase itself is `SecureField` text.

## 3. Phases (foundation-first; PR-sized steps)

These phases are PR-sized implementation steps, **not independently shippable macOS milestones**. On macOS, **P1–P3
are one coupled release**: P1 removes the cluster that disambiguated the *detached* system sheet, but macOS keeps the
detached sheet — and the resign / `.inactive` → `.active` churn it generates — until P3 moves authentication
in-window. Shipping P1's removal in a macOS build that still authenticates via the detached sheet would let
`AppLockController`'s resign-based away rule misfire on the auth sheet's own resign (P0 proved only the *in-window*
view avoids the resign). iOS / iPadOS / visionOS never needed that cluster (lock keys off `.background`, which the
biometric prompt never triggers), so the P1 foundation is independently sound there. The direction is unchanged — the
detached system-sheet path is eliminated decisively; the coupling is only a macOS delivery constraint.

- **P0 — Validation PoC (DONE; frozen #469).** Results inlined in §1. No code merges to `main`.

- **P1 — Lock foundation + decisive removal of the obsolete lifecycle/shield cluster.**
  Introduce `AppLockController` (the explicit lock state machine) and the decoupled cosmetic cover; adopt the
  per-platform away-event rule (iOS = `ScenePhase.background`; macOS = resign ∪ screen-lock ∪ "Lock Now").
  **Delete, in this same phase**, the cluster that exists only to disambiguate the system-sheet
  `.inactive` → `.active` cycle: `AuthenticationShield{Coordinator,Host,OverlayView}` and **both** of its
  `CypherAirApp` mounts; `PrivacyScreenLifecycleGate`; the union prompt snapshot
  (`AuthenticationPromptCoordinator.anyAuthenticationPromptSnapshot`) and the settle window; the
  `isPrivacyScreenBlurred` overload and the settle-blur bookkeeping in `AppSessionOrchestrator`.
  `AppSessionOrchestrator` retains its app-session-auth concerns (`recordAuthentication`,
  `pendingAuthenticatedContext`, `consumeAuthenticatedContextForProtectedData`); the lock / blur / grace /
  settle responsibilities move to `AppLockController`. Re-target the DEBUG `AuthLifecycleTraceStore` to the new
  lock-state transitions. The cosmetic cover lands here so there is no cover-coverage gap. Preserve the merged
  grace=0 behavior. *Why the cluster's removal is consolidated here:* its jobs — cosmetic overlay and
  `.active`-disambiguation timing — are subsumed by the cover subsystem and the explicit lock state. On iOS this is
  complete at P1 (lock keys off `.background`, which the biometric prompt never triggers). On macOS the
  disambiguation is unnecessary only once authentication stops resigning the app — i.e. once P3 moves it in-window —
  so although the removal is authored here, **on macOS P1 and P3 ship as one coupled release** and the cluster is not
  shipped removed while macOS still uses the detached sheet (see the §3 delivery-coupling note). P0/F1 fixes the
  within-release order: the shield occludes in-window auth, so it is torn down exactly as the in-window view is
  mounted. The cluster is never an authentication path. The independent `LocalDataResetRestartGate` is untouched here.

- **P2 — macOS single-window unification.**
  Remove the standalone macOS `Settings { }` scene; route settings into the main window; preserve Cmd-, via a
  `CommandGroup(replacing: .appSettings)` command. Update the macOS presentation hosts
  (`MacSettingsRootView`, `ProtectedSettingsHost`) to drop the settings-scene presentation mode; retire the
  `UITEST_ROOT="settings"` launch path; update the `launchSettings()` macOS UI tests to
  `launchMain() + openSettingsTab()`. The shield's settings-scene mount is already gone (P1); the
  **`LocalDataResetRestartGate` settings-scene mount is removed with the scene** — only its main-window mount
  remains.

- **P3 — macOS in-window authentication cutover (shipped surfaces; one decisive move, zero exceptions).**
  Introduce the `AuthenticationPresenting` seam + the macOS `LAAuthenticationView` implementation so the
  **authentication prompt** renders in-window (not merely the lock surface; iOS / visionOS pass through to the
  system prompt). Route **all** shipped macOS authentication in-window:
  - **App-session unlock** — in-window `evaluatePolicy`.
  - **Local Data Reset confirmation auth** — its app-session authentication (`evaluateAppSession`, source
    `localDataReset`) adopts the presenter.
  - **Software per-operation private-key auth** — present the operation's authorization in-window via
    `evaluateAccessControl(operation:)` and thread the resulting `LAContext` through
    `PrivateKeyAccessService.unwrapPrivateKey` into `SecureEnclaveManager.reconstructKey(…authenticationContext:)`
    (stop calling the `SecureEnclaveManageable` nil-context convenience overload). Covers signing, message
    decrypt, file-streaming decrypt, certification, revocation export, and S2K export/backup.
  - **Key-expiry gap** — `KeyMutationService.modifySoftwareExpiry` unwraps then re-wraps via
    `generateWrappingKey` with no context (two prompts today); thread one in-window context into both
    (the `PrivateKeyRewrapWorkflow` pattern).
  - **Provisioning** — `KeyProvisioningService.generateKey` / `importKey` authenticate in-window first, then
    thread the context into `generateWrappingKey`.

  **Remove the macOS mode-switch UI** (the `SettingsSecuritySection` "Private Key Protection" Standard/High
  picker, and the "App Access Protection" picker's passcode-fallback option). macOS pins private-key
  `.highSecurity` and app-session `.biometricsOnly`.

  **Two independent, user-initiated, in-window migration actions** are owned by a dedicated
  `MacAuthMigrationCoordinator` (a detect→run→record migration coordinator, modeled on
  `KeyMetadataDomainStore`) — **not** the
  crash-recovery hook `recoverPrivateKeyControlJournalsAfterPostUnlock`, which is a no-op unless an interrupted
  re-wrap journal already exists and only *finishes* an interruption. They are surfaced as **two Settings
  entries**, each with **its own in-window authentication and its own completion**, runnable in any order, each
  hiding on its own completion. They authorize **different Keychain items under different access controls via
  different mechanisms and must not share one `LAContext`**:
  - **(PK) re-wrap** `.standard` → `.highSecurity` via `AuthenticationManager.switchMode(to: .highSecurity, …)`
    → `PrivateKeyRewrapWorkflow`. **The migration must authenticate in-window biometric**, not via
    `evaluate(mode: .standard)` (which selects `.deviceOwnerAuthentication` = the detached system sheet +
    passcode — the old path): adapt `switchMode` / `PrivateKeyModeSwitchAuthenticator.authenticateCurrentMode`
    to take the `AuthenticationPresenting` seam on macOS and authenticate biometric-only via
    `evaluateAccessControl` against the existing key's access control (`.biometryAny` alone satisfies the
    Standard key's `[.biometryAny, .or, .devicePasscode]` OR-gate), then thread `lastEvaluatedContext` into the
    re-wrap. Completion = persisted `.highSecurity` (`private-key-control`). Drops `.devicePasscode`. Because the
    migration moves keys to the biometric-only flag set (dropping the passcode fallback), it **applies the existing
    pre-High-Security backup gate unchanged and must not bypass it**: it routes through
    `switchMode(to: .highSecurity, hasBackup:)`, which enforces the existing `AuthenticationError.backupRequired`
    safety net, and the migration entry surfaces the same `requiresRiskAcknowledgement` warning the manual switch
    shows. The gate is **account-level** — it blocks only when **no private-key backup exists at all** (`hasBackup`
    = at least one key with `PGPKeyIdentity.isBackedUp`); the migration neither strengthens it to a per-key rule nor
    weakens it.
  - **(AS) re-protect** `.userPresence` → `.biometricsOnly` via
    `ProtectedDataSessionCoordinator.reprotectPersistedRootSecretIfPresent(from:to:authenticationContext:)` →
    `reprotectRootSecret` (its own in-window `evaluatePolicy` context, `interactionNotAllowed`; `SecItemUpdate`
    on `kSecAttrAccessControl`; payload unchanged). Completion = persisted `.biometricsOnly` (UserDefaults).

  Explanatory pages host the inline authentication for the consequential flows. **Custody** (hidden / test-only)
  threads its context via its own `loadKeys` `kSecUseAuthenticationContext` seam when productized — a separate
  track, no permanent exception. *Why one cutover:* the per-operation seam is a uniform in-window mechanism
  (`evaluateAccessControl` / `evaluatePolicy` + a threaded context into entry points that already accept it);
  splitting the surfaces would ship the rejected "in-window with exceptions" half-state.
  *Red-line review (per [SECURITY.md](SECURITY.md) §10):* `AuthenticationManager`, `SecureEnclaveManager`,
  `AuthenticationMode.createAccessControl`, `Sources/Security/ProtectedData/*`, entitlements.

- **P4 — iOS / iPadOS / visionOS custom lock surface.** A custom opaque lock surface with the biometric
  auto-invoked, retry and biometrics-locked-out messaging preserved, driven by `AppLockController`. The platform
  authentication model is otherwise unchanged. Depends only on P1; independent of P3 (the macOS P1/P3 delivery
  coupling does not apply here — iOS never used the detached-sheet disambiguation). visionOS remains an
  unvalidated assumption (no hardware).

- **P5 (last) — Verification + current-state doc cutover.** macOS UI tests, device biometric tests, the hidden
  custody route check, and lock-state trace assertions; tests for **both** migration actions (PK re-wrap
  including the in-window-biometric authentication starting from a Standard key; AS re-protect; independent
  completion); the Local Data Reset in-window-auth test; negative tests (macOS offers no passcode fallback in
  either subsystem; macOS shows no mode-switch UI). Then flip [SECURITY.md](SECURITY.md) §4, [PRD.md](PRD.md)
  §4.9, and the two redesign-doc status blocks from forward-looking to current-state.

## 4. In-window authentication seam inventory (private-key)

Two distinct Secure-Enclave seams — they must not be collapsed:

**Software / SE-wrapped path** (through `SecureEnclaveManager`):
- **(a) Already threads a context** — `PrivateKeyRewrapWorkflow` (the mode-switch re-wrap) passes its
  authenticated `LAContext` into both `reconstructKey(…authenticationContext:)` and
  `generateWrappingKey(…authenticationContext:)`. This is the pattern the other seams adopt.
- **(b) The shared read seam** — `PrivateKeyAccessService.unwrapPrivateKey` → `reconstructKey`, which today
  calls the **nil-context convenience overload** in `SecureEnclaveManageable`. Covers signing (including
  password-message encryption that signs, via `PrivateKeyPasswordMessageEncryptionService`), message decrypt,
  file-streaming decrypt, certification, revocation export, and S2K export/backup. Fix: stop the convenience
  overload; thread the in-window-authenticated `LAContext`.
- **(c) The key-expiry gap** — `KeyMutationService.modifySoftwareExpiry` re-wraps via `generateWrappingKey`
  with no context. Fix: thread the in-window context (the (a) pattern).
- **Provisioning** — `KeyProvisioningService.generateKey` / `importKey` call `generateWrappingKey` without a
  context. Fix: authenticate in-window first, then thread.

**Custody path** (separate; hidden / test-only): `SystemSecureEnclaveCustodyKeyStore.loadKeys` with
`kSecUseAuthenticationContext`, then `SecKeyCreateSignature` / `SecKeyCopyKeyExchangeResult`. It does **not** go
through `SecureEnclaveManager`. There is no shipped context seam today (a DEBUG-only seam exists on the PoC
branch). Fix when productized: route the presenter's context into `loadKeys`.

`reconstructKey` and `generateWrappingKey` already accept an optional `LAContext`; the only change is to stop
calling the convenience overloads and thread an in-window-authenticated context.

## 5. Current → target component map

| Current | Target |
|---|---|
| `AuthenticationShield{Coordinator,Host,OverlayView}` (both mounts) | **removed (P1)** — replaced by explicit lock + cosmetic cover |
| `PrivacyScreenLifecycleGate`, union snapshot, settle window | **removed (P1)** — lock no longer reacts to `.active` |
| `isPrivacyScreenBlurred` overload + settle-blur | **removed (P1)** — cosmetic cover + explicit lock state |
| `AppSessionOrchestrator` resume/grace/blur/settle | **moved to `AppLockController` (P1)**; app-session-auth concerns stay |
| macOS standalone `Settings { }` scene | **removed (P2)** — single window |
| macOS detached system-sheet authentication | **removed (P3)** — in-window via `AuthenticationPresenting` / `LAAuthenticationView` |
| macOS private-key `.standard` + Standard/High switch UI | **removed (P3)** — biometric-only; one-time PK migration |
| macOS app-session `.userPresence` option | **removed (P3)** — biometric-only; one-time AS root-secret re-protect |
| `LocalDataResetRestartGate` (two mounts) | **retained** — independent of the cluster; **two mounts → one (P2)**; its auth moves in-window (P3) |
| — | **new:** `AppLockController`, decoupled cosmetic cover, `AuthenticationPresenting` + macOS impl, in-window lock surfaces, explanatory pages, `MacAuthMigrationCoordinator` + two independent Settings migration entries |

The **(P1)** / **(P2)** / **(P3)** labels mark which phase performs each change, not independently shippable macOS
milestones: on macOS the P1 removals and the P3 in-window cutover ship as one coupled release (see §3).

## 6. Red lines & tests

- **Red-line review.** `AppSessionOrchestrator`, `Sources/Security/ProtectedData/*`, `AuthenticationManager`,
  `SecureEnclaveManager`, `AuthenticationMode.createAccessControl`, and entitlements require human security
  review per [SECURITY.md](SECURITY.md) §10. Each touching phase carries positive + negative + round-trip tests.
- **No interim regression (macOS delivery coupling).** The merged grace=0 fix keeps working until superseded. P1
  may be an implementation PR slice, but on macOS the P1 cluster removal and the P3 in-window-auth cutover are
  **coupled for delivery (shipped together)**: because macOS keeps the detached system sheet until P3, P1's removal
  must not reach a shipped macOS build ahead of P3, or the new lock model would regress on the auth sheet's resign.
  iOS observes the same lock behavior at P1 (lock keys off `.background`). The old detached system-sheet path is
  still decisively eliminated — the coupling is a delivery constraint, not a softening of the direction.
- **Tests.** `AppLockController` pure-state-machine unit tests; cosmetic-cover tests; macOS UI tests (in-window
  unlock, explanatory pages, single-window settings); device biometric tests (single prompt, no resign, content
  preserved across in-window auth; per-op inline auth); the two migration-action tests (PK re-wrap with
  in-window-biometric auth from a Standard key; AS re-protect; independent completion); the Local Data Reset
  in-window-auth test; the hidden-custody route check; lock-state trace assertions; the visionOS build probe.

## 7. Decisions & validation status

- **Mechanism (decided):** `LAAuthenticationView` + `LAContext` — `evaluatePolicy` for app-session unlock,
  `evaluateAccessControl` for per-operation private-key authorization. `LARight.authorize(in:)` is a secondary
  fallback only.
- **Companion (decided):** excluded from the target (unvalidated in P0; different security semantics).
- **macOS biometric-only by construction (decided):** both subsystems drop their passcode-fallback path on
  macOS; the access-control model changes (recorded in [SECURITY.md](SECURITY.md) §4).
- **Auto-lock interval (decided):** reuse the existing grace setting as the unified interval; a separate
  macOS-specific setting is an optional future study.
- **visionOS (decided):** follow the iOS direction; on-device Optic-ID + `ScenePhase` confirmation is the one
  remaining unvalidated assumption (no hardware), tracked as such, not a design fork.

---

*This is a migration proposal. It does not change shipped behavior until these phases are implemented and
reviewed; the current-state docs are updated at P5.*
