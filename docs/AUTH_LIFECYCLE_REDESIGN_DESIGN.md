# Authentication / Privacy / Lifecycle Redesign — Design

> Status: Draft proposal. This document describes proposed future work and does **not**
> describe current shipped behavior. The shipped behavior remains as documented in
> [SECURITY.md](SECURITY.md) §4–§5 and [PRD.md](PRD.md) §4.9 until this redesign lands.
> Date: 2026-06-05.
> Purpose: Define the target architecture and user experience for CypherAir's app-lock,
> privacy-cover, and authentication-presentation flow across iOS, iPadOS, macOS, and
> visionOS, replacing the current entangled privacy-screen / lifecycle-gate design.
> Audience: Swift implementers, security reviewers, architecture reviewers, product, test owners, AI coding tools.
> Companion: [Technical Plan & Validation](AUTH_LIFECYCLE_REDESIGN_PLAN.md) (phasing, PoC, file map, tests).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [PRD.md](PRD.md), [TDD.md](TDD.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: Any change to the lock-state model, the per-platform away-event rules, the
> macOS in-app authentication mechanism, the per-operation authentication posture, or the
> cosmetic-cover / lock separation.

## 1. Context & motivation

### 1.1 What exists today
App-session authentication, the privacy blur, and the app lifecycle are coordinated by a set
of tightly-coupled components: `PrivacyScreenModifier`, `PrivacyScreenLifecycleGate`,
`AppSessionOrchestrator`, `AuthenticationPromptCoordinator`, and a separate
`AuthenticationShield*` overlay with its own dismissal state machine. A current-state audit
found roughly eight concerns entangled across these components:

1. App-switcher / multitasking privacy blur
2. Session lock + grace re-authentication
3. Per-operation private-key biometric
4. Authentication-failure UI (retry, biometrics-locked-out)
5. Protected-data relock
6. Lifecycle transient suppression (the gate)
7. The authentication-shield overlay + its dismissal timing
8. Post-authentication "settle blur" bookkeeping

### 1.2 Why it is fragile
Two structural problems drive the recurring defects (e.g. the grace=0 "second Face ID +
content clear" bug):

- **One overloaded signal.** `AppSessionOrchestrator.isPrivacyScreenBlurred` is a single
  boolean serving **both** cosmetic app-switcher privacy **and** the lock / auth-failure
  presentation. "Locked" is never an explicit state; it is *inferred* from blur +
  `isAuthenticating` + `authFailed` + grace.
- **Lock is re-evaluated on every `.active`.** Because a system biometric sheet produces a
  transient `.inactive` → `.active` cycle, the system must *disambiguate* "the sheet
  dismissing" from "a genuine resume." That single disambiguation is the entire reason the
  lifecycle gate, the union prompt snapshot, the 30-second settle window, and the shield
  dismissal timer exist — fragile machinery coordinated across async boundaries.

### 1.3 Verified platform facts (the constraints this design is built on)
Confirmed against the installed 26.x SDKs and Apple documentation:

| Fact | iOS / iPadOS | macOS | visionOS |
|---|---|---|---|
| Biometric prompt drives the app to | `.inactive` (never `.background`) | resign-active (no `.background` phase exists) | `.inactive` (assumed iOS-equivalent; validation deferred — no hardware) |
| App-switcher snapshot captured at | `.background` | n/a (no foreground snapshot) | assumed iOS-equivalent; validation deferred — no hardware |
| Embedded in-app auth view available | **no** | **yes** (`LAAuthenticationView` macOS 12+; SwiftUI `LocalAuthenticationView` macOS-only; `LARight.authorize(in:)` macOS 13+) | **no** |

The asymmetry is the heart of the design: iOS has an unambiguous `.background` signal but no
embedded auth view; macOS has no `.background` signal but **does** have embedded, in-window
authentication. Each platform uses what it actually offers.

## 2. Principles

1. **Separate the concerns.** Cosmetic privacy, session lock, and per-operation auth are three
   independent subsystems with no shared overloaded state.
2. **Lock is an explicit state**, owned by one controller — never inferred from blur.
3. **Never disambiguate the lifecycle with a heuristic.** Lock reacts only to *genuine* away
   events expressed in each platform's unambiguous signal; an authentication UI must never
   produce a false away event.
4. **On macOS, authentication is presented in-app** (embedded, non-resigning), so a genuine
   app-switch is distinguishable from authentication *by construction*.
5. **The app-unlock authentication is never reused for key use.** The authentication that
   unlocks the app must not later authorize a private-key operation (signing, decryption,
   certification, revocation, or a key-expiry change); each such operation authenticates on its
   own. This is a narrow separation
   between the app-unlock gate and key use — **not** a blanket rule that every workflow
   re-authenticates, and not the headline property to validate. A single coherent user action
   that spans several keys (e.g. an auth-mode switch that re-wraps every key) still authenticates
   once for that action, exactly as today.
6. **"Immediately" keeps its literal meaning** on every platform. We remove the ambiguity at
   its source rather than redefining the security setting.

## 3. The three subsystems

### A. Cosmetic privacy cover
A pure, opaque overlay shown whenever the app is not in the foreground. It exists only to keep
sensitive content out of the app-switcher snapshot and shoulder-surfing while away. It has
**zero** coupling to authentication: it never schedules a resume, never clears content, never
inspects prompts, never reads grace. It may briefly appear behind an iOS system biometric
sheet — that is cosmetic and harmless.

### B. `AppLockController` — the lock state machine
An explicit `@Observable @MainActor` state machine and the **single source of truth** for lock:

```
        ┌─────────────┐  away event + interval elapsed (or interval == 0)
        │  unlocked   │ ─────────────────────────────────────────────► ┌──────────┐
        │             │  · screen-lock (macOS) · explicit "Lock Now"     │  locked  │
        └─────────────┘ ◄─────────────────┐                             └────┬─────┘
              ▲                            │ auth success                     │ user/auto
              │ within interval            │ (records lastAuthenticationDate, │ initiates
              │ (no lock)                  │  hands off LAContext to          ▼ unlock
              │                            │  ProtectedData)             ┌─────────────┐
              └────────────────────────────┴─────────────────────────── │ unlocking   │
                                                                          └─────────────┘
```

It owns: the auto-lock interval, the away/idle bookkeeping, the protected-data relock on
entering `locked`, and the authenticated-`LAContext` handoff on reaching `unlocked`. It
subsumes the resume / grace / blur / settle responsibilities currently spread across
`AppSessionOrchestrator` and the gate.

### C. Decoupled operation authentication
Per-operation private-key biometrics are independent of lock. On macOS they are presented
in-app (§6–§7); on iOS/iPadOS/visionOS they use the system biometric. Because lock no longer
reacts to `.active`, an operation prompt can never trigger a lock evaluation.

## 4. Lock model

**Cover ≠ Lock.** Leaving the foreground *covers* content immediately (cosmetic). The app
*locks* — clears decrypted content and requires re-authentication — only after the **auto-lock
interval** elapses following an away event, or on screen-lock / explicit "Lock Now". The
current "grace period" setting becomes this auto-lock interval; **"Immediately" (0) means lock
as soon as the away event occurs**, on every platform. (Decided: the existing grace setting is
reused as the unified auto-lock interval for now; a separate macOS-specific setting is an optional
future study.)

"Away event" and why no gate is needed, per platform:

- **iOS / iPadOS / visionOS** — away event = `ScenePhase.background`. The system biometric only
  produces `.inactive`, never `.background`, so it is never an away event. On the next
  `.active`, lock is evaluated **only if** a real `.background` occurred since the last active
  state. "Immediately" locks on genuine backgrounding, unambiguously.
- **macOS** — away event = genuine app-resign (`NSApplication.didResignActiveNotification`) ∪
  screen-lock (`com.apple.screenIsLocked` via `DistributedNotificationCenter`) ∪ explicit
  "Lock Now". Because all macOS authentication is presented in-app and **does not resign the
  app** (§6–§7), the only thing that resigns the app is a real app-switch. So "Immediately"
  genuinely locks on app-switch with no false trigger from an auth UI.

This is the key result: the disambiguation problem is dissolved — on iOS by keying off the
unambiguous `.background`; on macOS by ensuring authentication never resigns the app.

## 5. Per-platform user experience

### iOS / iPadOS / visionOS
- **Cosmetic cover** when not active.
- **Lock screen**: a custom opaque lock surface (lock glyph; Face ID / Touch ID / Optic ID).
  The biometric is **auto-invoked** when the lock screen appears; a retry affordance and the
  existing biometrics-locked-out messaging are preserved.
- The system biometric sheet is acceptable here because lock keys off `.background`.
- **visionOS follows the iOS direction by decision** (custom lock surface + auto-invoked Optic ID).
  No visionOS hardware is currently available, so its behavior is assumed iOS-equivalent and marked
  **unvalidated** (on-device confirmation deferred) rather than separately designed.

### macOS
- **Cosmetic cover** on resign (optional/visual).
- **Lock screen** rendered **in-window** with embedded authentication (§6). Standard-mode and
  biometrics-unavailable fallback follows the §6.2 decision: an in-app password field if it can be
  done safely through public APIs, otherwise biometric-only on macOS for this flow.
- **Sensitive settings flows** (App Access Protection change; auth-mode switch / key rewrap)
  use **dedicated explanatory pages** (§6.2) with the authentication control hosted inline.

## 6. macOS in-app authentication

### 6.1 Mechanism
Use the macOS-only embedded APIs so authentication renders inside the app's own window. The
**chosen primary direction** (decided) is `LAAuthenticationView` + `LAContext`: it stays on the
same LocalAuthentication / `LAContext` path the app already uses and only changes the
*presentation* on macOS.

- `LAAuthenticationView` (NSView, macOS 12+): pair it with an `LAContext`. When
  `evaluatePolicy` or `evaluateAccessControl` is called on that context, "the UI will be
  presented using this view rather than using the standard authentication alert." **This is the
  path validated first (P0).**
- `LARight.authorize(localizedReason:in:completion:)` (macOS 13+) is a **secondary fallback**,
  considered only if the primary cannot meet a specific need; it is a different (authorization-
  rights) model and is **not** the path to validate first.

Because the UI renders in-window, the app **does not resign active** for authentication, which
is what makes the macOS lock model in §4 sound.

Supported inline policies are biometric / Apple-Watch only
(`deviceOwnerAuthenticationWithBiometrics`, `…WithCompanion`, `…WithBiometricsOrCompanion`, and
`deviceOwnerAuthentication` for convenience). There is no inline passcode entry, so:

### 6.2 In-app password fallback and explanatory pages
- **Password fallback (decided direction).** *Preferred:* pair the inline biometric with an
  **in-app password / login-password field** on the same surface (Passwords-style) for Standard
  mode and the biometrics-unavailable / locked-out cases. *Accepted fallback (pre-approved):* if a
  safe in-app password path is **not** achievable through public APIs, the Standard-mode password
  fallback is **removed on macOS for this flow** — these protected / authenticated operations then
  require biometric authentication on macOS (no password fallback). Which outcome applies is a P0
  validation item; both are pre-approved. See §9 for the security consequence.
- **Explanatory pages for sensitive changes.** App Access Protection changes and auth-mode
  switches present a dedicated page showing the consequences, requirements, and preflight
  checks (e.g. "no backup exists", "biometrics unavailable", "this re-wraps all keys") with the
  authentication control hosted inline on that page — replacing the detached popup and
  improving the failed-requirement / unavailable-mode UX.

## 7. Per-operation authentication design (macOS)

Per-operation authentication applies to **private-key operations** — the `PGPPrivateOperationKind`
set. Today five are live: the routine message operations **signing, decryption, certification** and
the key-maintenance operations **revocation and key-expiry changes**, each authenticating on its own
exactly as today; the sixth case, **binding refresh** (`refreshBinding`), is defined but **not yet
implemented**. (In the custody model the signing-role operations resolve to the Secure Enclave
**digest-signing** primitive and decryption to **key agreement**.) Unsigned standalone encryption — recipient-key or password-protected — does not touch the
private-key operation router, the Secure Enclave, or private-key authentication; an encrypt-and-sign
operation authenticates only for its **signing** step. What changes on macOS is only the
*presentation*: the per-operation biometric renders **in-app** (§6, §8) instead of through the
detached system sheet. (An auth-mode switch / key re-wrap is a single user action and authenticates
once for that action even though it touches every key — see §2, principle 5; its in-app
presentation and explanatory page are covered in §6.2.)

1. Create a fresh `LAContext`; pair it with an in-window `LAAuthenticationView`.
2. `context.evaluateAccessControl(accessControl, operation:, localizedReason:)` — the biometric
   renders **inline** and authenticates *that operation's* access control.
3. Perform the Secure Enclave operation with **that same context**:
   - Software path (CryptoKit): `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:,
     authenticationContext: ctx)` — CryptoKit Secure Enclave keys accept `authenticationContext`
     (SDK-verified).
   - Custody path: load the `SecKey` with `kSecUseAuthenticationContext: ctx`.

Properties:
- **The app-unlock authentication is not what authorizes a private-key operation.** Each
  private-key operation authenticates on its own context, which authorizes that operation and is then
  discarded; the context that unlocked the app is never reused to authorize signing, decryption,
  certification, or any other private-key operation. This is the narrow rule from §2 (principle 5) — it does **not** claim a single
  user action can never cover several keys, and it is not the property the PoC exists to prove.
- **No detached prompt.** Step 2 is the only authentication UI and it is in-window, so the app
  does not resign — preserving "Immediately".
- The off-main execution of the Secure Enclave operation and all memory zeroization are
  unchanged; only a non-secret `LAContext` crosses the actor boundary.

## 8. The `AuthenticationPresenting` abstraction

Per-operation and sensitive-flow authentication route through an injected protocol so the
private-key services do not depend on platform UI:

- **macOS implementation** hosts the inline `LAAuthenticationView` in the main window, runs
  `evaluateAccessControl` (or `evaluatePolicy` for unlock) on a fresh `LAContext`, and returns
  the authenticated context (or an authentication error).
- **iOS / iPadOS / visionOS implementation** is a pass-through: it returns a plain `LAContext`
  and lets the Secure Enclave operation present the system biometric (harmless — lock keys off
  `.background`).

The private-key services (`PrivateKeyAccessService`, custody bridges) call the presenter for
the access control + operation, then run the existing off-main Secure Enclave op with the
returned context. **Architectural implication:** per-operation crypto becomes *UI-coordinated*
on macOS — it must `await` a main-actor inline presentation before the off-main op. This is the
principal structural change and is validated by the P0 PoC (see the companion plan).

## 9. Security model preservation

This redesign must preserve every current invariant (see [SECURITY.md](SECURITY.md) §4–§5, §10):

- ProtectedData relock is **fail-closed**; the authenticated `LAContext` handoff to protected
  domains happens **only on unlock**, and is never reused to authorize a private-key operation.
- Grace / auto-lock **fails closed** (unavailable settings snapshot → immediate authentication).
- The boot-authentication early-readable exception is unchanged.
- Standard vs High-Security `LAPolicy` selection and the SE access-control flags are unchanged.
- The `DecryptionService` Phase 1 / Phase 2 boundary is unchanged.
- The narrow unlock-vs-key-use separation is preserved: the app-unlock authentication is never
  reused to authorize a private-key operation, and private-key operations authenticate on their
  own (§2, principle 5). This is unchanged from today and is **not** broadened into a blanket
  per-operation re-authentication rule.
- No secret logging; zero network.
- **macOS Standard-mode fallback (accepted consequence).** If P0 finds no safe public-API in-app
  password path, macOS drops the Standard-mode *password* fallback for this in-app authenticated
  flow and requires biometrics on macOS for these operations. This is a deliberate, **macOS-only**
  presentation-layer restriction; the Secure Enclave access-control flags are unchanged, and
  iOS / iPadOS / visionOS keep the system passcode fallback. If this path is taken, SECURITY.md §4
  is updated to record the macOS deviation.

Red-line files touched by the implementation (`AppSessionOrchestrator`, `Sources/Security/
ProtectedData/*`, `AuthenticationManager`, `SecureEnclaveManager`, entitlements) require
human security review per SECURITY.md §10.

## 10. Tracing

The DEBUG authentication trace facility (`AuthLifecycleTraceStore`, gated by
`CYPHERAIR_DEBUG_AUTH_TRACE`) is **retained throughout the transition**. Its trace points are
re-targeted from the old internals (gate / union snapshot / shield) to the new lock-state
transitions, cover events, away/lock triggers, and the in-app authentication flow. The ability
to verify the real on-device and macOS authentication flow must never be lost during the
migration; a lock-state trace persists even after the old machinery is deleted.

## 11. macOS single-window simplification

The standalone macOS `Settings { }` scene is removed so macOS has a single window/surface like
the other platforms (it is otherwise a second lifecycle/auth surface with its own
`.settingsSceneProxy` protected-settings mode and a second shield host). Settings move into the
main window using the same route the other platforms already use, with Cmd-, preserved via a
settings command. Details and the affected UI tests are in the companion plan.

---

*This is a proposal. It does not change shipped behavior until the phases in the companion
[Technical Plan & Validation](AUTH_LIFECYCLE_REDESIGN_PLAN.md) are implemented and reviewed.*
