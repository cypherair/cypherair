# Authentication / Privacy / Lifecycle Redesign — Target Design

> Status: **Implemented — describes current shipped behavior** (P5 doc cutover, 2026-06-11). All
> phases are on `main`: P1 (lock foundation; PR #472), P2 (macOS single-window unification;
> PR #475), P3′ (auth-lifecycle completion on the system sheet — explicit `.authenticating` rule,
> single-prompt key expiry, and the uniform operation-prompt-session enrollment), P4 (the
> opaque lock surface, shared by every platform), and P5 (this cutover; [SECURITY.md](SECURITY.md)
> §4–§5 and [PRD.md](PRD.md) §4.9 now state the same model). The original P3 — the macOS in-window
> authentication cutover — was **retired** (PR #491 closed unmerged): macOS 27 denies embedded
> LocalAuthentication UI to non-Apple-signed processes, and the post-authentication stalls that
> motivated in-window presentation no longer reproduce under the P1 lock model on macOS 27
> (see the [Migration Roadmap](AUTH_LIFECYCLE_REDESIGN_ROADMAP.md) §1 addendum). The redesign's goal
> changed **from a fix to an architecture improvement**: authentication presentation stays with the
> system, and the shipped result is the explicit, simple, maintainable lock-state model described here.
> Date: 2026-06-11 (re-scoped 2026-06-10; originally 2026-06-07).
> Purpose: Define the architecture and user experience for CypherAir's app-lock,
> privacy-cover, and authentication flow across iOS, iPadOS, macOS, and visionOS.
> This document is intentionally narrow: it states *what the end state is*, not how it was migrated
> to. Migration phasing, sequencing, and per-component technical detail live in the companion roadmap.
> Audience: Swift implementers, security reviewers, architecture reviewers, product, test owners, AI coding tools.
> Companion: [Migration Roadmap](AUTH_LIFECYCLE_REDESIGN_ROADMAP.md) (phases, PoC results and their
> macOS 27 invalidation, tests).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [PRD.md](PRD.md), [TDD.md](TDD.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: a change to the lock-state model, the per-platform away-event rules, the
> authentication-presentation posture, the per-operation authentication posture, or the
> two-subsystem boundary.

## 1. Two distinct authentication subsystems (read first)

CypherAir has **two separate authentication subsystems**. They protect different things, use different
LocalAuthentication mechanisms, and are configured independently. The redesign keeps them distinct, and this
document never conflates them.

**A. App-session authentication — `AppSessionAuthenticationPolicy`.**
Unlocks the app and authorizes the Protected App-Data root secret (and, through it, the protected domains). It
is the "App Access Protection" setting. Its authentication mechanism is a **policy evaluation**
(`LAContext.evaluatePolicy`). Its policies map to access-control flags on the root-secret Keychain item.

**B. Private-key authentication — `AuthenticationMode`.**
Authorizes Secure Enclave **private-key operations** (signing, decryption, certification, revocation,
key-expiry changes). It is the "Private Key Protection" setting. The mode determines the **`SecAccessControl`
flags on the SE wrapping key** (created via `createAccessControl()`). Per-operation authorization is the SE
evaluating those flags when the key is used.

**Both subsystems keep both of their user-selectable postures, on every platform.** The app-session
choice between `.userPresence` (biometry / Apple Watch / device password fallback —
`LAPolicy.deviceOwnerAuthentication`) and `.biometricsOnly`
(`LAPolicy.deviceOwnerAuthenticationWithBiometrics`), and the private-key choice between Standard
(`[.privateKeyUsage, .biometryAny, .or, .devicePasscode]`) and High Security
(`[.privateKeyUsage, .biometryAny]`), are permanent product features. The previously planned macOS
biometric-only pinning and its two one-time migrations are **withdrawn**: their premise — that the
in-window authentication view offers no password entry — became moot when in-window presentation was
retired. There is **no access-control model change** anywhere in this redesign.

## 2. The three subsystems

The target separates three concerns that were entangled before P1, with no shared overloaded state between them:

- **A. Cosmetic privacy cover.** A pure, content-obscuring overlay shown whenever the app is not
  foreground-active. It exists only to keep sensitive content out of the app-switcher snapshot and away from
  shoulder-surfing. It has **zero** coupling to authentication: it never schedules a resume, clears content,
  inspects prompts, or reads a lock interval. (Shipped in P1.)
- **B. `AppLockController` — the lock state machine.** An `@Observable @MainActor` state machine and the
  **single source of truth** for lock. `lockState` is explicit — `.locked`, `.authenticating`
  ("unlocking"), `.unlocked` — never inferred from a blur flag. It owns the auto-lock interval, the
  away/idle bookkeeping, the fail-closed Protected App-Data relock on entering the locked state, and the
  authenticated-`LAContext` handoff to Protected App-Data on unlock. (Shipped in P1; the `.authenticating`
  away-event rule below shipped in P3′.)
- **C. Authentication presentation.** The authentication prompt is the **system authentication sheet** —
  LocalAuthentication's standard presentation — on every platform. The app does not host the prompt
  inside its own window. (In-window presentation via `LAAuthenticationView` /
  SwiftUI `LocalAuthenticationView` is **abandoned**, §7.)

## 3. Lock model

**Cover ≠ Lock.** Leaving the foreground *covers* content immediately (cosmetic). The app *locks* — clears
decrypted content and requires re-authentication — only after the **auto-lock interval** elapses following an
away event, or on screen-lock / explicit "Lock Now."

Lock is an explicit state owned by `AppLockController`, and it reacts only to **genuine away events** expressed
in each platform's unambiguous signal:

- **iOS / iPadOS / visionOS** — away event = `ScenePhase.background`. A biometric prompt produces only
  `.inactive`, never `.background`, so it is never an away event.
- **macOS** — away event = genuine app-resign (`NSApplication.didResignActiveNotification`) ∪ screen-lock ∪
  explicit "Lock Now," **filtered by the `.authenticating` rule below**: the system authentication sheet
  may transiently resign the app, and that resign is by definition not the user going away.

### The `.authenticating` rule (the architectural core of P3′)

An app-driven authentication window is **explicit state, never lifecycle inference**:

- While `AppLockController.lockState == .authenticating` (an app-session unlock is in flight), and while an
  **operation-prompt session** is open (the session counter mirrored from
  `AuthenticationPromptCoordinator`), a macOS app-resign attributable to the authentication presentation is
  **not** an away event.
- **The uniform enrollment rule:** every user action that can present an authentication sheet while the app
  is unlocked runs inside **one operation-prompt session for its full duration** — private-key operations
  (through the shared unwrap seam), key generation and import, key-expiry modification, the mode-switch
  re-wrap, the App Access Protection policy change, and Local Data Reset. Enrollment is the wrapped action,
  never the prompt mechanism: privacy prompts (`withPrivacyPrompt`, the subsystem-A evaluation bracket)
  deliberately do **not** count toward the lock controller's mirror — a flow whose prompt is a privacy
  evaluation enrolls by wrapping its whole action in an operation-prompt session.
- Genuine away events **still win during authentication**: screen-lock and "Lock Now" supersede an
  in-flight authentication immediately and fail closed (the in-flight unlock result is discarded;
  protected data relocks). A plain app-resign during an **operation-prompt session** is ambiguous
  (the prompt's own resign vs. a real app switch), so it is **decided at the session's end**: still not
  foreground-active → the away is processed then (normal grace semantics, fail-closed relock); returned →
  it was the prompt's own resign and is discarded. A long-running enrolled action (e.g. key generation)
  extends that deferral window by design — a user who leaves and stays away is locked at the action's
  end, not mid-action, and the cosmetic cover hides content for the whole absence.
- This rule is a designed, documented, tested property of the state machine — the successor of the P1-interim
  resign-suppression guard, not a heuristic settle window. It makes the lock model correct **independent of
  how the system presents authentication or how long the user takes**, on every macOS version.

**"Immediately" (interval 0) means lock on the away event**, literally, on every platform.

### Verified platform constraints (the asymmetry this design is built on)

| Fact | iOS / iPadOS | macOS | visionOS |
|---|---|---|---|
| Biometric prompt drives the app to | `.inactive` (never `.background`) | may transiently resign-active (no `.background` phase exists) | `.inactive` (assumed iOS-equivalent; unvalidated — no hardware) |
| App-switcher snapshot captured at | `.background` | n/a (no foreground snapshot) | assumed iOS-equivalent; unvalidated — no hardware |
| Embedded in-window auth view usable | no | **no** — macOS 27 denies embedded LA UI to non-Apple-signed processes (LA -1007); see roadmap §1 addendum | no |

iOS has an unambiguous `.background` signal; macOS instead gets the explicit `.authenticating` rule. Each
platform uses what it actually offers.

## 4. macOS authentication model (system-presented, both postures)

On macOS, authentication is presented by the **system authentication sheet** for both subsystems. There is no
app-hosted prompt:

- **App-session unlock and the Local Data Reset confirmation** evaluate the configured app-session policy
  (`.userPresence` → `LAPolicy.deviceOwnerAuthentication`, which offers Touch ID, a paired Apple Watch, or
  the user's password; `.biometricsOnly` → `LAPolicy.deviceOwnerAuthenticationWithBiometrics`).
- **Private-key operations** authorize per-operation against the SE wrapping key's access control: the
  Secure Enclave evaluates the key's flags when the key is used, presenting the system prompt. The
  per-operation posture is intentional (one prompt per user-initiated crypto action); private-key
  authorization is outside the grace/session model.
- **Single prompt per user action is the contract.** Key-expiry modification — which unwraps with the old
  wrapping key and first-uses a new one — authenticates **once** via a system-sheet
  `evaluateAccessControl(.useKeyKeyExchange)` against the persisted mode's access control and threads that
  authenticated `LAContext` into both Secure Enclave operations (the mode-switch re-wrap pattern:
  `PrivateKeyRewrapWorkflow`); the context is confined to the one action and invalidated after (P3′
  stage 2′, shipped). Explicit pre-authentication is **not** generalized to already-single-prompt
  operations; that would be a separate, unscheduled change.
- **No mode pinning, no migrations.** Both App Access Protection options and both Private Key Protection
  modes remain selectable on macOS exactly as on iOS (§1).

## 5. iOS / iPadOS / visionOS authentication model

The existing platform authentication model is **preserved, unchanged**. The biometric prompt is the system
prompt; lock keys off `.background`, so the prompt's transient `.inactive` is never an away event. The lock
surface is a custom opaque screen with a text-only header (app name + locked-state caption) —
**one shared surface on every platform, macOS included** — with
the biometric auto-invoked when it appears, preserving the retry and biometrics-locked-out messaging (P4,
shipped). visionOS follows the iOS direction by decision; with no hardware available its behavior is an
iOS-equivalent assumption tracked as **unvalidated**, not a separate design.

## 6. Security model preservation

The redesign preserves every current invariant (see [SECURITY.md](SECURITY.md) §4–§5, §10):

- Protected App-Data relock is **fail-closed**; the authenticated `LAContext` handoff to protected domains
  happens **only on unlock** and is never reused to authorize a private-key operation.
- Auto-lock **fails closed** (an unavailable settings snapshot → immediate authentication).
- The boot-authentication early-readable exception is unchanged.
- The two authentication subsystems (§1) stay distinct; the app-unlock context is confined to app-session /
  Protected App-Data post-auth flows and is never routed into a private-key operation. The single-prompt
  key-expiry context (§4) is a **subsystem-B** context: it is created for, consumed by, and confined to that
  one private-key action, then invalidated.
- The `DecryptionService` Phase 1 / Phase 2 boundary is a permanent invariant.
- **Access-control flags are unchanged.** No key or root secret changes its `SecAccessControl` flag set
  under this redesign; the backup gate (`hasBackup` / `backupRequired`) is untouched.
- No secret logging; zero network.

## 7. What the target does not contain

The end state explicitly does **not** include the following:

- The `AuthenticationShield*` overlay (coordinator / host / overlay view) — removed (P1).
- `PrivacyScreenLifecycleGate`, the union prompt snapshot, and the post-prompt "settle window" — removed (P1).
- The overloaded `isPrivacyScreenBlurred` signal serving both cosmetic privacy and lock inference — removed (P1).
- The standalone macOS `Settings { }` scene (a second lifecycle/auth surface) — removed (P2).
- Heuristic disambiguation of authentication-driven lifecycle noise — replaced by the explicit
  `.authenticating` rule (§3, P3′).
- **In-window (app-hosted) authentication presentation.** Retired from the target on 2026-06-10 and
  **abandoned outright on 2026-06-12**: macOS 27 denies embedded LocalAuthentication UI
  (`LAAuthenticationView` and SwiftUI `LocalAuthenticationView`, both `evaluatePolicy` and
  `evaluateAccessControl`) to non-Apple-signed processes with LA error -1007, independent of the app's
  entitlements — and the shipped system-sheet model needs no in-window presentation, so the contingency
  was dropped (maintainer decision). The seam branch was deleted; the implementation record remains
  viewable in closed PR #491 and the P0 PoC in closed PR #469.

Local Data Reset and its post-reset restart gate remain, with their authentication presented by the system
sheet like every other surface.

---

*This design is fully implemented (P1–P5 on `main`) and describes current shipped behavior. The migration
record lives in the companion [Migration Roadmap](AUTH_LIFECYCLE_REDESIGN_ROADMAP.md).*
