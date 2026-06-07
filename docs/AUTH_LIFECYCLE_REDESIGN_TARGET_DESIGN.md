# Authentication / Privacy / Lifecycle Redesign — Target Design

> Status: Draft target design. This document describes a **proposed end state** and does **not**
> describe current shipped behavior. Shipped behavior remains as documented in
> [SECURITY.md](SECURITY.md) §4–§5 and [PRD.md](PRD.md) §4.9 until the redesign lands.
> Date: 2026-06-07.
> Purpose: Define the **target** architecture and user experience for CypherAir's app-lock,
> privacy-cover, and authentication-presentation flow across iOS, iPadOS, macOS, and visionOS.
> This document is intentionally narrow: it states *what the end state is*, not how to migrate to
> it. Migration phasing, sequencing, and per-component technical detail live in the companion roadmap.
> Audience: Swift implementers, security reviewers, architecture reviewers, product, test owners, AI coding tools.
> Companion: [Migration Roadmap](AUTH_LIFECYCLE_REDESIGN_ROADMAP.md) (phases, PoC results, seam inventory, tests).
> Companion current-state references: [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md),
> [PRD.md](PRD.md), [TDD.md](TDD.md), [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md).
> Update triggers: a change to the lock-state model, the per-platform away-event rules, the macOS in-window
> authentication-presentation model, the per-operation authentication posture, or the two-subsystem boundary.

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
evaluating those flags when the key is used — it is an **access-control authorization**
(`LAContext.evaluateAccessControl` in the target, threaded into the SE operation), **not** a top-level
`evaluatePolicy`.

The terms **"Standard Mode"** and **"High Security"** name only subsystem **B** (`AuthenticationMode`). The
app-session subsystem's change on macOS (dropping its passcode-fallback policy) is **never** described as
"Standard Mode removal."

## 2. The three subsystems

The target separates three concerns that are entangled today, with no shared overloaded state between them:

- **A. Cosmetic privacy cover.** A pure, opaque overlay shown whenever the app is not foreground-active. It
  exists only to keep sensitive content out of the app-switcher snapshot and away from shoulder-surfing. It has
  **zero** coupling to authentication: it never schedules a resume, clears content, inspects prompts, or reads a
  lock interval.
- **B. `AppLockController` — the lock state machine.** An `@Observable @MainActor` state machine and the
  **single source of truth** for lock. "Locked" is an explicit state, never inferred from a blur flag. It owns
  the auto-lock interval, the away/idle bookkeeping, the fail-closed Protected App-Data relock on entering the
  locked state, and the authenticated-`LAContext` handoff to Protected App-Data on unlock.
- **C. Authentication presentation.** The **authentication prompt itself** is presented in-window on macOS
  (§4), through an injected presentation seam, so private-key services and sensitive-settings flows do not
  depend on platform UI. This is distinct from both the cosmetic cover and the lock surface: a lock *surface*
  hosted in the window is not the same as the *authentication* being rendered in-window.

## 3. Lock model

**Cover ≠ Lock.** Leaving the foreground *covers* content immediately (cosmetic). The app *locks* — clears
decrypted content and requires re-authentication — only after the **auto-lock interval** elapses following an
away event, or on screen-lock / explicit "Lock Now."

Lock is an explicit state owned by `AppLockController`, and it reacts only to **genuine away events** expressed
in each platform's unambiguous signal:

- **iOS / iPadOS / visionOS** — away event = `ScenePhase.background`. A biometric prompt produces only
  `.inactive`, never `.background`, so it is never an away event.
- **macOS** — away event = genuine app-resign (`NSApplication.didResignActiveNotification`) ∪ screen-lock ∪
  explicit "Lock Now." Because all macOS authentication is presented **in-window** and does not resign the app
  (§4), the only thing that resigns the app is a real app-switch.

**"Immediately" (interval 0) means lock on the away event**, literally, on every platform. There is no
heuristic disambiguation of the lifecycle: the target removes the ambiguity at its source.

### Verified platform constraints (the asymmetry this design is built on)

| Fact | iOS / iPadOS | macOS | visionOS |
|---|---|---|---|
| Biometric prompt drives the app to | `.inactive` (never `.background`) | resign-active (no `.background` phase exists) | `.inactive` (assumed iOS-equivalent; unvalidated — no hardware) |
| App-switcher snapshot captured at | `.background` | n/a (no foreground snapshot) | assumed iOS-equivalent; unvalidated — no hardware |
| Embedded in-window auth view available | **no** | **yes** (`LAAuthenticationView`) | **no** |

iOS has an unambiguous `.background` signal but no embedded auth view; macOS has no `.background` signal but
**does** have embedded, in-window authentication. Each platform uses what it actually offers.

## 4. macOS authentication model (in-window local biometric)

On macOS, **the authentication itself is presented in-window** — the biometric prompt renders inside the app's
own window via `LAAuthenticationView` paired with the `LAContext` whose `evaluatePolicy` / `evaluateAccessControl`
is shown in that view. There is **no detached system authentication sheet** on macOS for any of these flows.
Because the prompt renders in-window, the app does not resign for authentication, which is what makes the macOS
lock model in §3 sound.

- **Authentication is local biometric (Touch ID).** macOS authentication uses local biometric authentication
  (`deviceOwnerAuthenticationWithBiometrics`). Apple Watch / companion authentication is **not** part of this
  model.
- **In-window is the only macOS authentication path** — there are no system-sheet exceptions. It covers app
  unlock, every private-key operation (including key generation and import, certification, revocation,
  key-expiry changes), the sensitive settings flows, and the Local Data Reset confirmation authentication.
- **macOS has no private-key mode choice.** The "Standard / High Security" selection (subsystem B) is removed on
  macOS: macOS private-key operations are biometric-only by construction (the high-security access-control
  flag set), authorized by the SE access-control flags plus an in-window-authenticated `LAContext`.
- **macOS has no app-session passcode-fallback option.** The app-session "App Access Protection" choice
  (subsystem A) is biometric-only on macOS — the device-passcode-fallback policy is not offered.
- **The Secure Enclave Custody path** (hidden / test-only; see [SECURITY.md](SECURITY.md) §3) follows the same
  in-window principle through its own Keychain authentication-context seam when it is productized; it is not a
  shipped surface and introduces no permanent exception to the in-window-only rule.

## 5. iOS / iPadOS / visionOS authentication model

The existing platform authentication model is **preserved, unchanged**. The biometric prompt is the system
prompt; lock keys off `.background`, so the prompt's transient `.inactive` is never an away event. The lock
surface is a custom opaque screen with the biometric auto-invoked when it appears, preserving the retry and
biometrics-locked-out messaging. visionOS follows the iOS direction by decision; with no hardware available its
behavior is an iOS-equivalent assumption tracked as **unvalidated**, not a separate design.

## 6. Security model preservation

The redesign preserves every current invariant (see [SECURITY.md](SECURITY.md) §4–§5, §10):

- Protected App-Data relock is **fail-closed**; the authenticated `LAContext` handoff to protected domains
  happens **only on unlock** and is never reused to authorize a private-key operation.
- Auto-lock **fails closed** (an unavailable settings snapshot → immediate authentication).
- The boot-authentication early-readable exception is unchanged.
- The two authentication subsystems (§1) stay distinct; the app-unlock context is confined to app-session /
  Protected App-Data post-auth flows and is never routed into a private-key operation.
- The `DecryptionService` Phase 1 / Phase 2 boundary is a permanent invariant.
- The macOS biometric-only model **preserves the existing backup gate as-is** — at least one private-key backup
  must exist (the shipped account-level `hasBackup` / `backupRequired` rule) before keys move to the biometric-only
  flag set with no passcode fallback; the redesign neither adds a per-key rule nor weakens it.
- No secret logging; zero network.

One change is **intended and deliberate**, recorded here and in [SECURITY.md](SECURITY.md) §4: on macOS the
**access-control model changes** — private-key keys move to the biometric-only flag set and the app-session
root secret is re-protected to the biometric-only flag set (§4). This is a model change, not an invariant being
"preserved unchanged," and the access-control flags are security-critical (human review required).

## 7. What the target does not contain

The end state explicitly does **not** include the following (each exists today and is removed during migration):

- The `AuthenticationShield*` overlay (coordinator / host / overlay view).
- `PrivacyScreenLifecycleGate`, the union prompt snapshot, and the post-prompt "settle window."
- The overloaded `isPrivacyScreenBlurred` signal serving both cosmetic privacy and lock inference.
- macOS detached system-sheet authentication (replaced by in-window authentication).
- The macOS private-key `Standard` mode and its Standard/High mode-switch UI.
- The macOS app-session device-passcode-fallback policy option.
- The standalone macOS `Settings { }` scene (a second lifecycle/auth surface).

Local Data Reset and its post-reset restart gate are **not** part of this removed set — they remain, with only
their macOS authentication presentation moving in-window and their surface following the single-window change.

---

*This is a target-design proposal. It does not change shipped behavior until the phases in the companion
[Migration Roadmap](AUTH_LIFECYCLE_REDESIGN_ROADMAP.md) are implemented and reviewed.*
