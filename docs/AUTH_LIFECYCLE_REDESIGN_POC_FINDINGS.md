# P0 PoC — Findings (macOS in-window authentication)

> Throwaway-branch validation record (`poc/auth-lifecycle-macos`, draft PR #469). This branch does
> **not** merge; only these findings carry back to `main` to update
> [AUTH_LIFECYCLE_REDESIGN_DESIGN.md](AUTH_LIFECYCLE_REDESIGN_DESIGN.md) /
> [_PLAN.md](AUTH_LIFECYCLE_REDESIGN_PLAN.md) and feed the P1–P7 phases.
> Updated as each P0 item is validated on real hardware (Mac + Touch ID).

## Validated

### Item 1 — No resign / no false lock — PASS
The in-window `LAAuthenticationView` (`LocalAuthenticationEmbeddedUI`, macOS 12+) authentication does
not resign the app (`NSApplication.isActive` stays `true`, resign count 0) and the real privacy
screen does not activate. Confirms the core thesis the macOS lock model depends on. The legacy
detached system sheet, by contrast, conflates real focus changes with auth lifecycle noise
(`resign/active +2` on focus-away/back) — the root cause the redesign removes.

### Item 5 — In-app password fallback — no in-window password field
The embedded view is biometric/companion only (`.deviceOwnerAuthentication` offers no in-window
passcode; the detached system sheet offers "Use Password" only on focus-away/back). → the macOS
Standard-mode flow for these operations will **require biometrics (drop the password fallback)**, per
the pre-approved decision. SECURITY.md §4 to be updated on carry-back.

### Item 2 — Software per-operation context consumption — PASS
A context authenticated in-window via `evaluateAccessControl(accessControl, operation:)` is consumed
by the real `SecureEnclaveManager.reconstructKey(from:authenticationContext:)` with **no second
prompt**, for a REAL decrypt and a REAL sign driven through the real `DecryptionService` /
`SigningService`. Proven deterministically with `interactionNotAllowed = true` (the op runs
non-interactively, i.e. no UI was needed). resign count 0.
- **Operation:** `.useKeyKeyExchange` for **both** decrypt and sign — the biometric-gated SE op is
  the wrapping key's self-ECDH, regardless of the OpenPGP operation.
- **Access control:** the full wrapping AC from `AuthenticationMode.createAccessControl()`
  (`[.privateKeyUsage, .biometryAny, .or, .devicePasscode]` for Standard mode) is **accepted** by
  `evaluateAccessControl` (`AC=wrappingAC`); the biometry-only fallback was not needed.
- Decrypt and sign are two distinct per-operation authentications (separate one-prompt operations).

## Findings / follow-ups (do not block P0)

### F1 — Legacy post-auth `AuthenticationShield` flashes after in-window auth succeeds (→ P2)
After a successful in-window Touch ID, the legacy post-auth `AuthenticationShield` overlay briefly
appears — a visually disruptive flash. This is an integration artifact of the **old**
lifecycle/shield machinery, not the new in-window auth UI. The redesign's P2 work
(`AppLockController`, decoupled cosmetic cover, and removing the shield's reaction to
`.active` / operation prompts) must eliminate it: a per-operation in-window auth must not trigger any
post-auth shield. Track for P2.

## Pending
- **Item 3** — custody per-operation consumption (real custody enabled on-branch).
- **Item 4** — unlock authentication is not reused for key-use operations (our routing).
- **Item 6** — mode-switch / rewrap under the in-window presenter.
- **Item 7** — visionOS (deferred; no hardware).
