# P0 PoC — Findings (macOS in-window authentication)

> Throwaway-branch validation record (`poc/auth-lifecycle-macos`, draft PR #469). This branch does
> **not** merge; only these findings carry back to `main` to update
> [AUTH_LIFECYCLE_REDESIGN_DESIGN.md](AUTH_LIFECYCLE_REDESIGN_DESIGN.md) /
> [_PLAN.md](AUTH_LIFECYCLE_REDESIGN_PLAN.md) and feed the P1–P7 phases.
> Updated as each P0 item is validated, deferred, or moved to a future phase, on real hardware
> (Mac + Touch ID).

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

### Item 6 — Mode-switch / rewrap under the presenter — PASS
The REAL `AuthenticationManager.switchMode` rewrap authenticates **once for the whole action** when its
authority prompt is presented in-window: a single in-window prompt for the switch even though it re-wraps
every key (exactly as today), with no resign (`resignDelta = 0`), the mode flips, and the recovery journal
ends empty (SECURITY.md §4 atomicity / crash-recovery preserved). Forward switch and restore are **separate
user-triggered single-auth steps** in the harness.
- **Production seam:** the single authority auth routes through the injected
  `localAuthenticationPolicyEvaluator`; the rewrap then reuses `lastEvaluatedContext` for every per-key SE
  op — no second prompt.
- **Deterministic proof:** `inWindowPresentCount == 1` for the whole N-key rewrap, with
  `forbidInteractionAfterPolicySuccess` (any hidden second per-key prompt would throw under
  `interactionNotAllowed` instead of silently re-prompting).
- Commit `9428e6b`. (The legacy shield had to be suppressed first — see F1.)

### Item 3 (narrow) — Custody-auth ↔ in-window compatibility — PASS
A **narrow technical-compatibility probe** (not full custody product-flow — see Deferred) confirmed an
in-window-authenticated `LAContext` is consumed by the **real custody Secure Enclave operations** with no
second prompt, for both roles:
- **Sign** (`.useKeySign`): `SystemSecureEnclaveCustodyDigestSigner` → `SecKeyCreateSignature`.
- **ECDH** (`.useKeyKeyExchange`): `SystemSecureEnclaveCustodyKeyAgreement` → `SecKeyCopyKeyExchangeResult`.

The context is threaded via **`kSecUseAuthenticationContext`** on the
`SystemSecureEnclaveCustodyKeyStore.loadKeys` query (the §3.3 production seam, DEBUG-only in the probe),
proven non-interactively (`interactionNotAllowed = true`, `resignDelta = 0`), one prompt each.
- **Scope:** reuses the real custody op code + one representative custody SE key per role; **no** OpenPGP
  router / Rust / generation service / resolver / role metadata — those self-tests/binds were the prompt
  storm that made the earlier full-flow run an invalid experiment.
- **New signal vs Item 2:** Item 2 used CryptoKit `authenticationContext:` and `.useKeyKeyExchange` only;
  this probe covers the **Security-framework `kSecUseAuthenticationContext`** path and adds `.useKeySign`.
- Commit `d3bbee0`.

## Findings / follow-ups (do not block P0)

### F1 — Legacy `AuthenticationShield` occludes and deadlocks the in-window mode-switch auth (→ P2, blocking)
The legacy `AuthenticationShield` is **not merely a cosmetic flash**. On the mode-switch path (the authority
auth is wrapped in `AuthenticationManager` → `withPrivacyPrompt`), the shield raises at **`.zIndex(10)`** —
*above* the harness's in-window `LAAuthenticationView` — and **occludes + deadlocks** the auth: the biometric
renders underneath the opaque "Authenticating…" shield, unreachable, so `evaluatePolicy` never returns and
the flow hangs. Items 1/2/5 dodged this only because they call the presenter directly, bypassing the prompt
coordinator (no shield event).

**PoC bypass (throwaway):** suppress the shield under `isPoCHarness` by resolving
`CypherAirApp.mainWindowShieldCoordinator` to `nil` (a host with a nil coordinator renders nothing). This is
safe because the **app-session unlock is owned by `.privacyScreen()` / `PrivacyScreenModifier`, not the
shield host** — unlock and the privacy blur still work; only the cosmetic shield overlay is removed.

**Consequence:** the P2 shield-**decouple** (stop the shield reacting to operation prompts) is a **functional
prerequisite** for in-window auth, not a cosmetic nicety; full shield **removal** stays P7. Commit `9428e6b`.
Track for P2.

## Deferred

### Item 3 — full custody product-flow validation — DEFERRED
The narrow **custody-auth ↔ in-window compatibility** sub-question is now **validated** (see the
**Item 3 (narrow)** entry under Validated). What remains deferred is the **full custody product-flow
validation**: Secure Enclave custody is not yet productized, so a meaningful end-to-end validation needs the
real product custody flow (generation + role-pair binding + router + metadata + revocation) combined with
the in-window model — a future task, **not** a continuation of the narrow spike.

The earlier *full-flow* harness attempt prompted repeatedly for Touch ID *during custody key generation* and
ended in a cancellation error — an **invalid experiment** (the generation + per-op flow was not understood
before wiring), reverted in `984af6c`. The narrow probe (commit `d3bbee0`) deliberately avoids that
generation/router machinery and instead exercises only the per-operation auth seam, which is why it produced
a clean signal where the full-flow attempt did not.

**Revisit** the full product-flow validation only when custody is product-shaped — alongside the in-window
auth model, not as a standalone spike.

## Architectural requirements (not PoC experiments)

### Item 4 — unlock auth is not reused for key use — REQUIREMENT (not validated by harness)
This boundary is **guaranteed by implementation / code routing**, not a runtime feasibility question,
so it is **not** a PoC harness experiment. A read-only investigation confirmed the separation is
already structurally enforced: the app-unlock `LAContext` lives only in
`AppSessionOrchestrator.pendingAuthenticatedContext` and is consumed solely by
`consumeAuthenticatedContextForProtectedData()` → ProtectedData; the private-key operation path runs
on a separate `withOperationPrompt` channel (distinct `kind=operation` vs `kind=privacy` traces) and
holds **no** reference to the app-unlock context (grep-verifiable). Recorded as a red-line requirement
in [PLAN §1 item 4 / §5](AUTH_LIFECYCLE_REDESIGN_PLAN.md) and DESIGN §2 principle 5; the redesign must
preserve it (the in-window per-operation presenter must never thread the app-unlock context into a key
operation). Verified by code structure/review, not a harness run.

## Pending
- **Item 7** — visionOS (deferred; no hardware).

## Investigations

### Other macOS auth call sites still on the system sheet (2026-06-06)
A read-only sweep of every macOS biometric trigger point found auth flows beyond the P0 items that
still show the **old detached/system sheet** today — most notably **key generation/provisioning and
import** (the SE-wrap self-ECDH prompts because no in-window `LAContext` is threaded into
`generateWrappingKey`), plus **key export/backup** and **custody generation** (self-sign). The guided
tutorial is mock-isolated (no real prompt). Full path inventory, choke-point analysis, and the
migrate-or-handle action for each are recorded in
[PLAN §8](AUTH_LIFECYCLE_REDESIGN_PLAN.md). Not fixed or validated now.

## Architecture-audit boundary (harness-only; does not merge)

The Item 3 narrow-probe harness uses the custody runtime (`ExternalP256KeyAgreementRequest`,
`SystemSecureEnclaveCustodyKeyAgreement`) from `Sources/App/PoC`, which trips two architecture-audit guards
in `CypherAir-UnitTests` (`ArchitectureSourceAuditTests`):
- **`generatedFFITypes` containment** — the generated UniFFI type `ExternalP256KeyAgreementRequest` must not
  appear in upper-layer source files.
- **`phase6ExternalKeyAgreementRuntimeContainment`** — the external P-256 key-agreement runtime must stay
  inside the FFI / Security / router-owned boundary, not `Sources/App`.

These two unit tests are therefore **red on this branch** (signed UnitTests: 1382/1384), and that is
**accepted**: the harness is DEBUG-only and **never merges** to `main`. The durable **production** seam these
guards protect is unaffected — the in-window context reaches the custody op via `kSecUseAuthenticationContext`
at `SystemSecureEnclaveCustodyKeyStore.loadKeys` (the §3.3 design target), which stays inside the Security
boundary. The probe's result (Item 3 narrow PASS) stands independently of the harness's intentional boundary
crossing; on carry-back to `main`, only the durable seam — not the harness wiring — is in scope.
