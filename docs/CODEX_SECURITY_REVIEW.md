# Codex Security Review — Verified Follow-ups

> Purpose: Track Codex cloud security-review findings that, after manual verification
> against the current code, are **real and worth acting on**. Confirmed false positives
> / by-design items are closed directly in Codex and are not duplicated here.
> Source: Codex cloud security review (`chatgpt.com/codex/cloud/security`).
> Verified against: branch `main`, HEAD `40ea2fa`. Code is referenced by file + symbol
> name (not line number) so references stay valid as the tree moves.
> Convention: keep each entry short — impact in 1–2 lines, the current code locations,
> and the Codex link so the finding can be closed once fixed.

**Status:** `open` = verified, not yet fixed · `in-progress` · `fixed` (then close in Codex). Findings judged false-positive / by-design are closed directly in Codex and never recorded here — this file only holds items we intend to fix.

---

## [open] Selector discovery surfaces unauthenticated User IDs

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/f6c9737226248191a651f043b8b6f146 — severity **low**
- **Verified real & reachable.** A crafted public certificate with a bare (un-self-signed)
  User ID survives import and appears in the contact certificate-signature UI looking
  identical to a validly-bound User ID. The app treats unauthenticated == normal at all
  three layers: data (no validity field), UI (only `Primary` / `Revoked` badges), and
  operation (`certify` succeeds with no binding check).
- **Impact (low, bounded):** A user can be socially engineered into producing / sharing a
  certification for an identity the key owner never bound. No in-app trust propagation
  (certifications are crypto-only); recipient selection is unaffected (keyed by key, not
  by these selectors). Real harm requires an external web-of-trust consumer.
- **Current code:**
  - `pgp-mobile/src/keys/selector_discovery.rs` — `discover_certificate_selectors` (enumerates every raw User ID packet)
  - `pgp-mobile/src/keys.rs` — `current_user_id_occurrence_state` (bare packet → `primary=false, revoked=false`), `find_user_id_by_selector` (validates occurrence index + bytes only, no binding), `struct DiscoveredUserId`
  - `Sources/Models/UserIdSelectionOption.swift` — no validity / authenticated field
  - `Sources/Services/CertificateSelectionCatalogMapper.swift` — forwards fields unchanged
  - `Sources/App/Contacts/ContactCertificateSignaturesView.swift` — User ID rows render only `Primary` / `Revoked` badges
- **Fix idea:** Add a `hasValidSelfBinding` (authenticated) flag to `DiscoveredUserId` →
  `UserIdSelectionOption` — the per-occurrence binding is already computed in Rust. Surface
  it in the UI ("not authenticated by this key") and/or gate `certify`. `DiscoveredUserId`
  is a `#[uniffi::Record]`, so this is a UniFFI-visible, multi-layer change (regenerate
  bindings + rebuild XCFramework + both-profile tests). While reworking this UI, also
  consider surfacing signer-key expiry/revocation status alongside User-ID binding
  validity — a related OpenPGP validity-display improvement on the same screen.

---

## [open] Production auth bypassable via ungated UI-test defaults key

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/85c8b620e92c8191ab484e11a5cf4143 — Codex severity **medium** · assessed **real, fix soon (highest priority in this batch)**
- **Verified real (HEAD 40ea2fa).** `AuthenticationManager.evaluate` and `evaluateAppSession` both return success the moment the `UserDefaults` bool `com.cypherair.preference.uiTestBypassAuthentication` is true — *before* any `LAContext`, with **no** `#if DEBUG` / XCTest / launch-arg gate (only the key definition + the two reads exist in the file). Production `AppContainer.makeDefault` builds the manager on `UserDefaults.standard`; the bypass is reachable from the shipped privacy-screen resume path. Introduced in 89d44d1; the read path later broadened to `evaluateAppSession` (15820db). **Never retired** (distinct from the authMode / grace-period / theme keys that *were* migrated to ProtectedData).
- **Purpose:** UI-test (XCUITest) auth bypass so automation skips biometric prompts. `makeUITest` writes it into an isolated per-UUID defaults suite — isolation is only on the *write* side; the production *read* path trusts `.standard` unconditionally.
- **Impact (bounded):** app-session / privacy-lock + mode-switch authorization bypass only. Does **not** bypass Secure Enclave private-key unwrap/sign/decrypt/export (hardware-gated independently). Zero-network → local same-user only; precondition is writing the key into the app's `UserDefaults.standard` / container domain (sandbox + macOS TCC make this non-trivial; not demonstrated end-to-end).
- **Current code:** `Sources/Security/AuthenticationManager.swift` (`UITestPreferences.bypassAuthenticationKey`, `evaluate`, `evaluateAppSession`); `Sources/App/AppContainer.swift` (`makeDefault` → `.standard`; `makeUITest` = only writer, isolated suite).
- **Fix:** make production unable to honor the key — gate on `#if DEBUG` / `isXCTestHost` / an injected non-standard defaults suite, or never read it from `.standard` in the production manager. `Sources/Security` red-line → describe + human-review before editing (SECURITY.md §10).

## [open] Import confirmation can act on a replaced key request (regression)

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/078f49939538819195ae18333d9d130b — Codex severity **medium** · assessed **real-low (regression)**
- **Verified real (HEAD 40ea2fa); a regression.** Pre-refactor (08a6e5d^) the confirmation buttons captured the displayed request locally; the refactor routed Verify/Add through `coordinator.confirmVerified()` / `confirmUnverified()`, which dereference the **live mutable** `coordinator.request` at tap time, while `present()` blindly overwrites any pending request. Tell-tale: `onCancel` still captures locally — the asymmetry shows it's an oversight. One shared coordinator is fed by two shipped sources (cypherair:// URL import + in-app Add Contact).
- **Impact:** a second import arriving while a confirmation sheet is open can make the action apply to the newer (attacker) request → an attacker key added / marked `.verified`, which suppresses the unverified-recipient warning at encryption time. Bounded by friction (precise timing, local/deep-link delivery, user tap); contact public-key/verification metadata only (no private-key compromise, no RCE). The exact exploitable window depends on SwiftUI `.sheet(item:)` dismiss/re-present timing (unverified on a real device), but the closure-capture regression is a correctness defect regardless.
- **Current code:** `Sources/App/Contacts/ImportConfirmationCoordinator.swift` (`present()`, `confirmVerified`/`confirmUnverified` vs local-capture `onCancel`); `Sources/App/Contacts/Import/IncomingURLImportCoordinator.swift` + `AppSceneIncomingURLRouter` (URL caller); `Sources/App/Contacts/AddContactView.swift` (in-app caller); shared host in `CypherAirApp.swift`; warning suppression at `Sources/App/Encrypt/EncryptScreenModel.swift`.
- **Fix:** Verify/Add + Add-Unverified button closures should capture the **displayed** request's callbacks (from the sheet closure parameter), matching `onCancel` and the pre-refactor pattern; and/or make `present()` refuse/queue while a request is pending. Add a regression test (`present(A); present(B);` then the sheet-bound verify action).

## [open] Unbounded armored text import can exhaust memory

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/792eaf5ba0488191a3b45e9651c6162c — Codex severity **medium** · assessed **real-low (one sub-claim is a false positive)**
- **Verified — text-mode real (HEAD 40ea2fa).** Decrypt "Import .asc File" and Verify "Import Signed File" read the chosen file with `Data(contentsOf:)` with **no size cap**, then make a full UTF-8 `String` copy, retaining both (plus the bound input → triple retention). A very large attacker-supplied .asc/plaintext file → memory exhaustion → app crash. Reachable from shipped Decrypt/Verify UI (default config enables import; only the tutorial sandbox disables it). Trigger: user taps the import button and selects a huge file.
- **File-mode sub-claim = FALSE POSITIVE (note when closing).** The report's "NSNumber.intValue 32-bit truncation bypasses the 256 KiB inspection guard" does not hold: on the macOS 26.5 SDK Swift's `intValue` is a 64-bit `Int` (only `int32Value` truncates, unused here), so the guard is sound; file *decryption* is streamed anyway. (Codex itself could not reproduce it.)
- **Impact:** local, user-mediated, availability-only crash of the victim's own process. No confidentiality/integrity/key/RCE; zero-network (no remote/zero-click).
- **Current code:** `Sources/App/Decrypt/DecryptScreenModel.swift` (`textCiphertextFileImportAction`); `Sources/App/Sign/VerifyScreenModel.swift` (`cleartextFileImportAction`); `Sources/App/Common/TextImport/ImportedTextInputState.swift` (retains rawData + textSnapshot).
- **Fix:** cap pre-read size (read `attributes[.size] as? UInt64` and reject oversized before `Data(contentsOf:)`, consistent with EncryptionService / DiskSpaceChecker); avoid retaining Data + two String copies.

## [open] Unbounded SKESK fallback in password decrypt (latent — not shipped-reachable)

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/5dfacb1e55cc81918f142034127840ff — Codex severity **medium** · assessed **real-low, latent**
- **Verified real at the Rust layer, NOT reachable in the shipped app (HEAD 40ea2fa).** `password::decrypt` loops over every SKESK collected by `collect_message_context` (unbounded `Vec`, no cap); each candidate triggers a full `decrypt_with_helper` (`read_to_end` of the whole payload into memory) *before* the integrity/auth failure is detected, and those errors are deferred so the loop continues. N valid-looking-but-failing SKESKs → ~N full-payload decrypts → CPU/memory amplification. The deferral is an intentional interop fix (6d9334a); only the bound is missing.
- **Reachability:** `PasswordMessageService` is service-only — no shipped UI/route/ScreenModel consumes it (no AppRoute case). No end-user action reaches this today.
- **Current code:** `pgp-mobile/src/password.rs` (`collect_message_context`, `decrypt`); `pgp-mobile/src/decrypt.rs` (`decrypt_with_helper`, `decrypt_with_fixed_session_key_detailed`); exposed via `pgp-mobile/src/lib.rs` `PgpEngine::decrypt_with_password`; wrapped by `Sources/Services/PasswordMessageService.swift` (no UI consumer).
- **Fix (do before any password-message route ships):** bound the SKESK / candidate-attempt count and/or add a payload-size/work budget separating cheap rejects from full-payload retries.
