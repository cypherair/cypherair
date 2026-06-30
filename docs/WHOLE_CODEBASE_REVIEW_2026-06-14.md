# Whole-Codebase Adversarial Review — 2026-06-14

> Status: Point-in-time review record (report-only).
> Scope: CypherAir at `main` (commit `8582f95`).
> Author: AI adversarial review (multi-agent fan-out + adversarial verification + maintainer-facing confirmation of high/security findings).
> Disposition: **None assigned.** This is a findings record, not a fix plan. Triage into `SR-FIX-*`/`SR-CLOSED-*` is the maintainer's call (see “Relationship to the SR-NEW backlog” below).

This review covers cryptography, security, correctness, architecture, technical debt, and test quality. It reports **only what is new or sharper** than the existing `docs/` audits (`SECURITY.md`, `CODEX_SECURITY_REVIEW*`, `PERSISTED_STATE_INVENTORY.md`), the now-retired architecture/FFI audit baselines tracked by [#502](https://github.com/cypherair/cypherair/issues/502) and [#545](https://github.com/cypherair/cypherair/issues/545), and the project memory of accepted designs.

**Out of scope (excluded by request):** generated bindings (`Sources/PgpMobile/`, `bindings/`), vendored crates (Sequoia/OpenSSL et al. — `pgp-mobile/src` *is* in scope), and `docs/archive/`.

## Method & assurance

- **Fan-out.** 22 reviewer cells, each scoped to one subsystem × dimension and seeded with the full known-findings baseline (4 open `SR-FIX`, the 11 pending `SR-NEW`, 47 `SR-CLOSED`, the FFI/architecture/persisted-state audits, and the documented accepted-design list) so each cell could suppress duplicates and report only deltas.
- **Adversarial verification.** Every raw finding was handed to an independent verifier instructed to *refute* it by re-reading the actual code, constructing or breaking the trigger path, and checking it against the baseline. 27 raw → 19 confirmed-new, 3 sharper-than-baseline, 2 known-duplicate confirmations, **3 rejected** (listed in Appendix B for transparency).
- **Personal confirmation.** The one `high` finding and both `security`-category findings were re-read and re-confirmed by hand against the source (file:line cited inline). WCR-01 was additionally confirmed end-to-end with a throwaway integration probe that was removed afterward — **the worktree is clean; this review changed no files.**
- **Severities** below are the conservative, code-grounded verifier severities. Where the original cell severity differed it is noted.

## Summary

| Severity | Count | IDs |
|---|---|---|
| High | 1 | WCR-01 |
| Low | 11 | WCR-02 … WCR-08, WCR-16 … WCR-19 |
| Informational | 10 | WCR-09 … WCR-15, WCR-20 … WCR-22 |

Headlines:

- **One real confidentiality defect (WCR-01, high):** CypherAir will encrypt to a recipient’s **revoked** encryption subkey when the primary key is still live — and shows that contact as fully valid. This is the only finding that crosses the threat model into actual data exposure, and it is a small, well-scoped fix.
- **The rest are low/informational:** a cluster of memory-hygiene / lock-surface / settings-state hardening gaps (WCR-02 … WCR-06), genuine but bounded architecture debt the prior refactor audit’s *symbol-grep* method missed (WCR-07, WCR-11), and a substantial test-quality cleanup with concrete **removal** recommendations (WCR-08, WCR-15 … WCR-22).
- **Crown-jewel invariants hold.** The AEAD hard-fail (in-memory `decrypt.rs` partial-plaintext zeroize; streaming `streaming.rs` temp-then-rename), profile/format auto-selection, and the SE-custody external-operation boundary were examined directly and are sound. No new findings there.

---

## Cryptography

### WCR-01 — `encrypt()` targets a revoked encryption subkey when the primary key is still live  ·  **High**

- **Where:** `pgp-mobile/src/encrypt.rs:65-72` (`collect_recipients`) and `:94-103` (`build_recipients`); UI mirror at `pgp-mobile/src/keys/key_info.rs:22-34` (`has_encryption_subkey` / `is_revoked`).
- **What:** Recipient selection chains `cert.keys().with_policy(policy, None).supported().alive().for_transport_encryption()` and **never calls `.revoked(false)`**. In Sequoia 2.3.0 the key-amalgamation iterator includes revoked keys unless `.revoked(false)` is set, and `.alive()` checks only the validity period (expiry), not revocation. `collect_recipients` separately rejects only **primary-key** revocation via `cert.revocation_status()` (`encrypt.rs:56-63`). So a recipient cert whose primary is live but whose encryption subkey carries a hard `SubkeyRevocation` (e.g. `KeyCompromised`) is accepted, and a PKESK is built for the revoked subkey. All recipient entry points share these helpers: `encrypt()`, `encrypt_binary()`, `encrypt_with_external_p256_signer()`, and streaming `encrypt_file()` / `encrypt_file_with_external_p256_signer()`.
- **Impact:** CypherAir encrypts plaintext to a key the recipient has cryptographically declared compromised/retired — exactly the scenario revocation exists to defend against. Whoever holds the revoked subkey can read the message. It is also a silent trust-confusion: `key_info.rs` derives `is_revoked` from primary status only and `has_encryption_subkey` from the same unfiltered iterator, so the contact is shown as fully valid and encryptable with **no warning**.
- **Trigger (verified):** A recipient cert with its **sole** transport-encryption subkey revoked (`KeyCompromised`), primary left live. A throwaway probe confirmed `encrypt_binary()` succeeded, `parse_recipients()` showed the PKESK addressed to exactly the revoked subkey’s key-id, and `decrypt_detailed()` with that subkey’s secret recovered the plaintext. With `.revoked(false)` added, the cert has zero encryption subkeys and `collect_recipients` rejects it (“no valid encryption subkey”).
- **Why it’s an omission, not a design choice:** the same crate already uses the correct idiom `…subkeys().revoked(false)` in five places in `pgp-mobile/src/keys/expiry.rs` (`:292,:379,:417,:552,:556`).
- **Related instances (same root cause, lower impact — own keys):** signing-key selection lacks the same filter at `pgp-mobile/src/sign.rs:94-98` (`.alive().for_signing()`, external/SE signer) and `pgp-mobile/src/encrypt.rs:119-128` (`setup_signer`, software signer has neither `.alive()` nor `.revoked(false)`). These let a user sign with their own revoked signing (sub)key. Fold into the same fix sweep.
- **Recommendation:** Add `.revoked(false)` to the amalgamation chains in `collect_recipients` and `build_recipients`; mirror it in `key_info.rs:22-28` (`has_encryption_subkey`) and consider surfacing subkey-level revocation in the contact model so the UI stops presenting revoked-subkey contacts as encryptable. Add positive/negative recipient tests for **both profiles** covering a subkey-revoked / primary-live recipient (the existing `security_recipient_policy_tests.rs` only cover *primary*-key revocation).
- **Novelty:** Distinct from `SR-FIX-05`/`SR-FIX-17` (signer/identity trust UI) and `SR-NEW-09` (filtered recipient retention). Existing recipient-policy tests cover only primary-key revocation; subkey revocation with a live primary is unguarded and untested.
- **Confidence:** High (code-confirmed + runnable probe + maintainer re-read).

---

## Security

### WCR-02 — Untrusted `cypherair://` import is processed (and a confirmation sheet presented) while the app is locked  ·  **Low**

- **Where:** `Sources/App/CypherAirApp.swift:386-390` (lock surface is an in-tree `.overlay`) vs `:420-461` (onboarding `.sheet`, tutorial `.fullScreenCover`, import/load `.alert`s, and `.onOpenURL`) and the import-confirmation `.sheet` in `Sources/App/Contacts/ImportConfirmationCoordinator.swift`; missing gate at `Sources/App/Contacts/Import/AppSceneIncomingURLRouter.swift:9-15`.
- **What:** `AppLockSurfaceView` is rendered as a SwiftUI in-tree `.overlay` on `mainWindowContent`, while the app’s modals are scene-level siblings — SwiftUI presents `.sheet`/`.fullScreenCover`/`.alert` **above** an ancestor overlay. More importantly, `.onOpenURL → AppSceneIncomingURLRouter.handle` gates only on `restartRequiredAfterLocalDataReset` and `IncomingURLImportCoordinator.handleIncomingURL` gates only on URL scheme + tutorial-active; **neither consults `appLockController.isLocked`.** `isLocked` is consulted only by the overlay (`:387`) and the load-warning gate (`:482`).
- **Impact:** Under the “brief physical access to a device that should be locked” threat, a co-located actor who triggers a crafted `cypherair://import?…` URL (NFC tag, message, QR) while CypherAir shows the lock surface (cold launch awaiting auth, or grace expired) gets the URL **parsed** and an import-confirmation sheet rendered over the lock, displaying attacker-supplied public-key metadata (User IDs / fingerprint) with an Import affordance. Bounded: no plaintext/private-key disclosure — the affected modals carry attacker public data or sandboxed tutorial content, and the actual import write to the protected `contacts` domain fails while locked (no wrapping root key). Net: a visual lock-bypass / UI-spoofing surface plus untrusted-parser exposure while nominally locked.
- **Recommendation:** Treat the lock as a presentation gate, not just a top overlay: early-return in `AppSceneIncomingURLRouter.handle` / `IncomingURLImportCoordinator.handleIncomingURL` when `isLocked` (queue or drop until unlocked), and gate the scene-level `.sheet`/`.fullScreenCover`/`.alert` item bindings on `!isLocked` (or auto-dismiss on entering locked). Alternatively host the lock surface at a window level guaranteed above modals.
- **Novelty:** Not in `SR-NEW-01…11` (those are relock-timing / grace-default / counter / cover-before-lock-task issues *inside* the `AppLockController` state machine). This is a structural presentation-layering + missing-URL-gate defect; no doc or test acknowledges it (`IncomingURLImportCoordinatorTests` covers only the tutorial-active gate).
- **Confidence:** Medium (z-ordering is documented SwiftUI behavior but not runtime-observed here; the missing lock gate on the URL path is certain regardless of z-order).

### WCR-03 — Derived wrapping-root-key `Data` left un-zeroed at domain-provisioning sites  ·  **Low**

- **Where:** `Sources/Security/ProtectedData/ProtectedSettingsStore.swift:210-216` and `Sources/Security/ProtectedData/PrivateKeyControlStore.swift:91-97`.
- **What:** Both provisioning sites do `let derivedWrappingRootKey = try domainKeyManager.deriveWrappingRootKey(from: &rawRootKeyInput)`, zero the raw input, then `SensitiveBytesBox(data: derivedWrappingRootKey)` and `defer { …box.zeroize() }`. `SensitiveBytes.init(data:)` copies into a fresh `ContiguousArray` (`ProtectedDataDomain.swift:170-172`) and `deriveWrappingRootKey` returns a fresh `key.withUnsafeBytes { Data($0) }` copy — so zeroizing the box never reaches the `let derivedWrappingRootKey` buffer, which is released to the allocator **un-wiped** at scope exit. (The session-coordinator path is *not* affected: `ProtectedDataSessionCoordinator` uses `var wrappingRootKey = …; defer { …protectedDataZeroize() }`, a CoW share that is zeroed; same correct pattern at `ProtectedSettingsStore.swift:623,696`.)
- **Impact:** The wrapping root key is the top-of-tree secret from which every domain master key is derived. A leftover un-zeroed copy in freed heap is recoverable by heap-forensics / co-resident page-scraping, undermining at-rest protection of all ProtectedData domains. Violates CLAUDE.md hard-constraint #5. Bounded: transient (released shortly after provisioning), the same secret is also durably held in the Keychain envelope + CryptoKit-locked storage, and storage is MIE/ProtectedData-protected — a hardening gap, not a direct exposure.
- **Recommendation:** Make the original a `var` and `defer { derivedWrappingRootKey.protectedDataZeroize() }` before constructing the box at both sites; or have `deriveWrappingRootKey` return a `SensitiveBytesBox`/`SensitiveData` so callers cannot hold an unmanaged `Data` copy. Sweep other `wrappingRootKey: Data` value parameters for the same pattern.
- **Novelty:** Not covered by any `SR-*` item or the FFI/architecture audits. `ARCHITECTURE.md` documents only that the *raw root secret* is zeroed — the *derived* wrapping-root-key original is exactly the gap.
- **Confidence:** High.

### WCR-10 — Contact-level “OpenPGP Certification: Certified” badge aggregates across all keys  ·  **Informational**

- **Where:** `Sources/App/Contacts/ContactDetailView.swift:416-442` (`certificationSummaryTitle` / `certificationSummaryColor`); model basis `Sources/Models/Contacts/ContactIdentitySummary.swift:12-28`; per-key projection `Sources/Services/ContactSummaryProjector.swift:97-117`.
- **What:** The contact-summary “OpenPGP Certification” badge is green/Certified if `contact.keys.map(\.certificationProjection.status).contains(.certified)` — i.e. **any** key, including historical or non-preferred ones. The contact’s encryption target, however, is `preferredKey` only (`canEncryptTo = preferredKey?.canEncryptTo`). Per-key certification is independent, so a contact whose only certified key is historical/non-preferred renders a green Certified header while the preferred encryption key’s own row reads Not Certified.
- **Impact:** A user reading the Trust section can infer the active encryption key is OpenPGP-certified when it is not — a trust-presentation overstatement that widens the gap the already-tracked `SR-FIX-05` concerns. Trigger is a self-inflicted user state (certify one key, then change preferred), not attacker-driven; no plaintext/key exposure. Mitigated by a trust footer and the correct per-key rows.
- **Recommendation:** Base the contact-level badge on the preferred/encryption-eligible key (align with the same key that drives `canEncryptTo`), or relabel it as “at least one key” rather than the active key.
- **Novelty:** Distinct from `SR-FIX-05` (single-certification trust *semantics*): this is an across-keys aggregation / key-selection mismatch at a specific site.
- **Confidence:** High (defect), with the caveat that severity is informational.

---

## Correctness

### WCR-04 — Crash between modify-expiry pending-bundle save and journal write orphans a usable wrapped private-key copy  ·  **Low**

- **Where:** `Sources/Services/KeyManagement/KeyMutationService.swift:261-286` (pending `saveBundle` at `:261`, `beginModifyExpiry` journal at `:282`); recovery gap at `:438-456` and `Sources/Security/PrivateKeyRewrapRecoveryCoordinator.swift:15-23`.
- **What:** `performModifySoftwareExpiry` writes the new re-signed cert to the **pending** namespace *before* writing the modify-expiry recovery journal. A process kill in that window leaves Keychain state `permanent=complete(OLD)` + `pending=complete(NEW)` with **both** journals empty. The only two startup recovery entry points are journal-gated (`checkAndRecoverFromInterruptedModifyExpiry` returns nil with no `modifyExpiry` journal; `checkAndRecoverFromInterruptedRewrap` returns nil with no `rewrapTargetMode`), and there is no orphan-scanning pass — so the complete pending bundle (a fully usable SE-wrapped copy of the private cert) persists across restarts.
- **Impact:** Defense-in-depth: a second wrapped private-key copy lingers beyond its intended lifetime (identical `WhenUnlockedThisDeviceOnly` + SE protection — **no new read exposure**, and it *is* reclaimed by Reset All Local Data and per-key delete since the pending services share the `com.cypherair.v1` prefix). Functional symptom: the next modify-expiry on that key fails once with `errSecDuplicateItem` before self-healing on retry (the catch calls `cleanupPendingBundle`).
- **Recommendation:** Write the recovery journal **before** the pending bundle (mirror `PrivateKeyRewrapWorkflow.run`, which calls `beginRewrap` before any Keychain mutation), or have the pending `saveBundle` pre-clear residual pending items.
- **Novelty:** Distinct from `SR-NEW-06` (retired *metadata* rows that survive reset — this orphan does **not** survive reset) and from SE-custody handle residue (different artifact class). Not modeled by the persisted-state inventory.
- **Confidence:** High.

### WCR-05 — Encrypt-to-Self picker selection is never re-validated; a stale/deleted self-key silently falls back to the default  ·  **Low**

- **Where:** `Sources/App/Encrypt/EncryptScreenModel.swift:64,843-847`; `Sources/App/Encrypt/EncryptOptionsSection.swift:19-29`; silent fallback at `Sources/Services/EncryptionService.swift:196-203`.
- **What:** With ≥2 own keys the “Encrypt to Self With” picker binds to `encryptToSelfFingerprint`, set once in `applyInitialSignerSelection` and only on explicit user pick or config change. The host view observes `runtimeSyncKey` and `protectedOrdinarySettings.state` but **not** `keyManagement.keys`. If the user picks self-key B then deletes B (or changes default) elsewhere, the picker renders blank but `encryptToSelfFingerprint` stays B; at encrypt time `resolvedEncryptToSelfKey` misses B and silently substitutes `keyManagement.defaultKey` (the `else if let defaultKey` branch). The recipient path has stale-selection guards (`hasStaleSelectedRecipients`, throws `staleSelection`); the encrypt-to-self own-key path has none.
- **Impact:** The self-copy is encrypted under a different own key than shown/last-selected. **Own-key-only** — no third-party exposure, message stays sender-decryptable — so a correctness/UX divergence, not a confidentiality leak.
- **Recommendation:** Add `onChange(of: keyManagement.keys)` that resets the fingerprint to `defaultKey.fingerprint`/nil when it no longer resolves; or make `resolvedEncryptToSelfKey` require an exact match and surface an explicit error for a missing user-chosen self-key.
- **Novelty:** Distinct from `SR-NEW-09` (third-party recipient hidden by filter). No code or test reconciles `encryptToSelfFingerprint` against live keys.
- **Confidence:** High.

### WCR-06 — High Security confirmation offers a “proceed at your own risk” path the service unconditionally rejects  ·  **Low**

- **Where:** `Sources/App/Settings/AuthMode/SettingsAuthModeRequestBuilder.swift:18,51-56` + `Sources/App/Settings/AuthMode/AuthModeChangeConfirmation.swift:45-62` vs `Sources/Security/AuthenticationManager.swift:795-802`.
- **What:** With a software key and no backup, switching to High Security shows a risk-acknowledgement toggle and a “Switch Mode” button (copy ends “…or proceed at your own risk.”). After acknowledging, `confirmPendingModeChange → performModeSwitch → switchMode` calls `performSwitchMode`, which hits `if newMode == .highSecurity && !hasBackup { throw .backupRequired }` **before any auth/rewrap**. The UI advertises a bypass; the service treats backup as a hard requirement.
- **Impact:** Dead affordance — the acknowledgement and promise never work; a no-backup user always gets `backupRequired`. **Fail-closed** (no downgrade/bypass; no secret exposure). Harm is a misleading/unusable security affordance and trust erosion in warning copy. Masked by tests: `SettingsScreenModelTests` only assert `requiresRiskAcknowledgement == true` with a mock action that doesn’t enforce `backupRequired`.
- **Recommendation:** Make the layers agree — either drop the no-backup risk-ack path and show a blocking “back up first” explanation, or, if at-your-own-risk High Security is intended, thread an acknowledged-risk flag through `switchMode` and relax the throw. Add a test that the no-backup→High-Security confirmation is either blocked in UI or actually succeeds.
- **Novelty:** Distinct from `SR-NEW-05` (authMode bootstrap downgrade) and the `SR-NEW-01…03` session/grace findings — a UI↔service policy contradiction in the AuthMode confirmation flow.
- **Confidence:** High.

### WCR-09 — `refreshProtectedOrdinarySettings` can silently discard the explicit per-message “Encrypt to Self” toggle  ·  **Informational**

- **Where:** `Sources/App/Encrypt/EncryptScreenModel.swift:740-743`; `Sources/App/Encrypt/EncryptScreenHostView.swift:57-59` (`.onChange(of: protectedOrdinarySettings.state)`); `Sources/Models/ProtectedOrdinarySettingsCoordinator.swift:131-140` (`saveLoadedSnapshot` replaces the whole `.loaded` state on any mutation).
- **What:** With `encryptToSelfPolicy == .appDefault`, the host observes the coordinator’s single `@Observable` `state` enum (fully replaced on **any** protected-ordinary write — theme, grace, onboarding flag, encrypt-to-self, tutorial state) and unconditionally re-seeds `encryptToSelf` from the app default. There is no per-message override flag. So an explicit in-flight toggle is overwritten by an unrelated settings write (e.g. theme changed in another macOS window/iPad scene) while the Encrypt screen’s `@State` model is alive.
- **Impact:** The per-message toggle flips out from under the user — a self-copy silently reverts on/off. **Own-key-only**, no third-party exposure; narrow reachability (concurrent settings write while Encrypt is open).
- **Recommendation:** Only refresh from the coordinator when the user has not overridden (track an “overridden” flag, or refresh only while `encryptToSelf == nil`), or react specifically to encrypt-to-self changes rather than to any state mutation.
- **Novelty:** Distinct from `SR-NEW-07` (grace-period default seeding) — this is the Encrypt screen *consuming* coordinator changes and clobbering an explicit toggle.
- **Confidence:** Medium (mechanism certain; depends on SwiftUI retaining the model across the write, which is the default lifecycle).

---

## Architecture

### WCR-07 — `ProtectedOrdinarySettingsCoordinator` is a lock/recovery/relock session state machine in `Sources/Models`, consumed directly by views  ·  **Low**

- **Where:** `Sources/Models/ProtectedOrdinarySettingsCoordinator.swift:5-9` (State `.locked`/`.loaded`/`.recoveryRequired`), `:52-61` (`loadAfterAppAuthentication`), `:67-69` (`relock`), `:71-75` (`resetAfterLocalDataReset(preserveAuthentication:)`), `:114-129` (catch → `.recoveryRequired`); consumed at `Sources/App/Settings/ThemePickerView.swift:6,23`, `Sources/App/ContentView.swift:18,56`, `Sources/App/HomeView.swift:6`. Forbidding rule: retired architecture-refactor target guidance; current tracking lives in [#502](https://github.com/cypherair/cypherair/issues/502).
- **What:** An `@Observable` class in `Models` implements a protected-domain session lifecycle (load-after-auth / relock / reset / recovery-on-failure) that mirrors the genuine Security-layer participants — exactly the category the refactor target says Models must not own (“unlock, relock, recovery, or migration coordination state machines”). Views read/mutate it directly via `@Environment` (e.g. `ThemePickerView` calls `setColorTheme`, `ContentView` does `.onChange(of: .state)`), bypassing the ScreenModel layer.
- **Impact:** Lock/relock/recovery coordination leaks into Models and the UI; changes ripple across Models/composition/views, and the Security session boundary is blurred. Maintainability / review-boundary debt, not a runtime crypto defect (fail-closed behavior is still enforced by the Security-layer participants this class mirrors).
- **Recommendation:** Relocate the lock/loaded/recovery coordination to a Security- or Service-owned protected-settings session type; expose only a read-only snapshot to ScreenModels; route view mutations and relock/reset through a service workflow.
- **Novelty:** The PR2D “Models Security vocabulary is extracted” audit row used a **symbol-text** check (`ProtectedDataError`/`LAContext`/etc.) and missed this class because it references none of those symbols by name — yet it is structurally a forbidden state machine in Models.
- **Confidence:** High.

### WCR-11 — `AppConfiguration` (Models) owns authentication policy, private-key-control state, and session/recovery lifecycle  ·  **Informational** (sharper than baseline)

- **Where:** `Sources/Models/AppConfiguration.swift:20` (`privateKeyControlState`), `:49` (`appSessionAuthenticationPolicy` + `didSet` UserDefaults write), `:64-84` (`lastAuthenticationDate`/`recordAuthentication`), `:27-46` (`postUnlockRecoveryLoadWarning`), `:86-95` (`resetToFirstRunDefaults`). Types defined in `Sources/Security/AuthenticationEvaluable.swift:9,133`. Mutated from App at `Sources/App/Settings/SettingsScreenModel.swift:254,505,508,510`.
- **What:** A core `Models` `@Observable` class holds Security-domain value types (`PrivateKeyControlState`, `AuthenticationMode`, `AppSessionAuthenticationPolicy`) and owns auth-session lifecycle, post-unlock recovery aggregation, and its own UserDefaults persistence; the App layer writes `appConfiguration.privateKeyControlState = .unlocked(newMode)` directly.
- **Impact:** A Models type depends on Security types and owns auth/session/recovery coordination + persistence, and App can set in-memory authorization state without going through Security — widening the review surface for sensitive auth state (an `AppConfiguration` edit is logically a Security edit but doesn’t look like one). **No security impact:** the mutated field is a UI mirror; the real cryptographic gate is `PrivateKeyControlStore.requireUnlockedAuthMode()`, not this field. Maintainability / review-boundary debt.
- **Recommendation:** Move private-key-control state, app-session policy, last-auth/grace logic, and recovery aggregation behind a Security/Service-owned session holder; have App/ScreenModel set authorization state through an `AuthenticationManager`/Security workflow.
- **Novelty / doc-accuracy correction:** The baseline PR2D “Models Security vocabulary is extracted” claim and the PR2C “AppConfiguration keeps only numeric grace-period values” claim are **both contradicted** by the current file — the symbol-grep audit missed the Security value types and the auth-session lifecycle now resident in Models. Worth recording as a named-instance correction even though the broad “App-layer owns auth state” concern overlaps the retired architecture-refactor audit baseline now tracked under [#502](https://github.com/cypherair/cypherair/issues/502).
- **Confidence:** High.

---

## Technical debt

### WCR-12 — `DetailedSignatureVerification.summaryEntryIndex` is threaded across the FFI boundary but never read by app code  ·  **Informational**

- **Where:** field `Sources/Models/DetailedSignatureVerification.swift:53`, dropped at `:73-80` (`summaryVerification` passes `signerFingerprint: nil`); written at `Sources/Services/FFI/PGPMessageResultMapper.swift:12,27,51,75,90,135`; rendered-without-it at `Sources/App/Common/DetailedSignatureSectionView.swift`.
- **What:** Rust meaningfully computes `summary_entry_index` (which observed signature “won” the folded summary) and Rust-side tests use it; the Swift mapper faithfully threads it into the model, but **no production Swift reader exists** — the summary row renders status only, with no signer attribution. Only tests round-trip it for equality.
- **Impact:** None today; latent confusion debt — a future maintainer wiring a “winning signer” row would find the field present yet deliberately unresolved.
- **Recommendation:** Either drop it from the Swift model (keep it Rust-internal) or wire `summaryVerification` to resolve identity from `signatures[summaryEntryIndex]`. Don’t keep carried-but-unread state.
- **Novelty:** A concrete dead-field instance, distinct from the tracked `SignatureVerification` dual-state debt.

### WCR-13 — `PGPKeyOperationFailureCategory.prohibitedFallbackAttempted` is an orphan case with shipped localized strings  ·  **Informational**

- **Where:** case `Sources/Models/PGPKeyOperationFailureCategory.swift:30`; user-facing copy `Sources/App/Common/CypherAirError+Presentation.swift:143-144`; en + zh-Hans strings `Sources/Resources/Localizable.xcstrings:5496`.
- **What:** An exhaustive trace of every producer of `PGPKeyOperationFailureCategory` (handle-store mapping, the two external-P256 translators, the failure mapper, the resolution factories, both provider bridges) shows the case is **never** produced — it appears only in the enum def, the exhaustive no-default presentation switch, the bridges’ catch-all default arm, and an `allCases` test. A maintained en+zh string pair exists for an unreachable state.
- **Impact:** None; the prohibited-fallback property (no silent SE→software fallback) is enforced structurally by router/resolver `.blocked`/`.unavailable` resolutions, not by emitting this category. The “exhaustive copy” design comment masks dead vocabulary.
- **Recommendation:** Remove the orphan case + its two `.xcstrings` entries + the bridge default-arm members, or wire it to a real guard; if intentionally reserved, annotate it as not-yet-produced.
- **Novelty:** Distinct from `SR-FIX-18`; an unreachable production error category with shipped strings.

### WCR-14 — `PGPKeyOperationResolution` carries ~80 lines of invariant-enforcing `Codable` that is never serialized  ·  **Informational**

- **Where:** `Sources/Models/PGPKeyOperationResolution.swift:21-83` (custom `init(from:)`/`encode(to:)` enforcing “supported ⇒ no category, failed ⇒ category”).
- **What:** The type is only ever built via its in-memory static factories and read via `.support`/`.failureCategory`; no `JSONEncoder`/`Decoder`/plist site touches it, and the enclosing `PrivateKeyOperationRoute` enum isn’t even `Codable`. The same invariant is already guaranteed at construction (private memberwise init + valid-by-construction factories). The decoder’s guarded threat — a tampered persisted resolution — cannot occur because resolutions are never persisted.
- **Impact:** Dead defensive infrastructure: maintenance surface plus a misleading signal that the type crosses an untrusted persistence boundary. No correctness/security risk. (The rejection branches *are* exercised by `ModelTests`, but only against synthetic input.)
- **Recommendation:** Drop the `Codable` conformance and custom coders, relying on the private-init + factory invariant; or, if persistence is genuinely planned, add the real site and a round-trip/negative test.
- **Novelty:** A concrete instance of model infrastructure maintained for a boundary the type never crosses.

---

## Test quality

The maintainer’s standing preference (project memory): **source-audit tests that scan source *text* and box-checking negatives that assert nothing are worse than none — recommend removal, not more coverage.** The items below apply that lens; each names exact files/tests and the behavioral coverage that already exists, so removals lose nothing.

### Recommended removals / merges

| ID | Test | Severity | Action | Why removal loses no coverage |
|---|---|---|---|---|
| WCR-08 | `Tests/ServiceTests/ArchitectureSourceAuditTests.swift` (1950 lines) + harness | Low | **Remove** | Imports only `Foundation`+`XCTest` (no `@testable import CypherAir`); 35 tests / 33 source-substring asserts; ~600 lines (`:253-868`) are meta-tests of the regex/sanitizer harness. The routing/zeroization intent is covered behaviorally by `PrivateKey*ServiceTests`, `PrivateKeyOperationRouterTests`, `PGPKeyCapabilityResolverTests`, `DecryptionServiceTests`, `PGPKeyOperationAdapterTests`, `PGPExternalP256KeyAgreementProviderBridgeTests`. Track the boundary in the architecture audit docs. *(Sharper than the baseline name-drop: quantifies scope, isolates the meta-test bulk, and flags the silent allowlist-rot maintenance trap.)* |
| WCR-15 | `Tests/ServiceTests/RepositoryAuditLoader.swift` + source-scan consumers | Informational | **Remove with the scanners; migrate residual checks** | Pure source-text loader; 5 consumers, all source-scanning. Surfaces a **new** hidden instance: `ContactServiceProtectedDomainTests.swift:554-577` slices `ContactsDomainStore.swift` and asserts *source ordering* (a `let … = expectedCurrentGenerationIdentifier()` line precedes a `unwrapDomainMasterKey` line) — proves nothing about runtime ordering; convert to a behavioral assertion. Also imposes a build-snapshot of `Sources/` into the test bundle (two xcfilelists). **Caveat:** `LocalizationCatalogTests`’ catalog-completeness use is more defensible — migrate it off the loader before deleting the loader outright. |
| WCR-16 | `DeviceProtectedDataRootSecretStoreTests` missing from `CypherAir-UnitTests.xctestplan` skip denylist | Low | **Add to denylist** (⚠ edits a protected `.xctestplan` — needs maintainer approval) | It is the **only** `Tests/DeviceSecurityTests/*` class absent from the 11-entry `skippedTests` denylist, yet it’s a real device test (guards on `SecureEnclave.isAvailable`, drives `KeychainProtectedDataRootSecretStore` + `evaluatePolicy`). On the documented `macOS,arch=arm64e` unit host it can interactively prompt or silently lose coverage; `test_unauthenticatedInteractionDisallowedContext_…` does an in-lane real SE Keychain round trip. *(Finder said medium; downgraded to low — test-lane hygiene, no security impact.)* |
| WCR-17 | `Tests/ServiceTests/SecureEnclaveCustodyEvidenceLogTests.swift:9-62` | Low | **Remove** | All 3 tests assert the formatting of `SecureEnclaveCustodyEvidenceSummary.line`, a **test-only** type (zero `Sources/` references) that joins enum raw values + ints; two pin literal strings, the third runs a regex tautological with the field types. The load-bearing sanitization is already covered in the device lane against **production** types (`assertSanitizedText`/`assertTraceIsSanitized` in `SecureEnclaveCustodyDeviceTestCase`). |
| WCR-18 | `Tests/FFIIntegrationTests/FFIIntegrationTests+MemoryZeroing.swift:54-61` (`test_sensitiveData_deinit_zerosStorage`) | Low | **Remove** | No `XCTAssert`; can only detect a crash during dealloc. Would pass identically if `SensitiveData.deinit`’s `storage.zeroize()` were deleted. The same `zeroize()` is already exercised on a live, inspectable buffer by `test_sensitiveData_explicitZeroize_clearsData`. |
| WCR-19 | `Tests/ServiceTests/KeyManagementServiceSecurityInvariantTests.swift:41-56` (`test_exportKey_highSecurity_biometricsUnavailable_throwsAuthError`) | Low | **Strengthen or remove** | Empty catch-all accepts *any* error; `exportKey` has ≥3 other reachable throw sites, so it stays green even if the biometrics guard is removed. Assert the specific `CypherAirError`/`MockSEError.authenticationFailed` mapping, or delete rather than keep a catch-all negative on a security boundary. |
| WCR-20 | `pgp-mobile/tests/gnupg_message_interop_tests.rs:499-525` (`test_c2b_10_compressed_seipd2_verified_by_composition`) | Low | **Remove** | Never constructs/decrypts a compressed-SEIPDv2 message (its own docstring concedes “verified by composition only”, KNOWN LIMITATION M6); its two assertion blocks duplicate `test_c2a_9_decrypt_deflate_compressed_message` and `test_encrypt_decrypt_text_profile_b`. Records “C2B.10 covered” for an untested combination. |

### Lower-value assertions (cleanup, no urgency)

- **WCR-21 — `assert!(result.contains("revocation"))` ×4** · Informational · `pgp-mobile/tests/profile_a_key_lifecycle_tests.rs:119`, `revocation_construction_tests.rs:169,180`, `profile_b_key_lifecycle_tests.rs:42`. `parse_revocation_cert` returns one hardcoded success string that always contains “revocation”, so the assertion can never fail independently of the preceding `.expect()`; the fingerprint in the string is never checked. Drop the four lines, or strengthen one to assert the source cert’s fingerprint. Genuine negative coverage already exists (`test_revocation_cert_wrong_key_profile_a/b`, `test_generate_key_revocation_wrong_certificate_fails_validation`).
- **WCR-22 — C3.8 “GnuPG incompatibility” tests never invoke `gpg`** · Informational · `pgp-mobile/tests/gnupg_message_interop_tests.rs:388-431`. Both only re-assert v6-ness / a Profile B self-round-trip (already in `profile_b_message_tests.rs`); the real gpg-rejection is `test_gpg_rejects_sequoia_profile_b_pubkey` (`gnupg_binary_tests.rs:271`). Rename for honesty or fold the v6 assertion into the existing version test. (Consistent with the file’s documented “gpg can’t run here, verify by composition” strategy — naming/dedup polish, not a defect.)

### Confirmations of already-known disliked tests (no new analysis)

- `Tests/ServiceTests/ContactServiceArchitectureAuditTests.swift` — source-audit scanner; baseline already flags it for removal.
- `Tests/ServiceTests/LocalizationCatalogTests.swift` — mixes a useful catalog-completeness check with a brittle source-grep key-discovery scan; keep the former, drop/migrate the latter (see WCR-15).

---

## Relationship to the SR-NEW backlog

`docs/CODEX_SECURITY_REVIEW.md` defers triage of the 11 `SR-NEW-*` (2026-06-14 scan) until “the in-progress whole-codebase review completes.” This document is that review. It deliberately does **not** re-report `SR-NEW-01…11`; every finding here is checked to be new or materially sharper. Suggested next step for the maintainer: triage `SR-NEW-01…11` and decide which WCR items (above) become `SR-FIX-*`. The only one that rises to a confidentiality defect is **WCR-01**.

## Appendix A — Coverage map (cells → result)

22 cells: crypto (encrypt/decrypt/stream, sign/verify, keys, SE-custody bridge, untrusted parsers, FFI/error/zeroize), security (SE-custody Swift, keychain, auth-lifecycle, protecteddata/memory), services (decrypt/encrypt/sign, QR/contacts, keymgmt), app (lock/privacy, encrypt-recipient, decrypt/keys/settings, contacts/onboarding/tutorial), architecture (layering, models/errors), test-quality (rust, swift-services, ffi/device/invariant). Cells that produced no new-or-sharper finding after verification: crypto sign/verify, crypto keys-lifecycle, SE-custody bridge (Rust + Swift), untrusted parsers, FFI/error/zeroize, keychain (beyond WCR-04), services decrypt/encrypt/sign, QR/contacts, keymgmt — i.e. the crown-jewel crypto and SE-custody paths verified clean against the baseline.

## Appendix B — Candidates considered and rejected (refuted on re-read)

1. **“Decrypt-path signature summary uses last-write-wins, downgrading a tampered (Bad) signature to ‘Signer certificate unavailable’.”** Rejected — the production fold does not exhibit the claimed downgrade once the actual `observe_result`/`entry_from_result` logic is read.
2. **“Signature-summary state-machine tests drive a hand-reimplemented helper, so they can’t catch drift.”** Rejected as a defect — the production fold is already covered by real-path tests across three files asserting the exact summary states/indices; at most a minor missing follow-to-valid multi-signer real-path case, not a defect.
3. **“`SourceComplianceStoreTests` / `OpenSourceNoticeStoreTests` are source-scans — remove.”** Rejected — both are genuine *behavioral* tests (decode fixtures, assert computed/sectioned/filtered output), not source scanners; nothing to act on.
