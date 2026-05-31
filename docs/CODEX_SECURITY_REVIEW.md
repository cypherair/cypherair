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

## [open] CA-01: Duplicate-contact conflict warning is dropped on import

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/3db1dd11b0548191993e920e471adfb2 — Codex severity **high** · assessed **real, needs UI/workflow fix**
- **Verified real, but narrower than the report headline.** A same-email or same-User-ID public-key import with a different fingerprint is intentionally stored as a **separate contact identity**, not as an overwrite of the existing contact. The app already computes `ContactCandidateMatch` and returns `.addedWithCandidate`, but `ContactImportWorkflow` collapses that result into ordinary success and never shows the conflict/candidate warning in the import confirmation flow.
- **Impact:** a spoofed duplicate contact can appear next to the legitimate contact with the expected display name/email. Future encryption only targets the attacker key if the user selects that duplicate contact row; unverified imports still get unverified-recipient warnings. This is a duplicate-recipient/conflict-warning gap, not automatic key takeover.
- **Current code:** `ContactImportMatcher.candidateMatch` computes the candidate; `ContactSnapshotMutator.addContact` stores the new identity/key; `ContactService.importResult` returns `.addedWithCandidate`; `ContactImportWorkflow.importContact` treats `.addedWithCandidate` like `.added`; `ContactRecipientResolver.publicKeysForRecipientContactIDs` resolves the selected contact ID's preferred key.
- **Fix idea:** preserve duplicate identities if that remains product policy, but surface the candidate conflict before/at import success and offer an explicit merge/review path. If product policy should be stricter, stage or block conflicting imports until the user chooses how to handle the existing contact.

## [open] CA-02: Release build token scope is too broad

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/b2db20bd745c8191856cc218daacb19d — Codex severity **high** · user-confirmed **real, pending fix**
- **Verified real, with narrowed scope.** The core issue is stable/edge release XCFramework builds passing `GH_TOKEN` to the whole `./build-xcframework.sh --release` step, so Cargo build scripts, proc macros, and `cargo run` helpers can inherit the release job token. PR/nightly read-token exposure is lower impact and not the main risk.
- **Impact:** if release builds run untrusted or compromised build code, that code can read a write-capable workflow token during artifact production. No app-runtime or end-user exploit is implied; this is a release supply-chain hardening issue.
- **Current code:** `.github/workflows/stable-build-release.yml` and `.github/workflows/xcframework-edge-release.yml` set write-class workflow permissions and pass `GH_TOKEN` to the XCFramework build step; `.github/workflows/pr-checks.yml` and `.github/workflows/nightly-full.yml` also pass read-scoped tokens; `scripts/build_apple_arm64e_xcframework.sh` invokes `gh`, `cargo build`, and `cargo run` in the inherited environment.
- **Fix:** only provide GitHub tokens to the `gh release list/download` calls that need them, and clear `GH_TOKEN` / `GITHUB_TOKEN` from Cargo/build subprocess environments.

## [open] CA-05: Stable release dispatch can decouple source ref from stable tag

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/893e12c4d22c8191afba18916328b86d — Codex severity **high** · user-confirmed **real, pending fix**
- **Verified real.** The manual stable release path accepts both `release_tag` and `source_ref`, checks out `source_ref`, and validates tag spelling plus project version/build, but does not prove the checkout `HEAD` is the stable tag commit.
- **Impact:** a user or attacker with workflow-dispatch authority could build and publish stable release assets from one ref under a different stable tag's release page, weakening provenance for the XCFramework, source bundle, and compliance artifacts. This is not an arbitrary fork-PR path.
- **Current code:** `.github/workflows/stable-build-release.yml` uses `workflow_dispatch.source_ref` for checkout under `contents: write`, `id-token: write`, and `attestations: write`; `publish-stable-release` creates the release after the build/audit jobs complete.
- **Fix:** formal stable publication should be tag-push only. Keep `workflow_dispatch` only for dry-run or validation that cannot create the official release, and add a guard that the checked-out `HEAD` equals the peeled stable tag commit.

## [open] CA-08: Edge release publication is not gated on Rust audit

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/9b57feaa6750819185da3adea4e4b205 — Codex severity **medium** · user-confirmed **real for edge, pending fix**
- **Verified real, narrowed to edge/drill releases.** Stable publication is already gated because `publish-stable-release` depends on `rust-dependency-audit`. The edge workflow still runs `rust-dependency-audit` and `publish-edge-release` as independent jobs, so the edge publish job can create the tag, upload assets, and publish the prerelease even if `cargo audit --deny warnings` fails.
- **Impact:** public edge/drill XCFramework prerelease assets can be published from a workflow run whose Rust dependency audit failed. This does not affect formal stable/App Store publication, but it weakens the prerelease supply-chain signal.
- **Current code:** `.github/workflows/xcframework-edge-release.yml` defines `rust-dependency-audit` and `publish-edge-release` without a `needs` relationship; `.github/workflows/stable-build-release.yml` already uses the intended gated shape for stable release publication.
- **Fix:** make `publish-edge-release` depend on `rust-dependency-audit`, or run the audit inside the publish job before any tag/release creation or asset upload.

## [open] CA-09: Contact certification needs an explicit trust model

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/784c0115a134819188d3ebac0d5d8ac3 — Codex severity **medium** · user-confirmed **Medium, standalone trust-model follow-up**
- **Verified real as a trust-semantics issue.** The certification workflow can save any cryptographically valid certification artifact from the candidate signer set, including unverified contacts, and the projection then displays a green `Certified` state in the contact Trust UI. This does not change manual fingerprint verification or recipient selection.
- **Impact:** misleading local trust metadata. A user may read `Certified` as trusted endorsement even when the signer is merely a known but untrusted contact, or when the artifact is only a self-certification-like structure.
- **Current code:** `Sources/Services/CertificateSignatureService.swift` (`candidateSignerCertificates`, artifact validation); `Sources/Services/ContactSnapshotMutator.swift` (`saveCertificationArtifact`, `recomputeCertificationProjections`); `Sources/App/Contacts/ContactDetailView.swift` / `ContactKeySummaryView.swift` (`Certified` Trust UI).
- **Fix:** handle separately as a Contacts/OpenPGP trust-model design item. `Certified` should mean trusted certification, while ordinary valid certification signatures should use neutral UI. Self-certification should not trigger contact-level trusted certification.

## [open] CA-10: Orphan root-secret cleanup can race first-domain creation

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/9fd5a847678881918e0eea9cbdfc2e77 — Codex severity **medium** · user-confirmed **Low priority, pending fix**
- **Verified real but low probability.** `ProtectedDataFirstDomainSharedRightCleaner` decides whether a root secret is orphaned from a caller-provided registry snapshot, then deletes the persisted root secret without reloading the current registry or serializing with registry mutations. A stale empty-registry snapshot could race a first-domain transaction after the root secret is saved but before domain artifacts are staged.
- **Impact:** local ProtectedData availability/recovery risk, not disclosure or authentication bypass. Normal first app authentication appears mostly serialized; practical reachability requires unusual fresh/reset first-domain task interleaving around protected settings or other ProtectedData access.
- **Current code:** `Sources/Security/ProtectedData/ProtectedDataFirstDomainSharedRightCleaner.swift` (`cleanupOrphanedSharedRightIfSafe`); `Sources/Security/ProtectedData/ProtectedDataRegistryStore.swift` (`performCreateDomainTransaction`); `Sources/Security/ProtectedData/PrivateKeyControlStore.swift` and `ProtectedSettingsStore.swift` first-domain bootstrap paths.
- **Fix:** before deleting a supposedly orphaned root secret, reload current registry under the registry mutation gate or equivalent serialized operation. Abort cleanup if current registry has a pending mutation, committed membership, or ready shared-resource state.

## [open] CA-11: Local reset must fail closed when app-session auth is unavailable

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/be6dc440a494819194638fde5dcd7663 — Codex severity **medium** · user-confirmed **real, low impact, pending fix**
- **Verified real, low reachability.** The local data reset flow checks whether app-session auth can be evaluated, but if auth is unavailable it skips the prompt and still proceeds to reset. In the realistic threat model this is a local destructive action, not data disclosure; an attacker generally still needs an already-unlocked app/session to reach it.
- **Impact:** local availability/destructive reset risk under narrow device-auth-unavailable conditions. No private-key disclosure or Secure Enclave bypass is implied.
- **Current code:** `Sources/App/Settings/SettingsScreenModel.swift` (`confirmLocalDataReset`); `Sources/App/Settings/LocalDataResetService.swift` (`resetAllLocalData`).
- **Fix:** if app-session auth cannot be evaluated, block reset and show an auth-unavailable error instead of treating the auth check as optional.

## [open] CA-15: Operation prompt lifecycle suppression can stale-consume real app switches

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/daf3bd3399248191900565067b6785ae — Codex severity **medium** · user-confirmed **High priority, pending fix**
- **Verified real, with platform-specific impact.** `PrivacyScreenLifecycleGate` observes operation-prompt generation lazily from later lifecycle callbacks. If an operation prompt ended before the gate observed the new generation, a later real lifecycle event can be stale-consumed as prompt noise. On macOS, a real `didResignActive` / `didBecomeActive` after Touch ID can leave the window unblurred, skip expected resume authentication, or contribute to the long-standing stuck-blur behavior. On iOS/iPadOS/visionOS, `.background` normally hard-blurs before the app-switcher snapshot, but inactive-only or prompt-tail timing can still cause short-lived privacy/UX failures.
- **Impact:** lifecycle privacy and reliability bug, not a private-key or payload-authentication bypass. It can expose already-unlocked UI on macOS app switches and can make authentication recovery feel stuck or inconsistent.
- **Current code:** `Sources/App/Common/PrivacyScreenLifecycleGate.swift` (`syncOperationAuthenticationAttemptGeneration`, prompt suppression decisions); `Sources/App/Common/PrivacyScreenModifier.swift` (scene/app notification routing); `Sources/Security/AuthenticationPromptCoordinator.swift` (`operationPromptAttemptGeneration`); `Sources/Security/ProtectedData/AppSessionOrchestrator.swift` (`handleSceneDidResignActive`, `handleSceneDidEnterBackground`, resume/settle handlers).
- **Fix design:** replace unbounded "next lifecycle event" suppression with bounded operation-prompt settle state. Real `.background` must always clear prompt state and hard-blur. Prompt-induced inactive/resign should use `blurOnly`; the matching active should use `settleTransientBlur` and must not call `handleResume()` or create a second auth prompt. After a short internal prompt-settle window from prompt end, stale prompt state must no longer suppress real app switches. Do not change the user-visible "Immediately" grace-period semantics to 3 seconds.

## [open] CA-16: In-flight resume task can clear background privacy blur

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/e2433b9357a48191b7ea3c939cad1a4d — Codex severity **medium** · user-confirmed **High priority, pending fix**
- **Verified real, with updated mechanism.** The historical `runPostAuthenticationWarmUpIfNeeded` path is gone, but `handleResume()` still authenticates, awaits post-auth domain/settings/contact work, then unconditionally clears `isPrivacyScreenBlurred`. If the user backgrounds the app during that post-auth window, `handleSceneDidEnterBackground()` hard-blurs first, but the in-flight resume task can later clear the blur.
- **Impact:** narrow timing window, but worth fixing with CA-15. On iOS/iPadOS/visionOS the common background-snapshot path is usually protected by the background event and system suspension, but the race is timing-sensitive. On macOS it is a clearer privacy/state-machine issue because an inactive or backgrounded window can remain visible and be overwritten by old resume work.
- **Current code:** `Sources/Security/ProtectedData/AppSessionOrchestrator.swift` (`handleResume`, `handleSceneDidEnterBackground`, post-auth completion); `Sources/App/Common/PrivacyScreenModifier.swift` (`performResumeAction` untracked task); `Sources/App/AppContainer.swift` (post-auth handler opens protected domains, contacts, protected settings, and recovery state).
- **Fix design:** maintain scene/activity generation or equivalent foreground state. `resignActive` / `background` should increment the generation and hard-blur. `handleResume()` should capture the generation at start and clear blur only if completion still belongs to the current active generation; otherwise keep blur and let the next active/resume path decide. This should not change user grace-period semantics.

## [open] CA-18: Drill release verification command needs shell-safe source refs

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/6d4198b21e5c8191a5d7d8339a3d6484 — Codex severity **medium** · user-confirmed **low-impact hardening, pending fix**
- **Verified low impact.** Edge/drill release notes render a copyable `gh attestation verify ... --source-ref "$RELEASE_SOURCE_REF"` command. A drill branch name containing shell metacharacters can be expanded if a developer copies that command into a shell.
- **Impact:** this does not execute in GitHub Actions and does not affect app users. It only affects manual verification of drill artifacts, but project docs explicitly tell reviewers to use the ref-pinned command from drill release notes.
- **Current code:** `.github/workflows/xcframework-edge-release.yml` writes `RELEASE_SOURCE_REF` into release metadata and the release-notes verification command; `docs/XCFRAMEWORK_RELEASES.md` directs drill-release verification to use the exact command rendered in release notes.
- **Fix:** render shell-safe quoted source refs in release notes, or restrict drill source refs to a safe character set before publishing notes.

## [open] CA-29: Abandoned file decrypt can adopt temporary plaintext output

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/a2a7f41bec048191b18443eaa38268e6 — Codex severity **medium** · user-confirmed **Low priority, pending fix**
- **Verified real, but low impact.** Manual cancel and content-clear already cancel the file operation, and the Rust streaming path deletes partial `.tmp` plaintext on cancellation or failure. The remaining gap is route abandonment: `DecryptView.onDisappear` clears current state but does not cancel an in-flight file decrypt, so a later successful operation can adopt a temporary plaintext output after the screen is gone.
- **Impact:** local app-sandbox temporary plaintext residue until startup/reset cleanup, not an external leak, AEAD bypass, or partial-plaintext exposure. The app already uses app temporary `tmp/decrypted/op-<UUID>/...` storage, complete file protection, and startup/reset cleanup.
- **Current code:** `Sources/App/Decrypt/DecryptScreenModel.swift` (`handleDisappear`, `decryptFile`, `adoptDecryptedFileOutput`); `Sources/App/Decrypt/DecryptView.swift` (`onDisappear`); `Sources/App/Common/OperationController.swift` (`cancelAndInvalidate`); `Sources/App/Common/AppTemporaryArtifactStore.swift` (`cleanupTemporaryArtifacts`).
- **Fix:** when the Decrypt route disappears, cancel/invalidate any in-flight file decrypt and prevent late output adoption; continue relying on startup/reset temporary cleanup as a backstop.

## [open] CA-33: Decrypt output and signature verification can become cross-mode mismatched

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/ffff6cd467088191ab32b29040dd40ab — Codex severity **medium** · user-confirmed **pending fix**
- **Verified real.** Decrypt keeps text output and file output separately, but both modes share one `detailedSignatureVerification`. A user can decrypt in one mode, decrypt in the other mode, then switch back and see the first mode's output with the second mode's signature verification state.
- **Impact:** trust UI correctness bug, not a cryptographic verification bypass. The visible signature section can be read as applying to the visible output even when it came from a different mode's result.
- **Current code:** `Sources/App/Decrypt/DecryptScreenModel.swift` (`decryptedText`, `decryptedFileURL`, shared `detailedSignatureVerification`, `decryptText`, `decryptFile`); `Sources/App/Decrypt/DecryptView.swift` (mode-gated output sections plus shared signature section).
- **Fix:** model text and file results as separate atomic `output + DetailedSignatureVerification` values, and render only the verification owned by the currently visible result.

## [open] CA-41: Tutorial contacts open should be idempotent while opening

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/703d8b5d0ad48191abf6a936394d174e — Codex severity **informational** · user-confirmed **low-priority pending fix**
- **Verified as a narrow tutorial reliability race.** Rapid repeated tutorial module opens can start more than one contacts-domain open while the tutorial sandbox is still `.opening`. A later failure can clean up the active tutorial container.
- **Impact:** disposable tutorial sandbox availability only. Real keys, contacts, settings, exports, temporary files, and private-key security assets are isolated from the tutorial sandbox.
- **Current code:** `Sources/App/Onboarding/TutorialSessionStore.swift` (`openModule`, `openContactsIfNeeded`); `Sources/App/Onboarding/TutorialSandboxContainer.swift` (`openContactsIfNeeded`); `Sources/Services/ContactService.swift` (`openContactsAfterPostUnlock`).
- **Fix:** when tutorial contacts are opening, either disable repeated module opens in the UI or cache/reuse one in-flight contacts-open task in `TutorialSandboxContainer`.

## [open] CA-42: Decrypt/Verify text input section recreation dismisses keyboard during edits

- **Codex:** https://chatgpt.com/codex/cloud/security/findings/3f03eebb98448191b26dbb3af9dcafa0 — Codex severity **informational** · user-confirmed **Medium priority, pending fix**
- **Verified real by code and user reproduction.** Decrypt and Verify both place the text input `Section` under `.id(textInputSectionEpoch)`, and ordinary edit setters bump that epoch through invalidation helpers. User reproduced that pressing backspace can dismiss the keyboard.
- **Impact:** core text-entry UX/availability issue for Decrypt text mode and Verify cleartext mode. It does not expose secrets or change decrypt/verify correctness, but it makes manual correction of encrypted/signed text unreliable.
- **Current code:** `Sources/App/Decrypt/DecryptScreenModel.swift` (`setCiphertextInput`, `invalidateTextInputState`); `Sources/App/Decrypt/DecryptView.swift` (`.id(model.textInputSectionEpoch)`); `Sources/App/Sign/VerifyScreenModel.swift` (`setSignedInput`, `invalidateCleartextVerificationState`); `Sources/App/Sign/VerifyView.swift` (`.id(model.textInputSectionEpoch)`).
- **Fix:** split edit invalidation from section refresh. Edit paths should clear stale result/phase1/verification state without bumping `textInputSectionEpoch`; import/reset/operation-completion paths can still refresh the input section when needed.
