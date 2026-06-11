# P3 Auth-Lifecycle Worklog (macOS in-window auth cutover)

Untracked working file — not committed unless asked. Session start: 2026-06-10.

## Objective recap
- PR-1: presentation seam + per-op private-key route (plan PR-1 + PR-2). Open PR, stop, present PR-2 breakdown.
- PR-2: everything else (remaining routes / migrations / pinning+cleanup), per-stage commits. After maintainer approves PR-1.
- macOS biometric-only is decided and final. iOS/iPadOS/visionOS byte-for-byte unchanged.
- Plan: ~/.claude/plans/please-investigate-current-main-composed-rabbit.md (predates legacy cleanup #484/#485/#487 — verify before trusting line refs).

## Stage log

### Stage 0 — Verification of plan vs current main (DONE)
- [x] Worktree clean at dcae0eb (main). Branch: feat/p3-in-window-auth-pr1.
- [x] PoC branch `poc/auth-lifecycle-macos` exists (local + origin).
- [x] Verified plan's cited symbols/sites against main (3 parallel sweeps).
- [x] Refreshed design-doc status blocks (commit 94a3329).

## Findings / contradictions vs plan (none material — proceed)
- PR-1 surface verified EXACTLY: evaluator closure (AuthenticationManager.swift:143-153), lastEvaluatedContext (:121),
  SE convenience extension (SecureEnclaveManageable.swift:86-98), unwrapPrivateKey choke point (:24), full 13-file
  call-site closure (KeyProvisioningService second site is :137 not :135 — trivial).
- PR-2-territory deltas (post-legacy-cleanup): `legacyInitialPayload()` GONE → seed now `Payload.initial(authMode: .standard)`
  at PrivateKeyControlStore.swift:86 AND :158 (TWO seed sites for the macOS pin). `migrateLegacySharedRightIfNeeded` GONE
  (AS marker seeds only via persistSharedRight). `reprotectPersistedRootSecretIfPresent` lives on
  ProtectedDataRootSecretCoordinator (:93-150); ACL-only SecItemUpdate in KeychainProtectedDataRootSecretStore (:196-275).
  `discardProtectedDataAuthorizationHandoffContextForPolicyChange` is on AppSessionOrchestrator.
  AppContainer closures at :733/:1046 (was :758/:1080); CypherAirApp lock overlay :386-390.
- Docs were stale exactly as user said (still "proposed", no #472/#475) — fixed.

## #477 post-mortem (prompt never displayed) — what PR-1 does differently
- #477 rendered LAAuthenticationViewHost BARE in a window `.overlay` (no frame, no chrome). The WORKING PoC rendered it
  as an explicit 160×160 view inside a visible material card in a ZStack. PR-1 reproduces the PoC card verbatim.
- Sheet caveat discovered: on macOS a SwiftUI .sheet is a separate attached window; a main-window overlay renders
  BEHIND it. Audit: all PR-1 acceptance flows (sign/decrypt/export/certification/revocation, encrypt-and-sign) are
  main-window content. Only Modify Expiry runs from a .sheet (KeyDetailView:306, MacPresentationHost:50) — its prompt
  placement is addressed in PR-2's key-expiry stage; interim: unwrap prompt renders in main window behind the sheet,
  Touch ID still operable (hardware), documented.

## Design decisions (PR-1)
1. Seam = plan's generic `presentingEvaluation` protocol (purpose: appSessionUnlock|perOperation|migration).
   MacAuthenticationPresenter = @MainActor @Observable, FIFO hand-off mutex + viewDidMount handshake (PoC shape,
   #477's serialization core which unit-tested green) + id-guarded viewDidMount + cancelActivePresentation()
   (invalidates context → evaluation throws; Cancel button + Esc in the card — PoC lacked this, needed for prod UX).
2. Host card: PoC-faithful — scrim (.ultraThinMaterial, blocks interaction = modality) + localizedReason headline +
   LAAuthenticationView at 160×160 + Cancel, .regularMaterial rounded card, mounted as .overlay immediately AFTER the
   lock-surface overlay in CypherAirApp (above lock surface, for PR-2 unlock reuse).
3. PrivateKeyAccessService: optional `authenticationPresenter` + `privateKeyControlStore` (default nil → existing unit
   tests unchanged; route engages only when both injected). macOS route: loadBundle → requireUnlockedAuthMode() →
   createAccessControl() → presentingEvaluation{evaluateAccessControl(.useKeyKeyExchange)} → thread context into
   off-main reconstruct via @unchecked Sendable carrier → invalidate after. iOS/visionOS: nil context, byte-for-byte.
4. Wiring: makeDefault injects presenter into KeyManagementService→PrivateKeyAccessService (production cutover).
   makeUITest does NOT (mock SE, UI-test bypass philosophy; otherwise MacUITests would hit real Touch ID). Both
   factories construct + expose container.authenticationPresenter (Mac presenter on macOS / passthrough elsewhere)
   so the host mounts in both.
5. SE convenience overloads deleted (red-line); 12 call sites get explicit `authenticationContext: nil`;
   PrivateKeyAccessService gets the real threading. MockSecureEnclave gains reconstruct context recording (+ counter)
   for positive/negative tests.
6. touchIDAuthenticationAllowableReuseDuration = 0 set centrally in present().

## Stage log (continued)

### Stage 1 — Seam introduction (DONE — commit be7706d)
- AuthenticationPresenting + Passthrough + MacAuthenticationPresenter + AuthenticationPresentationHost;
  AppContainer property + both factories; CypherAirApp mount after lock overlay; xcstrings (cancel + per-op reason);
  pbxproj membershipExceptions + both xcfilelists; MacAuthenticationPresenterTests (5) + Passthrough test (1).
- Build gotchas hit: (a) test files need `@testable import CypherAir` (membershipExceptions EXCLUDE Sources from the
  test-bundle compile — they exist for the RepositoryAudit snapshot, types come via the test host); (b) async
  `evaluateAccessControl` returns Bool, not Void — production now guards the Bool (false → AuthenticationError.failed).

### Stage 2 — Per-op route (DONE — commit 923c837)
- SE convenience overloads deleted (red-line); 45 call sites across 10 files → explicit `authenticationContext:`;
  PrivateKeyAccessService macOS route (persisted-mode AC → evaluateAccessControl(.useKeyKeyExchange) in-window →
  context threaded into off-main reconstruct → invalidate); KeyManagementService/AppContainer wiring (makeDefault
  wires route; makeUITest deliberately not); MockSecureEnclave context recording; 4 routing tests (pos+neg).

### Stage-verify verdicts (adversarial, fresh-context agents, 2026-06-10)
- Stage 2: PASS. 9/9 attack areas verified. 1 MINOR accepted: stub presenter never runs the evaluation closure, so the
  unit positive test can't prove evaluateAccessControl is invoked — covered by CypherAir-DeviceTests + the maintainer's
  manual Touch ID acceptance (which is the PR-1 gate anyway).
- Stage 1: PASS after resolution. F1 "host doesn't mount .appSessionUnlock inside AppLockSurfaceView" — deferred BY
  PLAN ("AppLockSurfaceView itself is unchanged in PR-1; the inside-mount is exercised in [app-session stage]");
  current mount sits above the lock overlay so unlock-purpose renders correctly as fallback. Tracked for PR-2 stage A.
  F2 "onCancel Task-hop race" — REFUTED: onCancel is sync+nonisolated (cannot touch @MainActor state); already-
  cancelled case is caught by the Task.isCancelled check inside the continuation closure; late cancel delivers on the
  next main-actor turn; cancellation unit test asserts release + reusability. F3 orphaned string — both commits ship
  in one PR; LocalizationCatalogTests green at tip.

### Stage 3 — Verification + PR (DONE)
- CypherAir-UnitTests (macOS, arm64e): 1318 tests, 0 failures.
- CypherAir-MacUITests: 25 tests, 0 failures.
- visionOS build probe: BUILD SUCCEEDED.
- NOT machine-verifiable here (awaits maintainer manual Touch ID test): actual LAAuthenticationView rendering,
  no-resign during prompt, single-prompt UX per op, context consumption with no second prompt on real SE.

## 2026-06-10 evening — maintainer manual test FAILED; root cause = environment (macOS 27 beta)

Symptom: per-op auth on macOS errors "Encryption failed: Authentication denied." with no visible prompt; backup
export same. (Launch/screen-lock system sheet = expected PR-1 interim, not a defect.)

Probe results (throwaway Tests/ServiceTests/InWindowAuthProbeTests.swift, real Touch ID stack, CLI Xcode 26.5 build):
- A/B/C: evaluateAccessControl(.useKeyKeyExchange) with paired LAAuthenticationView — detached, attached, attached+
  visible — ALL fail instantly: LA code **-1007**, NSDebugDescription **"Caller is not Apple signed."**
- D: paired view + evaluatePolicy(biometrics) — SAME -1007. → gate is on the EMBEDDED UI delegate, not the API.
- E: evaluateAccessControl, NO embedded view (system sheet) — ARMS and SUCCEEDS (user touched). API + threading healthy.
- F: system-sheet resign measurement INCONCLUSIVE from test host (app never active under xcodebuild).
- Maintainer's app log confirms: LAContext with uiDelegate:<LACUIAuthenticationViewModel> → events canceled (-4),
  verdict -1007 returned.

Environment timeline: PoC validated 2026-06-06 on macOS 26.x. 2026-06-09 (commit a3e2ad2): Mac → macOS 27.0 Golden
Gate dev beta (26A5353q) + Xcode 27 beta + entitlements enhanced-security-version-string 1→2. PR-1 built 06-10 on an
environment where the PoC's central result no longer holds. macOS 27 SDK EmbeddedUI headers byte-identical to 26.5 —
the gate is UNDOCUMENTED (beta regression or unannounced policy). CLI xcode-select = Xcode 26.5 (all my lanes);
maintainer IDE = Xcode 27 beta (additional unrelated breakage there: Foundation.ProgressReporter now collides with
UniFFI ProgressReporter in FFIIntegrationTests — separate toolchain-migration task).

**CONCLUSION: PR-1's implementation is architecturally sound (seam, threading, fail-closed ordering verified; system-
route crypto path proven by probe E) but the LocalAuthenticationEmbeddedUI presentation layer is BLOCKED for
non-Apple-signed callers on macOS 27 beta.** PR #491 stays open, unmerged, parked.

Probe matrix completed (2026-06-10 late evening), incl. the SwiftUI alternative found via Apple docs search:
| probe | view | API | result |
|---|---|---|---|
| A/B/C | AppKit LAAuthenticationView (detached / attached / attached+visible) | evaluateAccessControl | -1007 |
| D | AppKit LAAuthenticationView attached | evaluatePolicy | -1007 |
| G | SwiftUI LocalAuthenticationView (_LocalAuthentication_SwiftUI, macOS 13+) | evaluatePolicy | -1007 |
| H | SwiftUI LocalAuthenticationView | evaluateAccessControl | -1007 |
| E | none (system sheet) | evaluateAccessControl(.useKeyKeyExchange) | ARMS + SUCCEEDS |
| F | none (system sheet) | evaluatePolicy(biometrics) | ARMS + SUCCEEDS |

→ **ALL embedded/in-window authentication UI (AppKit + SwiftUI, both APIs) is denied to this non-Apple-signed app on
macOS 27 Golden Gate beta; the system-sheet routes are fully functional.** Docs (both SDKs) document NO such
restriction — and explicitly document the no-view case as falling back to the standard alert, not denying — so this
is an undocumented enforcement (beta regression or unannounced policy). NOT MTE: memory tagging is unrelated to this
code-signing policy check; MTE/MIE-v2 relates only to the separate weak_clear_no_lock crashes.

Maintainer field observation (same evening): on macOS 27 the old post-system-sheet stall ("stay for seconds–minutes")
seems largely fixed (one ~2s stall observed once). Unvalidated; product still targets macOS 26.5 where the old
behavior exists. Maintainer is considering: auth-lifecycle redesign still wanted but re-scoped; macOS password
fallback may RETURN as a normal feature (the biometric-only decision's premise — no in-window password entry — is
moot while in-window UI is unavailable).

Entitlement A/B (2026-06-10, maintainer-approved): CypherAirMacOS.entitlements enhanced-security-version-string 2→1,
rebuild, probe D → STILL -1007. File restored byte-for-byte. Since the PoC-era config (v1 + same hardened-process
keys) worked on macOS 26, the entitlements are fully exonerated: **the embedded-UI gate is purely the macOS 27 beta
OS.** Maintainer decision: no Apple Feedback (the original stall problem appears fixed by the same OS change).

GOAL CHANGE (maintainer, 2026-06-10): the auth-lifecycle refactor is re-scoped from "critical fix for post-auth
stalls" (Apple fixed that in macOS 27) to "architecture improvement — simpler, reliable, maintainable auth flow with
an explicit locked/unlocking/unlocked state model". Password fallback RETURNS as a normal macOS feature. API research
(Apple docs, both subsystems): app-session stays on LAContext.evaluatePolicy via the system sheet
(.deviceOwnerAuthentication ↔ userPresence incl. Apple Watch + password; .deviceOwnerAuthenticationWithBiometrics ↔
biometricsOnly; optional future: .deviceOwnerAuthenticationWithBiometricsOrWatch); private-key ops stay on
SecAccessControl-gated SE keys with implicit prompts, with optional explicit evaluateAccessControl pre-auth via
system sheet (probe E validated) to collapse double prompts (key expiry / provisioning); LARight/LARightStore
evaluated and rejected (duplicates ProtectedData rights + SE wrapping, high migration cost, no presentation gain);
embedded UI (AppKit LAAuthenticationView + SwiftUI LocalAuthenticationView) shelved until Apple unblocks — re-probe
each beta with Tests/ServiceTests/InWindowAuthProbeTests.swift (kept untracked).

## 2026-06-10 night — re-scope executed
- Maintainer decisions: (a) the .authenticating rule is redesigned INTO AppLockController (arch improvement, not
  guard-legitimization); (b) Modify Expiry single-prompt fix IS in plan (stage 2) — the only duplicate-prompt flow
  (provisioning verified single-prompt; correction to earlier stage-2 scope); no pre-auth generalization to other
  private-key ops (separate future proposal, may never happen); MIE crash investigated as its own track (chip
  task_ad6b4e96); Xcode 27 ProgressReporter fix chipped (task_5786dbd2); no Apple Feedback for the LA gate.
- PR #491 CLOSED with explanatory comment; seam parked on feat/p3-in-window-auth-pr1.
- Docs re-scope written in worktree ../cypherair-docs-rescope (branch docs/auth-lifecycle-rescope) and opened as
  **PR #492**: TARGET_DESIGN + ROADMAP fully rewritten — system-sheet presentation, both postures permanent,
  P3′ stages 0–3 (hygiene / .authenticating rule / single-prompt expiry / release gate incl. 26.5), P0 results
  annotated (not erased) with the macOS 27 addendum, decision log records both reversals.
- Next after #492 merges: stage-0 code PR (SE overload deletion + explicit contexts, salvaged from #491 minus the
  presenter), then stage 1.

## 2026-06-10 ~19:50 — #492 merged; stage 0 opened; soft mode mirrored
- Docs PR #492 MERGED (main = 9bd7729). Docs worktree removed.
- Soft-mode MTE entitlement mirrored into CypherAirMacOS.entitlements (uncommitted, matching the maintainer's iOS
  change — was previously only in CypherAir.entitlements, which does NOT sign macOS builds).
- **Stage 0 PR opened: #493** (branch refactor/se-explicit-auth-context, worktree ../cypherair-stage0): SE overload
  deletion + 45-site explicit authenticationContext sweep + MockSecureEnclave context recording. Re-derived
  mechanically from main (not cherry-picked) to exclude all presenter/route code. Lanes: 1308 unit / 25 MacUITests /
  visionOS probe — all green. Parked branch feat/p3-in-window-auth-pr1 retained per maintainer decision.
- MIE crash investigation: code audit CLEAN (key-gen flow, zeroing, FFI, unsafe inventory, weak refs); awaiting
  soft-mode fault logs — maintainer to repro key-gen→back→back with SanitizersAllocationTraces=tagged in the
  scheme env, then harvest logs → attribute allocation → Feedback draft.

## 2026-06-10 ~20:30 — stage 0 merged; stage 1 implemented + PR opened
- #493 (stage 0) MERGED by maintainer (no-CI fast merge), main = 71e21b0.
- **Stage 1 PR opened: #494** (branch feat/auth-lifecycle-authenticating-rule, worktree ../cypherair-stage0):
  isDrivingAppSessionAuth deleted; suppression (a) derived from lockState == .authenticating (identical window —
  state spans evaluation + post-auth fan-out); NEW deferred-away mechanism (b) for per-op prompts via
  AuthenticationPromptCoordinator.onOperationPromptsEnded + injected isOperationPromptActive — fixes the P1-interim
  grace=0 mid-operation lock regression. lockNow/screen-lock still win (not filtered); enterLocked clears pending
  deferral. Trace renamed to lock.authenticatingRule.*.
- Stage-verify adversarial pass: BLOCKER "multi-resign overwrite" REFUTED (both resign flavors are the same
  macResignActive signal; decision depends only on isForegroundActive at prompts' end — source is trace-only).
  Adopted hardenings: first-resign-wins guard, enterLocked clears pending (no double relock), AppContainer ordering
  comment, TARGET/ROADMAP precision edits ("decided at the prompts' end" replaces over-broad "supersedes"),
  +2 interleaving tests (multi-resign single decision; lockNow supersedes deferral).
- Lanes: 1317 unit / 25 MacUITests / visionOS probe — green. Manual smoke list for maintainer in the PR
  (4 scenarios incl. the away-and-stay-away mid-operation lock).
- Known design asymmetry (documented): user round-trips away-and-back during an op prompt → no lock at prompts'
  end (iOS locks on genuine .background immediately). Accepted: macOS resign is ambiguous; cover hides content
  while away; decision is fail-closed whenever the user is actually absent at decision time.

## 2026-06-11 early — MTE crash root-caused from live debug session (lldb via Xcode MCP)
- Crash thread (both repros identical): NSTextField dealloc (AppKit) during autorelease-pool drain in the display
  cycle → objc weak_clear_no_lock walks weak refs TO the text field → reads a weak-slot whose memory was already
  freed → EXC_ARM_MTE_TAG_FAULT. Allocation trace (Xcode pane): freed slot belonged to a SWIFT object
  (_swift_release_dealloc) destroyed during NSApplication event handling.
- Complementary console error in the same runs: "objc: Attempted to unregister unknown __weak variable at 0x16f..."
  (STACK addresses) — unbalanced objc_storeWeak/objc_destroyWeak, impossible to produce from safe Swift app code.
- Mechanism: SwiftUI's AppKit text-field bridging (SwiftUI TextField/SecureField → NSTextField on macOS) holds weak
  refs to the NSTextField from Swift-side bridge objects; on Golden Gate the weak-table bookkeeping is unbalanced in
  both directions (stale entry left behind on Swift-object dealloc; unknown unregister), and MIE's tag check turns
  the stale-entry touch into a crash at the text field's later dealloc.
- VERDICT: framework/runtime defect (SwiftUI↔AppKit bridge + objc weak table) under macOS 27 beta + MTE; app code
  exonerated (audit + the unbalanced-storeWeak signature). Repro = any text-field-heavy screen teardown — predicts
  import-key / password screens also crash on back-out, matching "in some other scenes".
- Also seen: glassEffect() multiple-updates-per-frame ×4 + AppKit layout recursion warning — beta SwiftUI instability,
  separate from the crash mechanism.
- Mitigation candidates: (1) Apple Feedback with both backtraces + console lines + deterministic repro (draft ready);
  (2) dev-time A/B: enhanced-security v2→v1 rebuild, retry repro (same code was crash-free under v1 on macOS 26;
  untested whether v1 on macOS 27 avoids it) — entitlements = maintainer's call; (3) wait for next beta.
- Evidence collection upgrade for next repro: lldb `breakpoint set -n objc_weak_error` catches the EARLier bookkeeping
  fault with the full stack of the code creating it (names the exact bridge component for the Feedback).

## 2026-06-11 ~05:20 — MTE crash REPRODUCED in a standalone sample; Rust fork exonerated
- Standalone reproducer at ~/coding/MTEWeakRepro (zero CypherAir code, zero Rust, stock Xcode 26.5 swiftc, arm64e,
  signed with maintainer's Apple Development identity + the same hardened-process/MIE v2 entitlements): auto-cycles
  NavigationSplitView → grouped Form with privacy-sensitive TextFields (writingTools disabled, focus engaged) →
  second push → pop → pop. CRASHED with the frame-for-frame identical signature (EXC_ARM_MTE_TAGCHECK_FAIL,
  weak_clear_no_lock ← NSTextField dealloc ← autorelease drain ← NSDisplayCycleFlush) AND the same
  "Attempted to unregister unknown __weak variable" console line.
- Discriminating signal: v2 of the sample (plain TextFields, no privacySensitive/writingTools, plain NavigationStack)
  survived 700+ cycles; v3 (faithful composition) crashed. → privacy-redaction / Writing Tools / field-editor weak
  bookkeeping implicated. arm64e REQUIRED (plain arm64 build = no MTE). LaunchServices refuses the ad-hoc/dev-signed
  bundle (-10825); direct exec works.
- CONCLUSIONS: (1) maintainer's Rust fork (coding/rust, branch carry196) fully exonerated — no Rust in the sample;
  (2) Apple framework/runtime bug (SwiftUI↔AppKit text-field weak bookkeeping × MIE v2 × Golden Gate);
  (3) exposure in CypherAir = every text-input screen teardown (keygen, import, password message, add contact,
  tag editing, reset confirmation phrase) — single root cause, no per-screen chase needed; re-test per beta via the
  sample (30s) + app smoke.
- FEEDBACK_DRAFT.md written in the sample folder; attachments listed (source, entitlements, .ips). Maintainer files it.
- 2026-06-11 ~05:55 — independent fresh-context verification (maintainer-requested, pre-filing): REPRODUCED from a
  clean rebuild (exact 12-frame match, mteState enabled, console line). CORRECTED my draft: the simplified control
  (plain fields, plain NavigationStack) ALSO crashes — in ~5s, 3/3 runs — so the privacySensitive/writingTools
  ingredient claim was FALSE (my earlier "survivor" run was never activated → focus never engaged). Trace-enabled run
  (SanitizersAllocationTraces=all) names the freed weak-slot owner: SwiftUI _AppearanceActionModifier.MergedBox
  (.onAppear box) deallocated via UpdateGroup.dispatchActions. FEEDBACK_DRAFT.md rewritten: control variant promoted
  to fast reproducer, trace-enabled .ips attached, launch caveat (-10825 → direct exec) documented, exception name
  corrected (EXC_ARM_MTE_TAGCHECK_FAIL). Ready to file.
- Submission text independently fact-checked by a second fresh agent (PASS-WITH-EDITS; SwiftUICore attribution,
  real crash timings, soft-mode hedge — applied). **FILED by maintainer as FB23066215 (2026-06-11)**, Developer
  Technologies & SDKs → SwiftUI → macOS 27.0 Seed 1 (26A5353q), Archive.zip + three standalone .ips attached.
  Per-beta retest: run ~/coding/MTEWeakRepro control variant ~1 min + key-gen→back→back in the app; cite FB23066215.

## 2026-06-11 — #494 review rework (6 findings, all dispositioned; commits 74f6e12 + 6da6a7d)
- Verified all 6 review findings with a Sonnet agent first (4 CONFIRMED, 1 corrected-consequences, 1 PARTIAL/overstated).
- FIXED: (#3 TOCTOU) coordinator gains session-began hook; AppLockController keeps a MainActor session COUNTER
  (not Bool — survives hop reordering across sessions); away rule consults the mirror; injected isOperationPromptActive
  closure removed. (#4) lockNow clears the deferral synchronously + isLockedState guard in promptsEnded
  (trace lock.authenticatingRule.deferredAwaySupersededByLock). (#5) write-once preconditions on both hooks + single
  wireOperationPromptLifecycle helper in AppContainer. (#1) documented-by-design comment (data already wiped + restart
  gate before the .unlocked transition).
- DEFERRED: (#2) post-auth fan-out resign drop — inherited from P1 guard, cover-mitigated, iOS fail-closed; deferral
  variants reintroduce settle heuristics → stage-3 trace-session checklist item. (#6) per-op MainActor hop is now
  load-bearing (maintains the mirror); cost ≤1 enqueue per crypto op.
- Post-rework stage-verify (fresh Sonnet adversary): NO BLOCKER; confirmed both new tests fail on pre-fix code;
  flagged the hop-delay race as untested at the pipeline level → added integration pin (real coordinator + real
  Task hops, resign delivered in the enqueue gap; fails under live-depth polling). Counter-leak audit clean
  (withOperationPrompt ends on throw; weak controller → fail-closed; LDR non-reset of counter = acceptable,
  restart-gated).
- Lanes: 1328/0 unit (incl. 8 local probe tests; PR delta +3 tests), 25/0 MacUITests, visionOS probe green.
  PR comment with the disposition table posted. Awaiting maintainer re-review of #494.

## 2026-06-11 — stage 1 MERGED (#494 → 81879e9); stage 2 implemented + PR opened
- #494 merged by maintainer (no-CI); branch deleted local+remote; branch list back to main + parked seam + PoC.
- **Stage 2 PR opened: #495** (branch feat/auth-lifecycle-single-prompt-expiry, commits 68c5e92 + invalidate-pin test):
  KeyMutationService.ExpiryAuthenticator injectable seam; production macOS = systemSheetExpiryAuthenticator
  (evaluateAccessControl(.useKeyKeyExchange) on persisted-mode AC, system sheet, reuse=0) running BEFORE
  unwrap/pending/journal; same context threaded into unwrapPrivateKey(authenticationContext:) (new optional param +
  @unchecked Sendable carrier into the @concurrent reconstruct) AND generateWrappingKey (pre-association covers wrap).
  invalidate exactly once (test-pinned via TrackingLAContext). Wiring: makeDefault only; makeUITest/Tutorial/iOS nil
  (byte-for-byte). New string keydetail.expiry.auth.reason (en+zh-Hans).
- Stage-verify (fresh Sonnet adversary): PASS — single-prompt traced end-to-end; fail-closed ordering verified
  (createAccessControl now throws BEFORE key material in memory — strictly tighter); no context escape; tests 1+2
  pin new behavior (fail on pre-commit). Adopted its gap: invalidate-once assertion test. Pre-existing findings
  recorded as BACKLOG (not this PR): (a) mode-switch crash-recovery window can leave a key's ACL one mode behind and
  modifyExpiry doesn't consult the rewrap journal; (b) @unchecked Sendable on KeyManagementService suppresses
  Sendable checking for stored closures.
- Lanes: 1331/0 unit (PR delta +3 tests), 25/0 MacUITests, visionOS probe green.
- Maintainer manual smoke for #495: Modify Expiry = ONE Touch ID prompt (was two); cancel aborts cleanly + retry works.
- After #495: P3′ stage 3 = verification gate (trace-enabled .authenticating session on macOS 27; review-#2
  fan-out observation item; macOS 26.5 validation pass before release).

## 2026-06-11 — STAGE 2 (#495) FAILED MANUAL TEST; ROOT-CAUSED; PR WITHDRAWN — REDO HANDOFF

**Maintainer-observed failure:** Modify Expiry still showed two system prompts AND surfaced
"This message is not addressed to any of your identities." Maintainer (rightly) withdrew trust in #495;
PR closed unmerged; stage 2 + stage 3 to be REDONE FROM MAIN by a fresh session. Process correction:
this stage was started without explicit maintainer approval — every future stage starts only on
explicit go-ahead.

**Root cause (proven by the maintainer's AuthTrace #269 capture, committed alongside this entry's PR):**
The new pre-authentication (expiryAuthenticator) ran OUTSIDE any operation-prompt session, so the
`.authenticating` rule had nothing to defer:
- #499–508 (10:24:51.8): the pre-auth system sheet's own resign → handleAwayEvent with mirror counter 0
  and state .unlocked → genuine away at grace=Immediately → APP LOCKED MID-ACTION (content cleared,
  all protected domains incl. key-metadata relocked).
- #512–525 (10:24:53.9): user touched (PROMPT 1, the pre-auth); unwrap ran with
  `reconstructKey hasAuthenticationContext=true → success in 5 ms, NO SECOND SE PROMPT` —
  **the context threading itself works on macOS 27; the single-prompt mechanism is sound.**
- #532+ (10:24:54.06): sheet dismissal → macBecomeActive → app locked → lock surface auto-unlock →
  PROMPT 2 = APP RE-UNLOCK (policy=userPresence, promptID=4) — not an operation prompt.
- Error: key-metadata domain relocked → catalogStore.containsKey == false →
  CypherAirError.noMatchingKey → presentation string is the decrypt-flavored
  "This message is not addressed to any of your identities." (CypherAirError+Presentation.swift:10).
- Fail-closed held: error fired before any pending bundle/journal; the key is untouched.

**Why machine verification missed it:** unit tests exercise KeyMutationService WITHOUT the lock
controller; MacUITests run under the auth bypass; both stage-verify passes attacked the mutation flow
and the .authenticating rule separately. The missing test class is COMPOSITION: lock controller +
prompt coordinator + a prompting flow, asserting new prompts enroll in the rule.

**REDO SPEC for the fresh session (stage 2′):**
1. Wrap the ENTIRE modifySoftwareExpiry action (pre-auth → unwrap → generate/wrap → promote) in ONE
   `authenticationPromptCoordinator.withOperationPrompt(source: "modifyExpiry")` session (inject the
   coordinator into KeyMutationService). The unwrap's inner session nests on the coordinator's stack;
   the stage-1 counter handles nesting. This also closes the pre-existing gap where the legacy second
   prompt (wrap) was never resign-protected.
2. Keep from #495 (conceptually proven, reimplement freely): injectable
   `KeyMutationService.ExpiryAuthenticator` seam (production macOS = one system-sheet
   `evaluateAccessControl(.useKeyKeyExchange)` on the persisted-mode AC, reuse=0, BEFORE any state);
   optional `authenticationContext:` on `unwrapPrivateKey` with the @unchecked Sendable carrier;
   context invalidated exactly once (TrackingLAContext test pin); makeDefault-only wiring
   (UI-test container + TutorialSandbox + iOS stay nil); xcstrings key keydetail.expiry.auth.reason.
3. NEW REQUIRED TEST: composition test — stub authenticator asserts
   `coordinator.isOperationPromptInProgress == true` while it runs, and a resign delivered during the
   pre-auth is DEFERRED (app stays unlocked) and decided at the prompts' end. This is the test that
   would have failed on #495.
4. Optional (maintainer to approve): replace the modify-flow's noMatchingKey guard error with an
   honest "key metadata unavailable / locked" error — the decrypt string reuse predates this work.
5. Verification: unit + MacUITests + visionOS probe + fresh stage-verify + maintainer manual smoke
   (ONE prompt total, no error, no re-unlock) BEFORE opening any PR — and get explicit approval to
   start the stage at all.
6. Stage 3 (after stage 2′): trace-enabled .authenticating observation session on macOS 27 (watch the
   deferred review-#2 fan-out item); 26.5 validation DROPPED per release decision (Sept / macOS 27 GA,
   deployment target bump is maintainer-owned).

GitHub PR #495 (closed) preserves the withdrawn implementation + this worklog snapshot as the
maintainer-viewable backup; local branch deleted to keep the workspace clean.

Open variables / next decisions (maintainer):
1. Entitlement A/B (enhanced-security-version-string 2→1, re-run probe D, restore) — distinguishes OS policy vs v2
   claim. Awaiting approval (protected file).
2. Apple Feedback for the embedded-UI gate (public API broken for third-party apps) — draft ready on request;
   attach probe test + log lines.
3. Whether macOS 27 is in the product support matrix for P3's release — decides whether this blocks P3 or merely
   blocks validation on this machine (product targets macOS 26.5 where PoC validated).
4. Real-app measurement: does the macOS 27 system sheet still resign the app? (Decides whether P3's in-window
   requirement even retains its original motivation on 27.)

Separate environmental issues (NOT PR-1): MTE tag faults in objc weak_clear_no_lock during key-gen→back→back etc.
(beta runtime / MIE v2 interaction; maintainer enabled soft-mode memory tagging for diagnostics); the four 06-10
16:3x .ips reports were my test stub's intentional fatalError (since fixed), not MTE.

## Known interim states (until PR-2)
- modifySoftwareExpiry: prompt 1 (unwrap) in-window but rendered in the MAIN window while the modify-expiry .sheet is
  up (macOS sheet = separate attached window; prompt sits behind/around it; Touch ID hardware still operable, Esc/
  Cancel in main window may be obscured); prompt 2 (generateWrappingKey) still the detached system sheet. Both fixed
  in PR-2 key-expiry stage. macOS is not shipped until all of P3 lands (delivery coupling), so no user exposure.
- App unlock, Local Data Reset, provisioning, migrations: still detached system sheet (PR-2 scope).
- Biometric-less Macs: per-op auth is now de-facto biometric-only on macOS (in-window prompt offers no password) —
  the decided-and-final posture, surfaced one PR early for per-op only.
