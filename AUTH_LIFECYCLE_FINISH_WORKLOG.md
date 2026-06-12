# Auth-Lifecycle Finish Worklog (one PR, per-stage commits)

Untracked working file — not committed unless asked. Session start: 2026-06-11.
Branch: `feat/auth-lifecycle-finish`. Plan: ~/.claude/plans/objective-finish-the-auth-lifecycle-compiled-eich.md (maintainer-approved; approval covers all four stages + opening the PR).

## Stage log

### Commit 1 — Stage 2′: single-prompt Modify Expiry (DONE — 425b45b)
- Redo of withdrawn #495 per the f166a66 redo spec: whole `modifySoftwareExpiry` action wrapped in ONE
  `withOperationPrompt(source: "modifyExpiry")` session (coordinator injected into KeyMutationService;
  inner `privateKey.unwrap` session nests). #495 mechanism reused: ExpiryAuthenticator seam,
  `systemSheetExpiryAuthenticator` (macOS, `evaluateAccessControl(.useKeyKeyExchange)`, reuse=0,
  pre-state), `unwrapPrivateKey(authenticationContext:)` + Sendable carrier, makeDefault-only wiring,
  `keydetail.expiry.auth.reason` (en+zh-Hans).
- Honest error (maintainer-approved): catalog guard now throws new `CypherAirError.keyMetadataUnavailable`
  (+ `error.keyMetadataUnavailable` en+zh-Hans). DecryptionService's `noMatchingKey` untouched.
- Tests: 4 unit (single-prompt identity on both SE ops + invalidate-once pin; declined → zero state;
  un-wired nil contexts; catalog-relock → keyMetadataUnavailable) + 2 composition
  (`OperationPromptLockHarness` + `ModifyExpiryOperationPromptCompositionTests`: pre-auth in-session,
  resign deferred → decided at prompts' end, both variants).

**Stage-verify (fresh Fable adversary, agent a1c7dfd117aa74e2f): PASS-WITH-FINDINGS, no blockers.**
- Required demonstration: with the session wrap removed (the #495 defect shape), the composition tests
  FAIL on both axes (in-session false + mid-action lock). Restored; full lane 1326/0 at HEAD.
- Finding 1 (MINOR): "5 tests" claim → suite has 4 (invalidate pin is assertions, not a 5th test).
  Resolution: wording only; PR description will use accurate counts.
- Finding 2 (MINOR): authenticator's evaluateAccessControl-throw path never invalidated the fresh context.
  RESOLVED in amend: do/catch — every failure path invalidates the never-returned context exactly once.
- Finding 3 (MINOR): pre-auth cancel surfaced as keychainError ("Failed to access secure storage.").
  RESOLVED in amend: LA cancel codes (userCancel/appCancel/systemCancel) → CypherAirError.operationCancelled,
  which ModifyExpiryScreenModel.shouldIgnore swallows by design → silent clean abort.
- Finding 4 (OBSERVATION): non-macOS now opens a coordinator session around modify-expiry (bookkeeping
  only; hooks wired only on macOS; prompts byte-for-byte). Accepted — this is the uniform rule's shape.
- Post-amend: targeted 6/6 green; commit amended 53eafee → 425b45b.

### Commit 2 — Uniform enrollment rule (DONE — 0e073cb)
- Wrapped: mode-switch (`AuthenticationManager.switchMode` → performSwitchMode, source
  `privateKeyProtection.switch`), App Access policy switch (extracted `AppAccessPolicySwitchWorkflow` +
  `AppContainer.makeAppAccessPolicySwitchWorkflow`, source `appAccessPolicy.switch`), Local Data Reset
  (`SettingsScreenModel.confirmLocalDataReset`, source `localDataReset`, coordinator via init param
  defaulting to `authManager.promptCoordinator`), provisioning (`keyProvisioning.generate` / `.import`).
- Tests: per-flow composition tests on the shared harness; workflow branch-logic suite (6);
  mode-switch early-exit balance; LDR counter-balance across `resetAfterLocalDataReset`.

**Stage-verify (fresh Fable adversary, agent a44289e5e5cab624e): PASS-WITH-FINDINGS, no blockers/majors.**
- Coverage sweep: rule confirmed uniform — all SE-prompt paths in-session or rule arm (a); crash recovery
  cannot prompt (bundle-store ops only); custody exclusion spec'd (ROADMAP §4); tutorial sandbox inert.
- Extraction verified behavior-preserving line-by-line vs the old CypherAirApp closure.
- Mutation demonstration: bypassing the generateKey wrap fails the composition test on both axes. Reverted.
- Findings (all OBSERVATION/MINOR, accepted, no code change): guard-placement asymmetry (no-change guard
  outside session for policy switch, inside for mode-switch — both sound); first-resign-before-began-hop
  race is fail-closed by design (pre-existing stage-1); policy switch has only the still-away composition
  variant (discard path identical controller code, covered via other flows); long-keygen deferral window
  = the approved trade-off; visionOS probe deferred to the PR-tip lane run.
- Full lane at HEAD: 1339/0.

### Commit 3 — P4 branded opaque lock surface (DONE — cef6bda)
- `AppLockSurfaceView` rewritten: opaque `.fill(.background)` base; brand column (winged-padlock
  `LockSurfaceBrandMark` imageset from the AppIconE middle layer, app display name, lock glyph);
  state-driven content, auto-invoke, and all `privacy.*` strings preserved verbatim; visionOS icon →
  `opticid`; a11y id `appLock.surface`. CosmeticPrivacyCover + CypherAirApp mount untouched.

**Stage-verify (fresh Fable adversary, agent a8212bb1ad881d1df): PASS-WITH-FINDINGS, no blockers/majors.**
- Lanes re-run fresh: unit 1339/0 (incl. LocalizationCatalogTests + repo audit); visionOS probe BUILD
  SUCCEEDED. macOS opacity verified EMPIRICALLY (offscreen render sampled alpha 1.0); compiled Assets.car
  contains the mark on macOS + visionOS; string sets byte-identical to P1 (no stale catalog risk).
- Finding 1 (MINOR) RESOLVED in amend: accessibility Dynamic Type overflow — ViewThatFits(.vertical) with
  ScrollView fallback so the retry button is always reachable; targeted suites re-run green.
- Accepted observations: visionOS opacity is an inference (unvalidated-by-decision); 689 KB universal PNG
  (provenance value, byte-identical to icon layer); open-shackle brand mark on a lock screen (maintainer
  judges visually); TARGET §2.A "opaque cover" wording tension vs .ultraThinMaterial (pre-existing P1
  wording — align during the P5 doc flip).

### Commit 4 — P5 current-state doc flip (DONE — 76d822b)
- SECURITY.md §4 blockquote → landed model; §5 lock-lifecycle ownership sentence updated. PRD.md §4.9 →
  two-layer cover/lock model + uniform rule; §5.6/§8.3 terminology aligned. TARGET → current-state incl.
  §3 arm (b) broadened to the uniform enrollment rule. ROADMAP → record-of-migration incl. stage 2′
  as-landed, uniform enrollment, release decision (~Sept, macOS 27 only, 26.5 dropped), inventory/map/
  tests/decisions updates.
- Fresh-context docs-consistency review (Sonnet): 4 issues found, 3 fixed in amend (ARCHITECTURE.md
  P1-deleted helper rows replaced with shipped helpers; PRD §5.6/§8.3 terminology; ROADMAP stage-2 prime
  marks); PRD §10.1 v1.0 changelog wording left as historical. Cross-doc agreement, claim-vs-code spot
  check, and links: CLEAN.

### Final lanes at tip (76d822b)
- CypherAir-UnitTests (macOS, arm64e): 1339/0. CypherAir-MacUITests: 25/0. visionOS probe: BUILD SUCCEEDED.
- PR #505 opened.

### 2026-06-11 — maintainer first manual pass + P4 rework (history rewritten)
- Maintainer verified OK: both mode switches + Local Data Reset. Feedback: lock-surface lock imagery
  "really bad" — remove the icon(s), text is enough; then explicitly: remove LockSurfaceBrandMark.png
  TOTALLY from the PR (history included).
- Rework: AppLockSurfaceView header is now text-only (app name + new `privacy.locked.title` "Locked"/
  "已锁定" caption); both images removed (brand mark + lock.fill glyph); functional biometric icons on
  retry button + locked-out card retained. Doc wording updated (PRD §4.9, TARGET §5 + status, ROADMAP
  P4/status/map, ARCHITECTURE row).
- History rewrite via soft-reset to 0e073cb: P4 recreated as a844e65 (image never added anywhere on the
  branch — verified `git log -- '*LockSurfaceBrandMark*'` empty), P5 recreated as 4d029cb, plus 25396e4
  carrying the maintainer's CURRENT_PROJECT_VERSION 14310→14311 bump (user-owned metadata, preserved).
  Force-pushed with lease; PR body updated (remaining manual items: Modify Expiry, provisioning,
  lock-surface re-check, trace checklist).
- Lanes at rewritten tip: unit 1339/0 (same content as pre-rewrite run), MacUITests 25/0, visionOS probe
  BUILD SUCCEEDED.
