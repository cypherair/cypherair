# SE Custody Phase 7 — Campaign Worklog (untracked; not part of the PR)

Branch: feat/se-custody-phase7-ui-exposure. Plan: ~/.claude/plans/please-read-github-issue-cryptic-peach.md.
Decisions recorded: issue #501 comment (2026-06-12, posted as step 0).

## Stage 7A — family generation UX + vocabulary flip (43cdc46, amended)

- Unit lane: PASS (CypherAir-UnitTests, macOS arm64e) after registering new files in git
  (RepositoryAudit snapshot requires git-tracked sources).
- Stage-verify (Fable adversary, fresh context): **PASS-WITH-FIXES**
  - F1 MAJOR: ImportConfirmView still used "Universal Compatible (Profile A)"/"Advanced
    Security (Profile B)" (import.profileA/B). RESOLVED: switched to
    contactKeyKindDisplayName under "Key Type" (import.keyType); catalog keys swapped.
  - F2 MINOR: portableCompatible keeps "all PGP tools" claim — SPEC-COMPLIANT (decision 7
    in the issue comment: portable rows keep current claims). No change.
  - F3 OBSERVATION: locked device-bound family would dead-end — no current caller
    (tutorial locks software family). Accepted; no code change.
  - F4 OBSERVATION: banned-claims test guard covers family presentation strings, not the
    commitment-sheet/post-gen catalog copy. Adversary manually scanned en+zh-Hans: clean.
    Accepted for now; candidate hardening in 7C.
  - F5 OBSERVATION: plan deviation +1 file (PGPKeyProfile+ContactPresentation.swift) +
    contact vocabulary call ("GnuPG Compatible"/"Modern (RFC 9580)") — flagged in commit
    message for maintainer review at PR time.
  - F6 NIT: stale KeyGenerationView doc comment. RESOLVED.
  - F7 NIT: theoretical dual-sheet handoff race on iOS. Accepted; no action.
- Verified clean: lands dark (production policy untouched, no DI wiring); decision 1/2/4/5
  compliance incl. zh-Hans banned-term scan; catalog integrity (25+1 added, 9+3 removed,
  0 modified); negative space (resolver/AppContainer/PgpMobile/pgp-mobile untouched);
  audit-rule compliance; tutorial parity; UI-test identifier stability.
- Final 7A commit after amend: 2f11825.

## Stage 7B — key detail / list / backup surfaces (9addcda, amended)

- Unit lane: PASS after two fixes during the stage: (a) nonisolated static mapping helper
  (tests call it off-MainActor); (b) healthy-detail test injects a healthy report — the
  hidden-generation test rig wires no recovery classifier, so the real report is .empty
  and correctly reads degraded (fail-visible). Added explicit missing-report fail-visible
  test. Production wires the classifier (AppContainer.swift:715,746 — verified).
- Stage-verify (Fable adversary, fresh context): **PASS-WITH-FIXES**
  - F1 MAJOR CARRY-FORWARD → added to 7D checklist: High Security mode-switch flow is
    custody-blind — SettingsScreenModel.hasBackup nag unsatisfiable for device-bound
    keys; AuthenticationManager backupRequired hard gate blocks High Security for
    device-bound-only users; PrivateKeyRewrapWorkflow receives ALL fingerprints and
    would FAIL the whole mode switch for mixed populations (no software bundle for SE
    keys). Dark today; must be fixed in 7D with positive+negative tests.
  - F2 MINOR: revocation-unavailable degrade clause untested (commit msg overclaimed).
    RESOLVED: test now exercises public + revocation disjuncts separately.
  - F3 MINOR: BackupKeyScreenModel.isDeviceBound was init-captured (fail-open for
    not-yet-loaded keys; no reachable path found, service fails closed regardless).
    RESOLVED: now computed from keyManagement.keys.
  - F4 NIT: keydetail.deviceBound.status.title intentionally not added (single-label
    degraded row) — do not "fix" later.
  - F5/F6/F7 OBSERVATIONS: fail-visible default documented; pre-existing
    keydetail.sharePublicKey defaultValue drift (out of scope); keys/report sync
    verified atomic-enough on all mutation paths incl. deleteKey.
  - Adversary verified ordinal mapping against the real producer (same enumeration,
    compactMap+defer SE-only counter) and ran 70 tests green incl. LocalizationCatalog
    + ArchitectureSourceAudit.
- Final 7B commit after amend: 17a61fb.

## Stage 7C — per-category failure presentation (7b3cda1)

- Unit lane: PASS first run.
- Stage-verify (Fable adversary, fresh context): **PASS**
  - F1 INFO → folded into 7D: SE generation path errors (SecureEnclaveCustodyHandleError)
    bypass per-category copy via the keyGenerationFailed fallback; normalize to
    .keyOperationUnavailable(category: error.failureCategory) at 7D.
  - F2 INFO → folded into 7D: replace keyGenerationFailed(reason: <category>.rawValue)
    throws (KeyManagementService:257-259, SecureEnclaveCustodyGenerationService:55-59)
    with .keyOperationUnavailable(category:).
  - F3 LOW optional: zh-Hans sanitization regression guard (adversary verified current
    zh strings clean programmatically). Deferred.
  - F4 INFO: error.seUnavailable effectively dead copy (zero production throw sites) —
    candidate later cleanup, not 7E-blocking.
  - Adversary verified: 27/27 coverage, no default, catalog byte-match en, single-hunk
    catalog diff, copy sanitization both languages, cancel-copy neutrality end-to-end
    incl. the FFI mapping path (PGPErrorMapper → .localAuthenticationCancelled passes
    CypherAirError.from unmapped, not swallowed by shouldIgnore), alert paths render
    errorDescription, tests non-tautological.

## Stage 7D — exposure flip + production DI (final: see git log; amended twice)

- Unit lane: PASS after re-pinning nine route tests from the retired
  production-blocked shape to the new explicit testSecureEnclaveOperationsBlocked
  policy (resolver-before-handle-store ordering preserved; failInventory +
  Unexpected*DigestSigner probes intact).
- Stage-verify (Fable adversary, fresh context): **FAIL → fixed → FIX-VERIFIED**
  - F1 BLOCKER: interrupted-rewrap RECOVERY path (AppContainer post-unlock)
    still enumerated ALL catalog keys; bundleless (device-bound) fingerprints
    classify .unrecoverable → block target-mode persistence + journal destroyed
    (silent High-Security ACL downgrade on mixed populations after a crash
    mid-mode-switch). RESOLVED: shared PGPKeyIdentity.softwareCustodyFingerprints(in:)
    used by both the switch path and the recovery call site; doc contracts updated;
    regression tests pin software-only recovery success AND the bundleless poisoning
    failure mode; source-pin audit test guards both call sites against regression.
    Fix re-verified by a second fresh Fable adversary: FIX-VERIFIED.
  - F2 MINOR: unrouted selective-revocation fail-closed negative test added.
  - F3 MINOR: empty-population backupExpectationSatisfied comment corrected
    (deliberate change from historical false; safe — noIdentities fires first).
  - F4 NIT deferred → flagged for maintainer: device-bound-only mode switch
    surfaces "No private keys found. Generate or import a key first." (false copy;
    fail-closed behavior correct). Candidate follow-up: dedicated copy or disabled
    mode rows for device-bound-only populations.
  - F5 NIT deferred: test-support naming still says "hidden" (makeHiddenSecureEnclave-
    GenerationService etc.) — cosmetic cleanup candidate.
  - F6: SECURITY.md §3 "blocked in production policy" now false → 7E fixes.
  - F7/F8/F9 OBSERVATIONS: optional blocked-policy matrix pin; production-policy
    end-to-end route test deemed marginal redundancy; rollback-failure-over-
    cancellation precedence is pre-existing and arguably correct.

## Stage 7E — docs alignment (amended once)

- Stage-verify (Fable adversary, fresh context): **PASS-WITH-FIXES** — every claim
  ADDED by the commit verified accurate against code (incl. PRD §3.3 copy byte-match
  vs catalog, anchors, governance shape, §4 generic-coverage judgment call); the
  sweep was incomplete. ALL RESOLVED in the amend:
  - F1 CODE_REVIEW.md checklist "remains hidden/test-only"/"not product-selectable"
    → post-exposure invariants.
  - F2 PERSISTED_STATE_INVENTORY.md hidden/test boundary rows → production boundary,
    release-gated.
  - F3 SECURITY.md §10 "Future" label dropped.
  - F4 ARCHITECTURE.md recovery-classifier row + Rust tree annotation + "Hidden
    generation recovery" + "integration planning" line.
  - F5 PRD §4.1 flow line + §6 key-detail acceptance → family vocabulary.
  - F6 TDD.md "Hidden/test generation" → custody generation.
  - F7 ROADMAP present-tense falsehoods fixed (line 73) + PR 9B superseded marker.
  - F8 PRD High Security safeguard lines custody-qualified.
  - F9 INFO accepted: bespoke-but-honest status headers (governance class drift
    noted for the maintainer); F10 INFO: IMPLEMENTATION_REFERENCE residuals covered
    by the reading note; README "Dual Encryption Profiles" left (defensible while
    release-gated).
