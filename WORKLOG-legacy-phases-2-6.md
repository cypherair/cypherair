# Worklog — Strict Legacy Cleanup Phases 2–6

Branch: `cleanup/legacy-phases-2-6` (from main @ 69a3680).
Spec: docs/LEGACY_CLEANUP.md (Doctrine, Test Policy, per-phase targets, Guardrails, Validation Matrix).
This file is a working record only — never committed.

Validation lane facts (verified 2026-06-10):
- Unit lane: `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS,arch=arm64e'` (TESTING.md §2.4 lines 64–65, 377–378, 405–406).
- Roadmap Validation Matrix row "ProtectedData/settings/..." says `-destination 'platform=macOS'` — STALE (missing `arch=arm64e`). Fix with first roadmap edit (Phase 2 commit).
- Rust lane: `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- Phase 6 rebuild: pinned stage1 `./build-xcframework.sh --release` per rust-sync skill.
- Known flake: LocalDataResetServiceTests in full suite — re-run; passes in isolation. Never weaken a test.

## Phase 2 — Protected Settings And Ordinary Settings Cleanup

Status: COMPLETED 2026-06-10 (verifier PASS).

### Verified targets (all present at listed locations before edit)
- ProtectedSettingsStore.swift: `PayloadV1` (L14), `OpenedSnapshot.requiresOrdinarySettingsMigration` (L25), `migrationAuthorizationRequirement()` (L142), `ensureCommittedAndMigrateSettingsIfNeeded` (L186), `migrateOpenedSettingsSnapshotIfNeeded` (L845), decode `case 1` (L895), `legacyInitialPayload` (L1022), `legacyOrdinarySettingsSnapshot` (L1032), `removeLegacySettingsSources` (L1036), legacy `clipboardNotice` UserDefaults source (L1023-25). Also the v1-upgrade-only machinery feeding them: `upgradeCommittedSettingsPayloadIfNeeded` (L702), `CommittedSettingsUpgradeFailure` (L30), `committedSettingsUpgradeFailure(for:)` (L759), `isFoundationFileIOError` (L815, only user is the upgrade classifier), `OpenedSnapshot.schemaVersion` (L23, only feeds migration checks).
- ProtectedOrdinarySettingsPersistence.swift: `ProtectedOrdinarySettingsLegacyKeys` (L9), `LegacyOrdinarySettingsStore` (L17). Protocol `ProtectedOrdinarySettingsPersistence` stays (current conformer ProtectedSettingsOrdinarySettingsPersistence).
- AppConfiguration.swift: `clipboardNoticeLegacyKey` (L68, only remaining uses are store legacy paths + resetPersistentKeys), resetPersistentKeys entries `clipboardNoticeLegacyKey` + `+ LegacyOrdinarySettingsStore.persistentKeys` (L104, L113). `AuthPreferences` keys + `legacyRequireAuthOnLaunchKey` stay (Phase 4).
- Callers: AppContainer.swift L216 (post-unlock opener), L1001-1003 (authenticated-test-bypass LegacyOrdinarySettingsStore), TutorialSandboxContainer.swift L91, CypherAirApp.swift L181-196 (migration authorization + ensureCommitted closures), ProtectedSettingsHost.swift L105-106/126-127, ProtectedSettingsAccessCoordinator.swift (dependency L28-29, settingsMigration traces L332-362, preauth block L424-460).
- Test support: `ProtectedSettingsPayloadV1` (TestSupport L367), `setLegacyOrdinarySettings` (L497), `assertLegacyOrdinarySettingsRemoved` (L514), `ProtectedDataTestAppLegacyOrdinarySettingsStore` typealias (L36). `KeyMetadataPayloadV1` stays (Phase 3).
- Tests: ProtectedSettingsDomainTests — migration-requirement test (L78), v1 migration (L155), legacy conflict (L200), committed-upgrade family (L246, 283, 324, 381, 419, 458), corrupt+legacy-sources (L499). LegacyOrdinarySettingsStore fixture uses: SettingsScreenModelTests L28, EncryptScreenModelTests L65, ModelTests L1123, TutorialSessionStoreTests L452, AppStartupCoordinatorTests L178.
- Guardrails: item4 allowance for ProtectedSettingsStore.swift (lockstep delete); item3 allowance entry for ProtectedSettingsStore.swift (Phase 2 clears that occurrence; PrivateKeyControlStore/AuthenticationEvaluable stay for Phase 4); add tokens for newly retired settings symbols incl. shared `PayloadV1` with per-path exception for KeyMetadataDomainStore until Phase 3.

### Key analysis findings
- Gate decision `noProtectedDomainPresent` only fires when committedMembership.isEmpty && sharedResource == .absent (ProtectedDataAccessGateClassifier L47-57) — exactly the state where migrationAuthorizationRequirement() returns .notRequired. The join-existing-shared-resource creation path arrives via authorizationRequired/alreadyAuthorized gates which authorize first. So the coordinator preauth block is removable without losing a reachable path; store keeps both creation branches (first-domain provision + join via currentWrappingRootKey).
- `.firstRunDefaults` == LegacyOrdinarySettingsStore.loadSnapshot() on empty defaults (gracePeriod 180, onboarding false, theme systemDefault, encryptToSelf true, tutorial 0) — in-memory rewrite is behavior-preserving for tutorial sandbox (suite wiped at init) and UI-test bypass (fresh UUID suite; onboarding override applied via applyOnboardingCompletionOverrideForTesting).
- UI tests do not seed `com.cypherair.preference.*` legacy keys (grep over UITests/ empty).

### Planned Doctrine-covered extras (beyond literal roadmap list — call out in commit/PR)
- `upgradeCommittedSettingsPayloadIfNeeded` + `CommittedSettingsUpgradeFailure` + `committedSettingsUpgradeFailure(for:)` + `isFoundationFileIOError`: v1→v2 committed-upgrade machinery; only callers are the removed migration paths.
- `OpenedSnapshot.schemaVersion`: source-schema tracking that only feeds requiresOrdinarySettingsMigration + migration verification → dead.
- `ProtectedSettingsStore` init `defaults:` parameter if fully dead after legacy source removal (store's only UserDefaults uses are the legacy paths) → remove param + ripple to constructors.
- Replacement composition: new `InMemoryOrdinarySettingsStore` (current-model in-memory fixture, sanctioned by roadmap "current in-memory fixtures") in new Sources/Models file + pbxproj/membershipExceptions + both RepositoryAudit xcfilelists.
- Store method rename `ensureCommittedAndMigrateSettingsIfNeeded` → `ensureCommittedIfNeeded` (matches PrivateKeyControlStore/sentinel convention; carries only current creation behavior, migration deleted). Coordinator/host dependency renamed to `ensureCommittedSettingsIfNeeded`; traces `protectedSettings.settingsMigration.*` → `protectedSettings.ensureCommitted.*`.

### Validation
- `xcodebuild build-for-testing` (macOS,arch=arm64e): pass (first run failed on RepositoryAudit stale-source check until `git add` of the new file — expected per build contract).
- Targeted (matrix "touching reset" row + phase tests): LocalDataResetServiceTests 13/13, ProtectedSettingsDomainTests 7/7, ArchitectureSourceAuditTests — all pass (62 executed, 0 failures).
- Full unit lane `xcodebuild test -testPlan CypherAir-UnitTests -destination 'platform=macOS,arch=arm64e'`: 1327 tests, 0 failures (log /tmp/p2-full.log). No LocalDataResetServiceTests flake this run.
- Roadmap edits in same commit: Phase 2 status line, stale matrix destination fixed to `platform=macOS,arch=arm64e` (first roadmap edit), guardrail-coverage paragraphs updated.
- Docs updated: ARCHITECTURE.md (coordinator description, post-unlock opener paragraph, UserDefaults tree), SECURITY.md §ordinary-settings paragraph (v1 upgrade sentence removed), TESTING.md (L58 + L156 settings coverage language), PERSISTED_STATE_INVENTORY.md (6 settings rows).

### Security-sensitive edits (CLAUDE.md edit-then-explain)
- `Sources/Security/ProtectedData/ProtectedSettingsStore.swift` — removed PayloadV1, v1 decode, migration/upgrade machinery, legacy UserDefaults seeding/cleanup, migrationAuthorizationRequirement; renamed ensureCommittedAndMigrateSettingsIfNeeded→ensureCommittedIfNeeded; dropped dead `defaults:` init param. Positive tests: fresh-install creation, ensure-committed no-op, mutations persist, reset preflight/recreate. Negative tests: corrupt current payload fails closed→recoveryNeeded, corrupt wrapped DMK fails closed→recoveryNeeded, join-without-key throws missingWrappingRootKey (RecoverySentinelTests).
- `CypherAir.xcodeproj/project.pbxproj` + both RepositoryAudit xcfilelists — registered new Sources/Models/InMemoryOrdinarySettingsStore.swift.

### Verifier verdict
PASS (fresh-context adversarial subagent, agentId ae687cfb206f87e4b). Findings & dispositions:
1. concern — transient-I/O failures at Settings open now persist recoveryNeeded (upgrade-path retryable classifier deleted with the migration entry). Verified: open-path catch byte-identical pre/post; recoveryNeeded self-heals on next successful open. Disposition: recorded, no new behavior added (out of phase scope); flag in PR summary as possible follow-up.
2. concern — AuthPreferences.gracePeriodKey (AuthenticationEvaluable.swift:398) orphaned by Phase 2. Disposition: remove in Phase 4 under "AuthPreferences keys used only as old migration sources".
3. concern — stale exemplar citation docs/AUTH_LIFECYCLE_REDESIGN_ROADMAP.md:141. Disposition: FIXED in commit 42d2264.
4-7. notes — stale-gate race degrades to fail-closed retry (authorized consequence); item4 per-path exception breadth (by design, closes at Phase 3); UI-test bypass ephemerality verified safe (MacUITests run optional, not matrix-required); ProtectedDataStorageRootTests schemaVersion:1 is generic infra metadata (compliant, untouched).
Carry-forward: Phase 3 must remove KeyMetadataDomainStore.PayloadV1 + item4 exception in same commit; check whether retryable-vs-recovery classification rides on migration machinery being deleted in Phases 3–5 and decide explicitly.

### Commits
- 65f952a refactor: retire Phase 2 protected-settings and ordinary-settings legacy surface
- 42d2264 docs: repoint paused P3 plan exemplar after Phase 2 settings rename

## Phase 3 — Key Metadata Cleanup
Status: COMPLETED 2026-06-10 (verifier PASS).

### Verified targets
- KeyMetadataStore.swift: KeyMetadataLegacyMigrationOutcome (L18), KeyMetadataMigrationSourceItem (L29), KeyMetadataMigrationSourceSnapshot (L35), KeyMetadataStore class (L42, all CRUD against metadataAccount/defaultAccount rows + loadMigrationSourceSnapshot L60 + cleanupMigrationSourceItems L79 + migrateLegacyMetadataIfNeeded L120). KeyMetadataLoadState + KeyMetadataPersistence protocol are CURRENT (domain store conforms) → move to new KeyMetadataPersistence.swift; file deleted.
- KeyMetadataDomainStore.swift: PayloadV1 (L67), DecodedPayload.sourceSchemaVersion (L72), OpenedSnapshot.sourceSchemaVersion (L80), legacyMetadataStore (L83/97/104), migrationWarning (L92), decode case 1 (L489), upgrade-on-read writeback (L214-225), cleanupLegacyRowsMatchingOpenedPayload (L530), updateMigrationWarning (L580), migrationWarningMessage (L589, + its own orphaned `app.loadWarning.keyMetadataMigration` string), mergedIdentities (L596, migration-only), legacy snapshot seeding in ensureCommittedIfNeeded (L132-137,169-178) and continuePendingCreate (L626-634). authenticationContext params on ensureCommitted/open feed only legacy reads → drop.
- KeyCatalogStore: migrateLegacyMetadataIfNeeded passthrough (L26-44), updateRevocation (L73-91).
- KeyManagementService: KeyMetadataStore fallback (L63-64) → metadataPersistence becomes required; legacyMetadataMigrationLoadWarning (L13), legacyMetadataMigrationCompletedInProcess (L33), completeKeyMetadataLoad migrationWarning param + hasMigrationWarning trace (L167-182), migrateLegacyMetadataAfterAppAuthentication (L184), clearLegacyMetadataMigrationLoadWarning (L225), warning message + `app.loadWarning.legacyMetadataMigration` (L239).
- AppSessionOrchestrator.borrowAuthenticatedContextForMetadataMigration (L140) — ZERO production callers; metadataMigration trace purpose L145.
- AuthTraceMetadata: metadataPrefix service/prefix classifications (L16-18, L57-59) + metadataAccount account kind.
- LocalDataResetService: metadataAccount reset pass (L114-118), remainingMetadataAccountServices postcondition (L391-395, L408).
- KeyMutationService.cleanupLegacyMetadataRows (L289-304) + call (L238).
- KeyExportService empty-revocationCert backfill branch (L56-78).
- KeychainConstants: metadataService (L106), metadataPrefix (L111), metadataAccount (L126).
- PGPKeyIdentity: init(from:) tolerant defaults (L147-154) — strict decode makes custom init(from:) + CodingKeys identical to synthesized → delete both; memberwise default args (L119-120) → required params. PGPKeyProfile.defaultCustodyKind exists only to feed the tolerant defaults → orphaned after change (Doctrine extra).
- Production compositions: AppContainer legacyKeyMetadataStore (L632) + opener WithContext closures (L705/717) + makeUITest KeyManagementService L1048 (relied on fallback); TutorialSandboxContainer KeyManagementService L99 (same). ProtectedDataPostUnlockOpenContext.authenticationContext + WithContext init exist only to carry the migration LAContext → Doctrine extras once metadata params drop.
- Replacement fixture: new InMemoryKeyMetadataStore (current-model, sanctioned "current in-memory fixtures").
- Carry-forward check (Phase 2 verifier): KeyMetadataDomainStore open-path error classification is generic and not riding on the removed upgrade writeback — nothing to port.

### Deviations / Doctrine-covered extras (call out)
- Delete whole KeyMetadataStore.swift; protocol+state move to KeyMetadataPersistence.swift (current types, not legacy relocation).
- DecodedPayload wrapper struct deleted (only carried sourceSchemaVersion).
- ProtectedDataPostUnlockOpenContext struct + WithContext init removed; openers revert to (Data) closures.
- PGPKeyProfile.defaultCustodyKind removed if orphaned.
- KeyManagementService.metadataPersistence becomes required (no silent fallback).
- borrowAuthenticatedContextForMetadataMigration test in ProtectedDataAppSessionOrchestratorTests deleted with the method.

### Validation
- build-for-testing iterations until clean (12 rounds; logs /tmp/p3-build*.log).
- Targeted: KeyMetadataProtectedDomainTests 12/12, KeyManagementServiceMetadataTests 4/4, KeyManagementServiceRevocationSelectionTests 24/24, LocalizationCatalogTests 5/5 pass. ArchitectureSourceAuditTests custody-containment failure → fixed by adding KeyProvisioningService allowance (explicit custody fields are now written at provisioning — the storage boundary). LocalDataResetServiceTests temporary.remaining flake → passed in isolation (known flake protocol; never weakened).
- Full unit lane `xcodebuild test -testPlan CypherAir-UnitTests -destination 'platform=macOS,arch=arm64e'`: first run 1313 tests/4 failures → repaired (2 tests moved from Keychain-error injection to persistence failNextUpdate injection, profile-B Keychain count 4→3, tolerant-decode old-input test DELETED per Test Policy); final run **1312 tests, 0 failures** (log /tmp/p3-full2.log), no flake.
- xcstrings: both `app.loadWarning.legacyMetadataMigration` and `app.loadWarning.keyMetadataMigration` removed (32-line diff, no reflow).
- Roadmap: Phase 3 status line; guardrail-coverage paragraphs updated (item2 extended tokens, item4 PayloadV1 exception removed in lockstep, item7 allowances removed).
- Docs: ARCHITECTURE.md (module table, KeyMetadataDomainStore description, Keychain layout tree + legacy row note), SECURITY.md (metadata storage note, revocation note, KeyMetadataDomainStore paragraph), TESTING.md (L58, pending-create legacy bullet removed, revocation backfill bullets), PERSISTED_STATE_INVENTORY.md (PGPKeyIdentity row).
- During test rewrite, self-caught and removed a drafted test that reconstructed the old record shape (missing custody fields) — forbidden old-input failure test.

### Security-sensitive edits (CLAUDE.md edit-then-explain)
- `Sources/Security/KeyMetadataStore.swift` DELETED (entire legacy Keychain metadata store + migration types); current `KeyMetadataLoadState`/`KeyMetadataPersistence` moved to new `Sources/Security/KeyMetadataPersistence.swift` together with new current-model `InMemoryKeyMetadataStore` (tutorial/UI-test/test fixture). Positive: domain CRUD/persistence tests; negative: corrupt/missing/unsupported-schema fail-closed tests.
- `Sources/Security/ProtectedData/KeyMetadataDomainStore.swift` — removed PayloadV1, sourceSchemaVersion (DecodedPayload wrapper deleted), decode case 1, upgrade-on-read writeback, legacyMetadataStore, migrationWarning surface, cleanupLegacyRowsMatchingOpenedPayload, legacy seeding in ensureCommitted/continuePendingCreate (now Payload.initial(identities: [])), authenticationContext params dropped. Positive: fresh-install/mutation/recovery tests; negative: corrupt current generation, mismatched custody, unsupported schema → recoveryNeeded.
- `Sources/Security/KeychainManageable.swift` — metadataService/metadataPrefix/metadataAccount constants removed; listItems doc updated.
- `Sources/Security/AuthTraceMetadata.swift` — metadata service/prefix/account trace classifications removed.
- `Sources/Security/ProtectedData/AppSessionOrchestrator.swift` — borrowAuthenticatedContextForMetadataMigration removed (zero production callers).
- `Sources/Security/ProtectedData/ProtectedDataPostUnlockCoordinator.swift` — ProtectedDataPostUnlockOpenContext struct + WithContext init removed (existed only to carry the migration LAContext); openers back to (Data) closures.
- `Sources/App/Settings/LocalDataResetService.swift` — metadataAccount reset pass + remaining-rows postcondition + failure key removed. Positive/negative: LocalDataResetServiceTests reset coverage incl. marker rows.
- `Sources/Models/PGPKeyIdentity.swift` — custom tolerant init(from:) + CodingKeys deleted (strict synthesized Codable); memberwise default args removed (explicit fields required). `Sources/Models/PGPKeyProfile.swift` — defaultCustodyKind removed (existed only to feed the tolerant defaults).
- `Sources/Services/KeyManagement/KeyExportService.swift` — revocation backfill branch removed; export fails closed (.revocationArtifactUnavailable) on missing artifact, custody-independent, no unwrap. Negative test added (software custody) + existing SE-custody fail-closed test retained.
- `Sources/Services/KeyManagement/KeyMutationService.swift` — cleanupLegacyMetadataRows removed. `KeyCatalogStore.swift` — migration passthrough + updateRevocation removed.
- `Sources/Services/KeyManagementService.swift` — KeyMetadataStore fallback removed; metadataPersistence REQUIRED; legacy migration warning surface + migrateLegacyMetadataAfterAppAuthentication + clearLegacyMetadataMigrationLoadWarning removed; completeKeyMetadataLoad(migrationWarning:) → completeKeyMetadataLoad(source:).
- pbxproj + both RepositoryAudit xcfilelists — KeyMetadataStore.swift → KeyMetadataPersistence.swift swap (git rm/add done).

### Deviations / Doctrine-covered extras (called out)
- As planned in "Planned extras": whole-file delete + protocol relocation; DecodedPayload wrapper; post-unlock context struct; required metadataPersistence; defaultCustodyKind; borrow-test deletion.
- KeyExportService kept `privateKeyAccessService` dependency (still used by exportKey).
- Audit rule `phase5KeyManagementCustodySwitchContainment` gained a KeyProvisioningService allowance (new explicit custody-field writes at the provisioning/storage boundary — consequence of removing the memberwise defaults).
- Tests asserting "fresh service sees old persisted state" reworked onto shared in-memory persistence (restart simulation preserved); Keychain-error injection for metadata failures replaced by persistence-level failure injection (failNextUpdate/failNextLoadAll added to RecordingKeyMetadataPersistence).

### Verifier verdict
PASS (fresh-context adversarial subagent, agentId a97d39559f0b07156). Findings & dispositions:
1. concern — LocalDataResetServiceTests full-suite flake is now a second recurrence and the "protocol" isn't in TESTING.md. Disposition: maintainer kickoff explicitly defines the rerun protocol; surfacing in PR summary as a follow-up (document in TESTING.md §2 and/or fix cross-test pollution).
2. note — additional reintroduction tokens possible (KeyMetadataStore, defaultCustodyKind, migrationWarning family). Disposition: load-bearing tokens covered; left for a future guardrail pass; recorded.
3. note — DMK zeroize CoW aliasing is framework-wide pre-existing idiom, not a Phase 3 regression. Disposition: hardening candidate, separate PR.
4-5. notes — custody allowance granularity; InMemory duplicate error shape divergence. Recorded, no action.
6. note — keep worklog untracked. Confirmed (explicit git add excludes).
Carry-forward captured below into Phases 4–6 planning (item3 lockstep, gracePeriodKey, invalidLegacyAuthMode xcstring, legacySelfTestReportsDirectoryExists postcondition, allowLegacyMigration:false in Phase 5, protectedDataRootSecretLegacyCleanup trace classification in Phase 5, item #9 comment repoint in Phase 6).

### Commits
- 2fbc4d2 refactor: retire Phase 3 key-metadata legacy surface

## Phase 4 — Private-Key-Control And Cleanup-Only Residue
Status: COMPLETED 2026-06-10 (initial FAIL docs-only → fixed bd66737 → re-verify PASS).

### Verified targets
- PrivateKeyControlStore: legacyInitialPayload (L604, reads authModeKey/rewrap*/modifyExpiry* defaults), cleanupLegacyDefaults (L647), calls at L89/L142 (bootstrap), L162/L194 (ensureCommitted), L382/L404 (continuePendingCreate). `defaults` property/param dead after removal.
- AuthenticationEvaluable.swift: PrivateKeyControlError.invalidLegacyAuthMode (L205, errorDescription L224-226 + xcstrings `error.privateKeyControl.invalidLegacyAuthMode`), AuthPreferences keys authModeKey (L395), gracePeriodKey (L398, Phase 2 orphan), rewrapInProgressKey (L401), rewrapTargetModeKey (L406), modifyExpiryInProgressKey (L409), modifyExpiryFingerprintKey (L412). defaultGracePeriod STAYS (current snapshot defaults).
- AppConfiguration: legacyRequireAuthOnLaunchKey (L69) + resetPersistentKeys legacy entries (5 AuthPreferences keys + legacyRequireAuthOnLaunchKey).
- AppTemporaryArtifactStore: legacyTutorialDefaultsSuitePrefix (static L10 + property L15 + init param L21), legacyTutorialDefaultsSuiteNames (L221), cleanupTutorialDefaultsSuites multi-suite enumeration (L126; fixed-suite cleanup is current behavior → renamed singular), remainingTutorialDefaultsSuites legacy half (L138).
- AppStartupCoordinator: cleanupTemporaryFiles legacy self-test removal + documentDirectory/legacySelfTestReportsDirectory params (L123-141), legacySelfTestReportDirectory (L143).
- AppContainer: legacySelfTestReportsDirectory property/param/wiring (L37/74/109/653/843/884/921/1165/1204).
- LocalDataResetService: legacySelfTestReportsDirectory property/param/delete pass (L37/60/81/219) + postcondition/trace/failure (L362-363/396/413/436-437).
- Tests: AppStartupCoordinatorTests Phase7 cleanup test (legacy self-test dir + legacy UUID suite + similar-suite fixtures), LocalDataResetServiceTests legacy fixtures, ProtectedDataDomainRecoverySentinelTests legacy-journal import tests (no-handoff seeding + first-domain migration test), ModelTests resetRemovesLegacyRequireAuthOnLaunchKey, KeyManagementServiceTestSupport tearDown defaults removal, DeviceSecurityTestCase L49-53, DeviceAuthenticationManagerTests L270.
- Guardrails: item3 allowances (PrivateKeyControlStore.swift + AuthenticationEvaluable.swift) lockstep-deleted; item3 tokens extended with cleanup-only symbols.

### Deviations / Doctrine-covered extras (planned)
- PrivateKeyControlStore `defaults:` init param removed (dead after legacy fns go) — ripples to constructors.
- cleanupTutorialDefaultsSuites → cleanupTutorialSandboxDefaultsSuite, remainingTutorialDefaultsSuites → remainingTutorialSandboxDefaultsSuites (fixed-suite-only current behavior keeps a non-enumerating name; old names are removal targets).
- AuthPreferences.gracePeriodKey removed here per Phase 2 verifier carry-forward (orphaned migration-source key).

### Validation
- build-for-testing: 4 iterations to green (logs /tmp/p4-build*.log).
- Device-test target compile check: `build-for-testing -testPlan CypherAir-DeviceTests -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO` — exit 0 (covers DeviceSecurityTestCase/DeviceAuthenticationManagerTests edits; device RUNS not required by matrix).
- Targeted (matrix reset row + phase suites): LocalDataResetServiceTests 13/13, AppStartupCoordinatorTests 3/3, ProtectedDataDomainRecoverySentinelTests 16/16, PrivateKeyControlRecoveryTests 12/12, ArchitectureSourceAuditTests 42/42, LocalizationCatalogTests 5/5, TutorialSessionStoreTests 57/57 — 148 tests, 0 failures.
- Full unit lane: **1310 tests, 0 failures** (log /tmp/p4-full.log), no reset flake this run.
- xcstrings: `error.privateKeyControl.invalidLegacyAuthMode` removed (16-line diff).
- Roadmap: Phase 4 status; item3 coverage paragraph updated; "No guardrail rule yet covers" now lists only Phase 5/6 items.
- Docs: ARCHITECTURE.md (PrivateKeyControlStore lines, tutorial-suite cleanup wording, Documents/self-test tree line, UserDefaults tree legacy rows), SECURITY.md (UserDefaults exceptions note, tutorial cleanup note), TESTING.md (self-test legacy cleanup + migration phrases), PERSISTED_STATE_INVENTORY.md (requireAuthOnLaunch row deleted; authMode/rewrap*/modifyExpiry*/self-test/tutorial rows updated).

### Security-sensitive edits (CLAUDE.md edit-then-explain)
- `Sources/Security/ProtectedData/PrivateKeyControlStore.swift` — legacyInitialPayload + cleanupLegacyDefaults removed; all three creation paths now seed `Payload.initial(authMode: .standard)`; dead `defaults:` init param removed. Positive: first-domain creation with standard defaults + empty journal (rewritten sentinel test), recovery-journal mutation tests unchanged (current payload-based). Negative: no-handoff bootstrap refusal, pending-mutation fail-closed tests unchanged.
- `Sources/Security/AuthenticationEvaluable.swift` — PrivateKeyControlError.invalidLegacyAuthMode case removed; AuthPreferences reduced to defaultGracePeriod (authModeKey, gracePeriodKey [Phase 2 orphan], rewrapInProgressKey, rewrapTargetModeKey, modifyExpiryInProgressKey, modifyExpiryFingerprintKey deleted).
- `Sources/Models/AppConfiguration.swift` — legacyRequireAuthOnLaunchKey + 5 AuthPreferences reset entries removed; resetPersistentKeys now appSessionAuthenticationPolicyKey + uiTestBypassAuthentication only.
- `Sources/App/Settings/LocalDataResetService.swift` — legacySelfTestReportsDirectory property/param/reset-directory/postcondition/trace/failure removed; tutorial cleanup now fixed-suite only.
- AppContainer/AppStartupCoordinator/AppTemporaryArtifactStore — legacy self-test directory plumbing and legacy tutorial UUID-suite enumeration removed; fixed-suite cleanup renamed cleanupTutorialSandboxDefaultsSuite/remainingTutorialSandboxDefaultsSuites.

### Deviations / Doctrine-covered extras (called out)
- As planned: defaults param removal; fixed-suite cleanup rename; gracePeriodKey removed under this phase's AuthPreferences bullet (Phase 2 carry-forward).
- Startup test `test_appStartupCoordinator_deletedKeyDoesNotRestoreInterruptedModifyExpiryBundle` DELETED outright (existed to assert old-defaults residue survives startup; current journal-based no-restore invariant covered by KeyManagementServiceKeyMutationTests.test_deleteKey_interruptedModifyExpiry_clearsRecoveryStateAndBlocksRestore and PrivateKeyControlRecoveryTests).
- Legacy-journal import test rewritten as `test_privateKeyControl_emptyRegistryCreatesFirstDomainWithStandardDefaults` (current creation invariant).
- item3 rule renamed to cover cleanup-only artifact symbols; allowances deleted in lockstep.

### Verifier verdict
Initial verdict FAIL (fresh-context adversarial subagent, agentId a8a3885535a6f28f5) — code-side verified clean across all axes; failure was documentation-only: 4 major (SECURITY.md §4 legacy-keys migration paragraph, TESTING.md private-key-control migration bullet, TESTING.md deleted-coverage claims, TDD.md migration/exception bullets), 2 minor (TESTING.md metadata-account residue from Phase 3, empty 'legacy cleanup-only' class), 1 nit (dangling comment). ALL FIXED in commit bd66737; fresh-context re-verification (agentId af92350fe2c3a439d): **PASS** — all 7 findings resolved, adversarial docs sweep clean. Borderline note: CODEX_SECURITY_REVIEW_CLOSED.md/INDEX.md decision records still phrase SR-CLOSED-12 in present tense — curated historical decision records, left as-is (surfaced in PR summary). Cosmetic double blank line in SECURITY.md L313-314 — will ride along with the Phase 5 SECURITY.md edit.
Carry-forward: Phase 5 doc surfaces need explicit checking (format-floor paragraph, TESTING.md L58 CAPDSEV2 clauses, inventory right-store/format-floor/legacy-cleanup rows); item1A/1B lockstep; reset interplay mirrors the Phase 4 postcondition-removal pattern.

### Commits
- d814b6f refactor: retire Phase 4 private-key-control and cleanup-only legacy residue
- bd66737 docs: align SECURITY/TESTING/TDD/inventory with retired Phase 3-4 migration surfaces

## Phase 5 — Root-Secret Cleanup
Status: COMPLETED 2026-06-10 (initial FAIL docs-only → fixed 91c50c0 + c6d3a5a → re-verify PASS).

### Verified targets
- ProtectedDataRootSecretCoordinator: `legacyMigrationDeferred` outcome enum (L4-7), `legacyRightStoreClient` (L11/20/28), `migrateLegacySharedRightIfNeeded` (L273-385, incl. orphaned `error.protectedData.rootSecretMigrationVerification` string shared with raw-v1 migration), `allowLegacyMigration`/`localizedReason` threading in loadRootSecretForAuthorization (L93-132), itemNotFound→migration fallback, storageFormat/didMigrate gate + trace keys, `recordRootSecretEnvelopeMinimumVersion` plumbing (floor), legacy removeRight in removePersistedSharedRight (L88-90).
- ProtectedDataRightStoreClient.swift: `ProtectedDataRootSecretStorageFormat` (L9, legacyV1Raw/envelopeV2), `ProtectedDataRootSecretLoadResult` (L14, reduces to Data), `formatFloorStore` wiring (L48/55/66/111/326/366/452), `openOrMigrateRootSecretPayload` length-based raw-v1 recognition + downgrade check (L320-393), `migrateLegacyRawRootSecret` (L395-479), `loadRootSecretPayload` (migration verify only, L481-497), `deleteLegacyCleanupMarkerIfPresent` (L535-565), `ProtectedDataPersistedRightHandle`/`ProtectedDataRightStoreClientProtocol`/`ProtectedDataRightStoreClient`/`LocalAuthenticationPersistedRightHandle` (L572-785). `minimumEnvelopeVersion` protocol param. expectedRootSecretLength STAYS (current envelope seal/open validation).
- ProtectedDataDeviceBinding.swift: `ProtectedDataRootSecretFormatFloorMarker` (L191) + `ProtectedDataRootSecretFormatFloorStore` (L219-330).
- ProtectedDataRegistry: `rootSecretEnvelopeMinimumVersion` field (L83) + emptySteadyState arg + validateConsistency floor check (L101-104). RegistryStore.recordRootSecretEnvelopeMinimumVersion (L124-140).
- ProtectedDataSessionCoordinator: legacyRightStoreClient/recordRootSecretEnvelopeMinimumVersion init params, allowLegacyMigration params (L59/77/100), legacyMigrationDeferred handling (L150-158).
- ProtectedDataPostUnlockCoordinator: `allowLegacyMigration: false` arg (L114 region).
- AppContainer: makeProtectedDataSessionCoordinator legacyRightStoreClient param + ProtectedDataRightStoreClient constructions + recordRootSecretEnvelopeMinimumVersion closure (L162-164).
- LocalDataResetService: legacyRightStoreClient property/param/removal pass + `legacyRight.remove.*` failure keys, protectedDataRootSecretLegacyCleanupService deletion pass + hasLegacyCleanup postcondition/trace/failure, format-floor deletion pass + hasFormatFloor postcondition/trace/failure.
- KeychainConstants: protectedDataRootSecretFormatFloorService, protectedDataRootSecretLegacyCleanupService. AuthTraceMetadata: their classifications.
- Tests/support: MockProtectedDataRightStoreClient + MockProtectedDataPersistedRightHandle + ThrowingRootSecretFloorRecorder + insertLegacyRootSecret/replaceRootSecretPayload raw-v1 helpers; CAPDSEV2 v1→v2 migration / format-floor downgrade / legacy-cleanup deletion tests; reset tests' legacy-cleanup/format-floor row fixtures.
- Guardrails: item1A allowances (5 files) lockstep; item1B tokens (check list); add storageFormat/format-floor tokens (roadmap gap).
- Docs: SECURITY.md Device-Binding Note format-floor paragraph (objective-mandated), TESTING.md L58 CAPDSEV2 clauses, inventory format-floor/legacy-cleanup rows.

### Deviations / Doctrine-covered extras (planned)
- ProtectedDataRootSecretLoadResult/StorageFormat removed entirely; protocol loadRootSecret returns Data, minimumEnvelopeVersion param dropped (entire floor retired incl. registry field + registry recorder — the registry field/recorder exist only to feed the downgrade check the roadmap names; "the format floor has no remaining purpose").
- ProtectedDataRootSecretAuthorizationLoadOutcome enum removed (only carried the migration deferral).
- localizedReason param on loadRootSecretForAuthorization removed (fed only legacy right authorization).

### Validation
- build-for-testing: 8 iterations to green (logs /tmp/p5-build*.log). Device-test target compiles for iOS Simulator after deleting DeviceProtectedDataRightStoreTests.swift (whole-file legacy LARight store coverage; not in pbxproj exceptions/xcfilelists).
- Targeted (matrix reset row + phase suites): LocalDataResetServiceTests 11/11, ProtectedDataRootSecretTests 6/6 (incl. new current-model `test_rootSecretStore_undecodablePayloadFailsClosed` using non-32-byte garbage to avoid old-shape reconstruction), ProtectedDataDomainKeySessionTests 10/10, ProtectedDataAccessGatePostUnlockTests 14/14, ProtectedDataDomainRecoverySentinelTests 15/15, ArchitectureSourceAuditTests 42/42, LocalizationCatalogTests 5/5 — 103 tests, 0 failures.
- Full unit lane: **1303 tests, 0 failures** (log /tmp/p5-full.log), no flake.
- xcstrings: `error.protectedData.rootSecretMigrationVerification` removed.
- SECURITY.md format-floor paragraph rewritten per the objective ("any payload that does not decode as a current CAPDSEV2 envelope fails closed as ordinary undecodable input"); Phase 4's cosmetic double blank line fixed in same pass. ARCHITECTURE.md (4 module lines, downgrade bullets, Keychain tree rows, legacy-cleanup exception list), TESTING.md (L58 CAPDSEV2 clauses, pre-auth bullet) updated. Inventory had no remaining rows.
- Roadmap: Phase 5 status; item1A/1B coverage paragraph; "No guardrail rule yet covers" now Phase 6 only.

### Security-sensitive edits (CLAUDE.md edit-then-explain)
- `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift` — REWRITTEN: legacy LARight surface (protocol/client/handle), ProtectedDataRootSecretStorageFormat, ProtectedDataRootSecretLoadResult, length-based raw-v1 recognition, migrateLegacyRawRootSecret, deleteLegacyCleanupMarkerIfPresent, format-floor wiring all deleted; loadRootSecret now returns Data and decodes the CAPDSEV2 envelope only. Positive: envelope round-trip/device-binding tests; negative: tamper suite + undecodable-payload fail-closed + device interaction/missing-binding fail-closed tests.
- `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift` — legacyMigrationDeferred outcome, legacyRightStoreClient, migrateLegacySharedRightIfNeeded, allowLegacyMigration/localizedReason threading, floor recording, storageFormat/didMigrate trace keys removed.
- `Sources/Security/ProtectedData/ProtectedDataSessionCoordinator.swift` — legacy/floor init params and allowLegacyMigration params removed; authorization path now derives the wrapping root key from the plain Data secret.
- `Sources/Security/ProtectedData/ProtectedDataDeviceBinding.swift` — ProtectedDataRootSecretFormatFloorMarker + ProtectedDataRootSecretFormatFloorStore deleted.
- `Sources/Security/ProtectedData/ProtectedDataRegistry(.Store).swift` — rootSecretEnvelopeMinimumVersion field, validateConsistency floor check, recordRootSecretEnvelopeMinimumVersion deleted (old registries with the extra key still decode; Codable ignores unknown keys).
- `Sources/Security/KeychainManageable.swift` — formatFloor/legacyCleanup service constants deleted; `Sources/Security/AuthTraceMetadata.swift` — their classifications deleted; `Sources/Security/Mocks/MockKeychain.swift` — root-secret mock returns Data.
- `Sources/App/Settings/LocalDataResetService.swift` — legacyRightStoreClient removal pass + legacyRight.remove.* failure key, format-floor and legacy-cleanup row deletion passes + hasFormatFloor/hasLegacyCleanup postconditions/trace/failure keys removed (mirrors the Phase 4 pattern).
- `Sources/App/AppContainer.swift` + `ProtectedDataPostUnlockCoordinator.swift` — right-store/floor wiring and allowLegacyMigration:false removed.

### Deviations / Doctrine-covered extras (called out)
- As planned: load-result struct/enum removal (loadRootSecret → Data), outcome enum removal, localizedReason param removal, registry floor field/recorder removal (the registry half of the floor exists only for the downgrade check the roadmap retires).
- Test support: MockProtectedDataPersistedRightHandle + MockProtectedDataRightStoreClient replaced by current-model RecordingProtectedDataRootSecretStore; ThrowingRootSecretFloorRecorder deleted; insertLegacyRootSecret renamed insertRootSecretPayload (generic payload seeding); replace/loadRootSecretPayload helpers deleted.
- Deleted tests: raw-v1 migration/floor trio in ProtectedDataRootSecretTests, session floor-failure test, legacy-migration deferral tests (post-unlock + sentinel), legacy right-store device test file, reset legacy-row fixtures/postcondition tests.

### Verifier verdict
Initial verdict FAIL (agentId a0878e232bb2687a3) — code-side verified clean on all axes; findings: 2 major stale ARCHITECTURE.md sentences (raw-v1 migration bullet, store module line), minor orphaned ProtectedDataError.missingPersistedRight, process note to call out the missing-root-secret classification change (cancelledOrDenied→frameworkRecoveryNeeded via pre-existing itemNotFound classification — correct post-cutoff: ready registry + missing secret is genuine corruption; CALLED OUT here for the PR summary), notes on guardrail token granularity and the stale ProtectedDataRightStoreClient.swift filename (recorded debt). Fixes in 91c50c0. Re-verification (agentId aecfc859d65e19847): original findings PASS; sweep found 2 more stale lines — TDD.md:381 registry minimum-version claim and TESTING.md:84 migration state-machine cross-reference — FIXED in c6d3a5a exactly per the re-verifier's stated remediation-for-PASS conditions; final repo-wide doc sweep clean (remaining 'migration state machine' hit is the live KeyMigrationCoordinator rewrap-recovery machinery, in scope as current).

### Commits
- 538f58a refactor: retire Phase 5 root-secret legacy right-store, raw-v1, and format-floor surface
- 91c50c0 docs: drop stale raw-v1 migration claims; remove orphaned missingPersistedRight error case
- c6d3a5a docs: drop remaining root-secret floor and migration-coverage claims from TDD/TESTING

## Phase 6 — Rust And UniFFI Signature Cleanup
Status: COMPLETED 2026-06-10 (verifier PASS).

### Verified targets
- pgp-mobile/src/signature_details.rs: legacy_status/legacy_signer_fingerprint fields on all four detailed result records (L39-78), LegacyFoldMode (L82), SignatureCollector legacy_status/legacy_signer_fingerprint/legacy_stopped + legacy_signer_fingerprint() accessor, state_from_legacy_status (L278), fold-quirk tests (expired-fingerprint survival tests L386-433 = explicit deletion targets; verify_like/no_observed tests carry legacy assertions to strip).
- KEY ANALYSIS: the collector's stop-walk also produces summary_state/summary_entry_index — that selection IS the current Swift contract (PGPMessageResultMapper reads only summaryState/summaryEntryIndex; spec says no Swift call-site rewrites). So the walk survives with the legacy OUTPUTS removed: LegacyFoldMode→SummaryFoldMode, legacy_stopped→summary_stopped carry the current summary semantics, not old-model data compatibility (called out as the Phase 6 judgment call).
- decrypt.rs: SignatureStatus enum (L17, becomes zero-use → stale exposure removed), DecryptLike constructions/destructuring. verify.rs: empty_detailed_result status mapping, VerifyLike construction. password.rs: PasswordDecryptResult.signature_status/signer_fingerprint (L40-41) + constructions. streaming.rs: file results + helper paths. external_decryptor(.rs/tests), external_signer/tests: constructions/assertions.
- Swift: NO production/test consumers of legacyStatus/legacySignerFingerprint/SignatureStatus (verified; only generated bindings carry them). Sources/PgpMobile regenerated by pinned rebuild (rust-sync skill).
- Guardrails: NEW Rust guardrail reading pgp-mobile/src via CARGO_MANIFEST_DIR forbidding the retired symbols; Swift item #9 tokens (legacyStatus, legacySignerFingerprint, legacySignerIdentity, legacyVerification) per the audit file's standing comment.
- Docs: PRD.md L182/L280 legacy-summary-fallback wording; DetailedSignatureVerification.swift L102 §9 comment repoint (spec Follow-Ups mandates).

### Implementation (2026-06-10)
- signature_details.rs fully rewritten: four detailed result records lost `legacy_status`/`legacy_signer_fingerprint`; `LegacyFoldMode`→`SummaryFoldMode` (`legacy_stopped`→`summary_stopped`); `into_parts()` → 3-tuple `(summary_state, summary_entry_index, signatures)`; `state_from_legacy_status` and the `legacy_signer_fingerprint()` accessor deleted; observe_result preserves exact summary semantics (Valid stops both modes; MissingKey updates without stopping; hard failure stops VerifyLike only).
- decrypt.rs: `SignatureStatus` enum deleted (zero uses remained). verify.rs: early-error path maps `is_expired_error` → `SignatureVerificationState::Expired`/`Invalid` directly. password.rs: `PasswordDecryptResult.signature_status`/`signer_fingerprint` removed (4 construction sites). streaming.rs: 3-tuple destructuring, summary-only error-path constructions. external_decryptor.rs: 2 sites.
- Unit tests in signature_details.rs rewritten current-model-only: deleted the two expired-fingerprint-survival fold-quirk tests (explicit spec deletion targets); kept/renamed walk-semantics tests; added decrypt-like follows-later-results and verify-like hard-failure-freeze coverage.
- DELETION-vs-REWRITE split for the wider Rust test surface (Test Policy: rewrite only current-invariant coverage):
  - DELETED legacy assertions where current-model assertions already sat adjacent: detailed_signature_tests.rs (all legacy_status/legacy_signer_fingerprint asserts incl. the legacy-vs-entry cross-checks and Bad-fp-None old-model asserts), password_message_tests.rs, external_signer/password_message.rs.
  - REWROTE current crypto invariants onto the summary model where the legacy assert was the only check (Valid→Verified, Bad→Invalid, Expired→Expired, NotSigned→NotSigned, UnknownSigner→SignerCertificateUnavailable; signer-fp asserts → `signatures[summary_entry_index].signer_primary_fingerprint`): profile_a/b_message_tests, streaming_roundtrip_tests, cross_profile_tests, gnupg_message_interop_tests (8×), security_signature_policy_tests (12×, incl. tamper/expiry/revocation negative tests + doc comments), external_signer/{text_encrypt,detached_file,cleartext,streaming_file_encrypt}, external_decryptor src tests, examples/generate_detailed_signature_fixtures.rs (fixture self-checks).
- Guardrails added: pgp-mobile/tests/legacy_symbol_guardrail_tests.rs (CARGO_MANIFEST_DIR walk of src/, whole-word matcher distinguishing DetailedSignatureStatus/CertificateSignatureStatus/signer_primary_fingerprint, + matcher self-test); ArchitectureSourceAuditTests `legacyCleanupSignatureFoldSymbols` rule + `test_legacyCleanup_phase6_signatureFold_isTrackedForStrictRetirement` (item #9 tokens, Sources/ minus Sources/PgpMobile/, no temporary exceptions — symbols verified absent from hand-written Swift); audit-file standing comment updated.
- Docs: roadmap Phase 6 `> Status: Completed (2026-06-10).` + Guardrails section rewritten (Phase 6 zero-coverage paragraph replaced with the two-sided guardrail description); PRD.md L182/L280 reworded to summary-state/entry-index model; DetailedSignatureVerification.swift comment repointed to "Follow-Ups Outside This Roadmap"; ARCHITECTURE_REFACTOR_TARGET.md example list dropped dead `SignatureStatus` (Doctrine-covered extra). FFI_BOUNDARY_LEAK_AUDIT.md deliberately NOT edited — dated non-canonical audit snapshot (2026-05-19), editing would falsify the historical record.
- Build note: pinned stage1 download hit repeated transient 503s (user-side proxy ↔ GitHub release CDN); succeeded after retries. Same command/tag as documented.
- DEVIATION (spec inaccuracy, called out): the roadmap bullet "no Swift call-site rewrites" missed three Swift TEST consumers of the generated legacy surface. (1) Tests/FFIIntegrationTests/FFIIntegrationTests+PasswordMessages.swift (3 asserts) and (2) Tests/ServiceTests/PrivateKeyPasswordMessageEncryptionServiceTests.swift (4 asserts) consumed `PasswordDecryptResult.signatureStatus`/`signerFingerprint` — first unit-lane run failed compiling these; (3) Tests/ServiceTests/ModelTests.swift:728 constructed `FileVerifyDetailedResult(legacyStatus:legacySignerFingerprint:...)` via initializer labels — second lane run failed on this (my member-read sweep missed labeled constructor args; subsequent label sweep found exactly one). Handled per Test Policy: one legacy assert deleted (adjacent `summaryState` assert already present), the rest rewritten onto `summaryState`/`summaryEntryIndex`/`signatures[].signerPrimaryFingerprint`, constructor call moved to the summary-only initializer. Verified no other constructions of the four detailed records or PasswordDecryptResult outside Sources/PgpMobile. `build-for-testing -quiet` clean before the third lane run. Roadmap bullet amended with an as-executed note.

### Validation (matrix row: Rust/UniFFI signature cleanup — all three steps in order)
- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`: green — 29 test binaries all "test result: ok", 0 failures (includes new legacy_symbol_guardrail_tests 2/2). `cargo fmt --check` clean.
- Pinned rebuild `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 ./build-xcframework.sh --release`: Build Complete (after transient 503 retries); PgpMobile.arm64e-build-manifest.json rewritten (content-identical — toolchain/dependency pins unchanged, as expected); Sources/PgpMobile/pgp_mobile.swift + bindings/pgp_mobile.swift regenerated.
- Generated bindings check: 0 occurrences of legacyStatus/legacySignerFingerprint; no bare SignatureStatus type; summaryState/summaryEntryIndex present on all four detailed records; PasswordDecryptResult reduced to status/plaintext/summary fields.
- Full unit lane `xcodebuild test -testPlan CypherAir-UnitTests -destination 'platform=macOS,arch=arm64e'`: **1304 tests, 0 failures, TEST SUCCEEDED** (third run; first two failed on the Swift-test deviation above). Count reconciliation: 1303 (Phase 5) + 1 new audit guardrail test = 1304 ✓. No LocalDataResetServiceTests flake this run.

### Verifier verdict
PASS (fresh-context adversarial subagent, agentId a52a9e7271661c81a). All seven axes verified clean against the actual diff: removal targets gone everywhere (incl. bindings byte-identical pair), rename judgment confirmed sound (old legacy_stopped gated BOTH legacy and summary updates → summary_stopped carries prior summary semantics exactly; PGPMessageResultMapper = live consumer at 6 sites), Test Policy compliant with no vacuity (every tamper test still asserts Invalid), guardrails effective (matcher self-test proven; lockstep clean), docs consistent, hard constraints untouched, validation claims plausible (29 binaries = 1 lib + 1 bin + 26 integration + doc-tests; 1304 = +1 audit test).
Noted, not blocking (for PR): (1) pre-existing generatedFFITypes ban list still carries the now-dead SignatureStatus token — reintroduction prevention, cosmetic; (2) hand-edits to generated bindings would bypass guardrails — documented/rationalized in roadmap Guardrails (generated files are declared not-hand-edited); (3) the no-Swift-rewrites deviation is test-only, recorded in the as-executed note.

### Commits
- 633fa5e refactor: retire legacy signature fold surface from Rust, UniFFI, and generated Swift (Phase 6)

## Review fix pass (post end-to-end review, 2026-06-10)
Commit f0cd2b3 (signed). M1: TDD.md retired-metadata row + table row deleted, ARCHITECTURE.md dangling Metadata-account tree header deleted (connector fixed). M2: KeyManagementService.swift:345 export doc comment rewritten to fail-closed reality (comment-only, security-sensitive file, called out). M3 (preferred variant): 16 collision-free ban tokens added (item1A 4 right-store type names; item2 migrateLegacyMetadataAfterAppAuthentication+metadataService; item3 six AuthPreferences key constants; item4 four upgrade-machinery symbols) + coverage map updated + honest residual-gaps paragraph restored. L1 stale exemplar clause dropped; L2 Follow-Ups past tense; L3 as-planned sentence restored verbatim + corrected as-executed parenthetical; L4 EOF blank line stripped (security-sensitive file, whitespace-only, called out). Validation: ArchitectureSourceAuditTests 43/43 + LocalizationCatalogTests 5/5, git diff --check clean.
