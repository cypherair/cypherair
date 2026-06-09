# Legacy Cleanup

> Status: Active strict-retirement roadmap.
> Purpose: Canonical plan for retiring app-owned legacy data models, persisted
> formats, migration sources, fallback decoders, cleanup-only hooks, legacy
> fixtures, and old-input tests after the 2026-06-08 support cutoff.
> Audience: Human developers, security reviewers, QA, and AI coding agents.
> Truth sources: current `main` source tree;
> [PERSISTED_STATE_INVENTORY.md](PERSISTED_STATE_INVENTORY.md);
> [ARCHITECTURE.md](ARCHITECTURE.md); [SECURITY.md](SECURITY.md);
> [TESTING.md](TESTING.md).
> Last reviewed: 2026-06-08.

This document replaces the earlier cleanup inventory and deleted execution
roadmap. It is now the single source of truth for the strict legacy-retirement
roadmap. Production cleanup happens in later PRs; this roadmap records what must
be removed and how to validate those removals.

## Doctrine

After support ends for an app-owned old model, new CypherAir builds must not
know it, recognize it, migrate it, fall back to it, clean it up as a special
case, or carry dedicated tests for its input data.

App-owned old persisted models, old schemas, migration sources, fallback
decoders, upgrade-on-read paths, cleanup-only legacy hooks, and legacy fixture
dependencies are retirement targets. Production, tutorial, UI-test, and unit
test callers that depend on those targets must be rewritten to current models
or removed with the old surface.

Cleanup is incomplete when old behavior survives through any of these forms:

- renaming a type, method, field, stored key, or helper while carrying the same
  old behavior forward
- moving old behavior to a new file, module, wrapper, adapter, helper, or
  fixture
- replacing an old fixture with a new fixture that still drives the old
  compatibility path
- adding special handling for old data after support has ended
- adding success or failure tests for old input data after the old model is
  removed

If old data remains on disk after support ends, new software treats it like any
other unknown or corrupted current-model input. The software must not contain
code that identifies why the data is old, and it must not add tests for old
data's post-cutoff failure behavior. Existing current-model validation,
corruption, recovery, and error handling are sufficient.

This roadmap records retirement targets only. It provides no continuation path
for app-owned old models inside new software.

## Test Policy

Delete tests that validate old migration success, old compatibility decode, old
fallback behavior, old cleanup hooks, old fixture behavior, or old input
failure.

Rewrite coverage only when it proves a current invariant with current-model
fixtures or ordinary malformed current data. Rewritten tests must not seed,
decode, fixture, identify, or assert known old payloads, old keys, old defaults,
old suites, old rows, or old artifact shapes.

Do not add new tests for how old-model data should fail after support ends. Once
cleanup is complete, the software should not know enough about the old model for
that behavior to be a product contract. Old-input tests such as Contacts
schema-v1 fail-closed checks, legacy artifact decode fixtures, raw-v1 root
secret fixtures, legacy metadata rows, legacy defaults seeds, and legacy
signature fold fixtures are deletion targets.

## Roadmap

### Phase 0 — Documentation And Guardrail Reset

- Delete obsolete planning docs and make this file the canonical roadmap.
- Align Swift source-audit comments and guardrail rationale with this roadmap.
- Add or revise guardrails so every later production PR removes both code and
  the corresponding temporary audit allowance.
- Do not use Phase 0 to delete production behavior.

### Phase 1 — Contacts Low-Blast-Radius Cleanup

Retire Contacts old-model residues that do not require cross-domain security
plumbing.

- Remove Contacts schema-v1 old-input tests in `ContactsDomainSnapshotTests`
  and any product contract around diagnosing schema-v1 payloads.
- Limit Contacts guardrails to reintroduction prevention, not to
  constructing known old input.
- Remove certification artifact partial-v2/defaulting behavior:
  `ContactCertificationArtifactReference.init(from:)` defaults for missing
  `canonicalSignatureData`, `source`, `targetSelector`, and `validationStatus`;
  `legacyTargetSelector`; `legacyUserIdDisplayText`; legacy-derived
  `ContactCertificationArtifactReference.userId`; and `ContactSnapshotMutator`
  assignment of `userId` from selector display text.
- Remove persisted `"Unknown"` sentinel semantics:
  `IdentityPresentation.legacyUnknownDisplayName`, UI special casing, contact
  mutation logic that treats persisted `"Unknown"` as old replaceable state, and
  tests that assert persisted sentinel behavior.
- Rewrite any useful Contacts tests with current schema data and current-shape
  certification artifacts only.

### Phase 2 — Protected Settings And Ordinary Settings Cleanup

Retire protected-settings schema v1 and the old ordinary-settings UserDefaults
model across production, tutorial, and tests.

- Remove `ProtectedSettingsStore.PayloadV1`,
  `requiresOrdinarySettingsMigration`,
  `migrateOpenedSettingsSnapshotIfNeeded`, decode `case 1`,
  `legacyInitialPayload`, `legacyOrdinarySettingsSnapshot`,
  `removeLegacySettingsSources`, and the legacy `clipboardNotice` UserDefaults
  source.
- Remove `LegacyOrdinarySettingsStore` and
  `ProtectedOrdinarySettingsLegacyKeys`; rewrite callers such as
  `TutorialSandboxContainer`, authenticated-test-bypass composition,
  `AppContainer`, settings tests, model tests, and tutorial tests to use current
  protected-settings or current in-memory fixtures.
- Remove protected-settings migration UI/access plumbing:
  `ProtectedSettingsAccessCoordinator.migrationAuthorizationRequirement`,
  `ensureCommittedAndMigrateSettingsIfNeeded`, `settingsMigration` traces,
  `ProtectedSettingsHost` migration wiring, and `CypherAirApp` migration
  authorization paths.
- Delete protected-settings v1, old ordinary-settings, old `clipboardNotice`,
  old UserDefaults fixture, and migration authorization tests. Current settings
  tests must use current payloads and current access/relock/recovery behavior.

### Phase 3 — Key Metadata Cleanup

Retire legacy Keychain metadata rows, test-fixture dependence on the old helper,
key-metadata schema v1, tolerant metadata decode, and revocation backfill.

- Remove the `KeyMetadataStore` fallback/CRUD fixture dependency and legacy
  Keychain metadata row model, including default-account and `metadataAccount`
  source reads.
- Remove `KeyMetadataLegacyMigrationOutcome`,
  `KeyMetadataMigrationSourceItem`, `loadMigrationSourceSnapshot`,
  `cleanupMigrationSourceItems`, `migrateLegacyMetadataIfNeeded`,
  `KeyCatalogStore` migration passthrough, `KeyManagementService`
  warning/wiring, and `CypherAirApp` warning presentation.
- Remove `LocalDataResetService` cleanup and postcondition awareness for
  legacy metadata-account rows, including `metadataService`, `metadataPrefix`,
  and `metadataAccount` use that exists only for old metadata rows.
- Remove delete-side legacy metadata cleanup:
  `KeyMutationService.cleanupLegacyMetadataRows`.
- Remove `KeyMetadataDomainStore.PayloadV1`,
  `DecodedPayload.sourceSchemaVersion`, `OpenedSnapshot.sourceSchemaVersion`,
  decode `case 1`, and upgrade-on-read writeback when
  `sourceSchemaVersion < Payload.currentSchemaVersion`.
- Remove `PGPKeyIdentity.init(from:)` tolerant defaults for missing
  `openPGPConfigurationIdentity` and `privateKeyCustodyKind`; current metadata
  records must persist explicit fields.
- Remove imported-key revocation backfill:
  `KeyExportService` empty-`revocationCert` branch,
  `KeyCatalogStore.updateRevocation`, old imported-key empty-`revocationCert`
  tests, metadata-update-failure backfill tests, and old diagnostics.
- Rewrite useful key-management tests against current protected metadata
  storage, current missing-required-material behavior, and current revocation
  artifact requirements.

### Phase 4 — Private-Key-Control And Cleanup-Only Residue

Retire legacy UserDefaults import/cleanup and old local artifact cleanup hooks.

- Remove `PrivateKeyControlStore.legacyInitialPayload`,
  `cleanupLegacyDefaults`, `invalidLegacyAuthMode`, and `AuthPreferences` keys
  used only as old migration sources.
- Current private-key recovery journal coverage must create and mutate journal
  state inside the current `private-key-control` ProtectedData payload, with no
  old-defaults setup, import assertions, cleanup assertions, or old-model
  diagnostics.
- Remove cleanup-only old artifact discovery and validation:
  `legacySelfTestReportsDirectory`, `legacySelfTestReportDirectory`,
  `legacyTutorialDefaultsSuitePrefix`, `legacyTutorialDefaultsSuiteNames`,
  `cleanupTutorialDefaultsSuites`, and `legacyRequireAuthOnLaunchKey`.
- Current temporary/export cleanup and fixed `com.cypherair.tutorial.sandbox`
  cleanup must not depend on old suite enumeration, old defaults keys, or old
  fixtures.
- Delete tests that create old `Documents/self-test/`, old
  `com.cypherair.tutorial.<UUID>` suites, old `requireAuthOnLaunch` residue, or
  legacy private-key-control defaults.

### Phase 5 — Root-Secret Cleanup

Retire legacy right-store and raw-v1 root-secret recognition/migration paths.

- Remove root-secret legacy `LARight` migration and authorization deferral:
  `legacyMigrationDeferred`, `legacyRightStoreClient`,
  `migrateLegacySharedRightIfNeeded`, `allowLegacyMigration`, and
  `ProtectedDataRightStoreClient` right-store migration/cleanup behavior.
- Remove local-data reset awareness of legacy right-store rows.
- Remove raw-v1 root-secret migration and cleanup-marker handling:
  `legacyV1Raw`, `migrateLegacyRawRootSecret`,
  `deleteLegacyCleanupMarkerIfPresent`, and
  `protectedDataRootSecretLegacyCleanupService`.
- Current root-secret tests must use the current envelope, device-binding, and
  ordinary malformed current data. They must not seed or name raw-v1 data or old
  right-only installs.

### Phase 6 — Rust And UniFFI Signature Cleanup

Retire the full legacy signature fold surface from Rust, UniFFI, generated
Swift, and tests.

- Remove `legacy_status`, `legacy_signer_fingerprint`, `LegacyFoldMode`,
  `legacy_stopped`, `state_from_legacy_status`,
  `PasswordDecryptResult.signature_status`,
  `PasswordDecryptResult.signer_fingerprint`, generated Swift `legacyStatus`,
  generated Swift `legacySignerFingerprint`, and stale `SignatureStatus`
  exposure.
- Regenerate UniFFI bindings after Rust result-shape changes.
- Current API surface must use `summary_state` / `summaryState`,
  `summary_entry_index` / `summaryEntryIndex`, and detailed signature entries
  without legacy fold/status aliases, wrappers, or compatibility semantics.
- Delete tests that encode old fold quirks, including expired fingerprint
  survival through bad/unknown later signatures. Rewrite broad message tests
  only when the input is independently a current product scenario and
  assertions target current summary/detail behavior.

## Guardrails

The existing Swift source-audit rules in
`Tests/ServiceTests/ArchitectureSourceAuditTests.swift` are part of Phase 0.
They should continue to fail when production `Sources/*.swift` reintroduce
removed Swift legacy symbols, and each production cleanup PR must delete the
matching temporary allowance when it removes the symbol.

Additional guardrails are needed as cleanup proceeds:

- Swift guardrails should cover newly retired Contacts artifact/sentinel,
  settings, key-metadata, private-key-control, cleanup-only, and root-secret
  symbols.
- Rust guardrails should read `pgp-mobile/src` via `CARGO_MANIFEST_DIR` and
  forbid the Phase 6 legacy signature symbols after they are removed.
- Guardrails must not require construction of old input data as product
  behavior.

## Validation Matrix

| Change family | Minimum validation |
|---------------|--------------------|
| Phase 0 docs/source-audit wording only | `git diff --check`; source-audit targeted unit test |
| Contacts model cleanup | targeted Contacts unit tests plus `ArchitectureSourceAuditTests` |
| ProtectedData/settings/key-metadata/private-key-control/root-secret cleanup | `xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests -destination 'platform=macOS'` |
| Rust/UniFFI signature cleanup | `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`, then `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1 ./build-xcframework.sh --release`, then macOS unit tests |
| Any cleanup touching reset | targeted local-data reset tests plus the relevant broader unit lane |

Every cleanup PR should include the exact symbols removed, the current-model
tests that replaced any still-useful invariant coverage, and confirmation that
old-input success/failure tests were deleted rather than redefined as future
contracts.

## Documentation Follow-Up

As implementation PRs land, update current-state docs that still describe old
models as live behavior, especially:

- `ARCHITECTURE.md` references to legacy metadata rows, protected-settings v1
  migration, root-secret legacy migration, tutorial UUID-suite cleanup, and
  old settings sources.
- `SECURITY.md` references to lazy revocation backfill, legacy metadata rows,
  protected-settings schema-v1 upgrade, and old cleanup-only paths.
- `TESTING.md` old migration/fail-closed coverage language for Contacts,
  protected-settings, key-metadata, private-key-control, revocation backfill,
  raw-v1 root secret, and cleanup-only artifacts.
- `PERSISTED_STATE_INVENTORY.md` rows for legacy UserDefaults, legacy metadata
  rows, self-test reports, tutorial UUID suites, Contacts old schema tests, and
  cleanup-only keys.
- `PRD.md` legacy summary fallback wording.
