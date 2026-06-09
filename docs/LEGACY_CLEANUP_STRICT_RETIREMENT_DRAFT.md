# Legacy Cleanup Strict Retirement Draft

> Temporary draft for discussion. This document records the strict retirement
> doctrine and expanded repo-grounded inventory for app-owned legacy surfaces
> after the 2026-06-08 cutoff. It does not set PR order and does not update the
> official cleanup guides yet.

## Doctrine

After support ends for an app-owned old model, new CypherAir builds must not
know it, recognize it, migrate it, fall back to it, clean it up as a special
case, or carry dedicated tests for its input data.

App-owned old persisted models, old schemas, migration sources, fallback
decoders, upgrade-on-read paths, cleanup-only legacy hooks, and legacy fixture
dependencies are retirement targets. Production, tutorial, UI-test, and unit
test callers that keep those targets alive must be rewritten to current models
or removed with the old surface.

Cleanup is incomplete if old behavior survives through any of these forms:

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
other unknown or corrupted current-model input. The software must not keep code
that identifies why the data is old, and it must not add tests for old data's
post-cutoff failure behavior. Existing current-model validation, corruption,
recovery, and error handling are sufficient.

This draft grants no approval to leave any listed legacy behavior in place. Any
future request to preserve one must be raised separately and explicitly approved
by the maintainer before implementation.

## Test Policy

Delete tests that only validate old migration success, old compatibility decode,
old fallback behavior, old cleanup hooks, old fixture behavior, or old input
failure.

Migrate a test only when it proves a current invariant that would otherwise lose
coverage, such as current-schema validation, current protected-domain recovery,
relock cleanup, mutation rollback, no silent reset of unreadable current data,
current signature summary/detail behavior, or current tutorial sandbox cleanup.

Do not add new tests for how old-model data should fail after support ends. Once
cleanup is complete, the software should not know enough about the old model for
that behavior to be a product contract. Old-input tests such as Contacts
schema-v1 fail-closed checks and legacy artifact decode fixtures are retirement
candidates, not future contracts.

## Mandatory Retirement Inventory

### Root Secret Legacy Right Store

- Surface: root-secret legacy `LARight` migration and authorization deferral.
- Current residue: `legacyMigrationDeferred`, `legacyRightStoreClient`,
  `migrateLegacySharedRightIfNeeded`, `allowLegacyMigration`, and
  `ProtectedDataRightStoreClient`.
- Current callers: protected-data session/root-secret coordinators, app
  container wiring, post-unlock authorization flow, and local-data reset.
- Required removal: delete the legacy right read, authorization, migration,
  deferral, tracing, and reset hooks. Old right-only installs must not migrate.
- Test action: delete old right-store migration/deferred-authorization tests.
  Migrate only current root-secret authorization, recovery, and relock
  invariants.

### Raw V1 Root Secret Payload

- Surface: raw 32-byte root-secret payload migration into the current
  device-bound envelope.
- Current residue: `legacyV1Raw`, `migrateLegacyRawRootSecret`,
  `deleteLegacyCleanupMarkerIfPresent`, and
  `protectedDataRootSecretLegacyCleanupService`.
- Current callers: `KeychainProtectedDataRootSecretStore.loadRootSecret`,
  `ProtectedDataRootSecretCoordinator`, and local-data reset validation.
- Required removal: delete raw-v1 detection, migration, post-migration cleanup
  marker handling, and cleanup-marker reset validation. Keep current
  `ProtectedDataRootSecretFormatFloorStore` anti-downgrade behavior as current
  security state.
- Test action: delete raw-v1 migration and cleanup-marker tests. Migrate only
  current v2 envelope, device-binding, and format-floor tests.

### Private-Key-Control UserDefaults Import

- Surface: private-key-control import from legacy `UserDefaults` keys.
- Current residue: `PrivateKeyControlStore.legacyInitialPayload`,
  `cleanupLegacyDefaults`, `invalidLegacyAuthMode`, and `AuthPreferences` keys
  used as migration sources.
- Current callers: first-domain bootstrap, post-unlock domain creation, and
  pending-create recovery.
- Required removal: create `private-key-control` from current defaults only;
  delete legacy defaults import, cleanup, invalid-old-mode error handling, and
  related strings.
- Test action: delete tests that seed old auth-mode, rewrap, or modify-expiry
  defaults. Keep current protected recovery journal tests.

### Protected Settings And Ordinary Settings Migration

- Surface: protected-settings schema v1 and old ordinary-settings
  `UserDefaults` backend.
- Current residue: `ProtectedSettingsStore.PayloadV1`,
  `requiresOrdinarySettingsMigration`, `migrateOpenedSettingsSnapshotIfNeeded`,
  `legacyInitialPayload`, `legacyOrdinarySettingsSnapshot`,
  `removeLegacySettingsSources`, `LegacyOrdinarySettingsStore`, and
  `ProtectedOrdinarySettingsLegacyKeys`.
- Current callers: protected-settings create/open/upgrade/reset flows,
  `TutorialSandboxContainer`, authenticated-test-bypass composition, model
  tests, and settings screen tests.
- Required removal: make schema v2 the only recognized protected-settings
  payload, remove the old UserDefaults backend, and replace tutorial/test bypass
  persistence with current-model test fixtures rather than a legacy store.
- Test action: delete protected-settings v1 migration and old ordinary-settings
  import tests. Migrate only current settings access, mutation, recovery, relock,
  and tutorial sandbox behavior.

### Protected-Settings UI And Access Plumbing

- Surface: UI/access authorization path whose only purpose is protected-settings
  migration.
- Current residue:
  `ProtectedSettingsAccessCoordinator.migrationAuthorizationRequirement`,
  `ensureCommittedAndMigrateSettingsIfNeeded`, `settingsMigration` traces,
  `ProtectedSettingsHost`, and `CypherAirApp` wiring.
- Current callers: live settings host tests, app composition, and settings
  screen-model tests.
- Required removal: remove migration authorization dependencies, branches,
  traces, host wiring, and tests with the store migration path.
- Test action: delete tests that only prove old migration authorization order or
  failure shape. Migrate only current protected-settings open, mutation,
  recovery, and relock assertions.

### Key Metadata Keychain Migration

- Surface: migration from legacy Keychain metadata rows into protected
  `key-metadata`.
- Current residue: `KeyMetadataStore` CRUD/default fallback,
  `KeyMetadataLegacyMigrationOutcome`, `KeyMetadataMigrationSourceItem`,
  `loadMigrationSourceSnapshot`, `cleanupMigrationSourceItems`,
  `migrateLegacyMetadataIfNeeded`, `KeyCatalogStore` migration passthrough,
  `KeyManagementService` warning/wiring, and `CypherAirApp` warning
  presentation.
- Current callers: `KeyMetadataDomainStore`, app container wiring, post-auth
  key-management migration calls, tutorial/UI-test paths, and many service
  tests that seed `KeyMetadataStore` directly.
- Required removal: require explicit current metadata persistence; remove legacy
  Keychain source reads, delete cleanup, migration warnings, and default
  fallback construction.
- Test action: move necessary current metadata assertions to protected-domain or
  memory-only current fixtures. Delete tests that prove default-account or
  metadata-account legacy row import, cleanup retry, partial migration, or
  warning behavior.

### Key Metadata Protected Schema V1

- Surface: in-domain key-metadata schema v1 upgrade-on-read.
- Current residue: `KeyMetadataDomainStore.PayloadV1`,
  `DecodedPayload.sourceSchemaVersion`, `OpenedSnapshot.sourceSchemaVersion`,
  decode `case 1`, and upgrade-on-read writeback when
  `sourceSchemaVersion < Payload.currentSchemaVersion`.
- Current callers: authoritative snapshot read, post-unlock domain open, and
  pending-create recovery.
- Required removal: delete the old payload type, source-schema tuple/state, v1
  decode branch, and writeback path that upgrades old payloads. Old schema
  payloads should not be recognized as a special case.
- Test action: delete schema-v1 migration-success tests. Migrate only current
  schema validation, current corruption recovery, and current no-silent-reset
  invariants.

### PGP Key Identity Legacy Decode

- Surface: tolerant decode of old `PGPKeyIdentity` JSON/plist records.
- Current residue: `PGPKeyIdentity.init(from:)` uses `decodeIfPresent` defaults
  for missing `openPGPConfigurationIdentity` and `privateKeyCustodyKind`.
- Current callers: legacy Keychain metadata decode and protected key-metadata
  payload decode.
- Required removal: require current metadata records to persist explicit
  `openPGPConfigurationIdentity` and `privateKeyCustodyKind`; remove the
  custom old-field defaulting.
- Test action: delete legacy JSON decode tests. Keep current encode/decode tests
  that include all current fields.

### Revocation Backfill

- Surface: lazy recovery of imported keys whose metadata has empty
  `revocationCert`.
- Current residue: `KeyExportService` empty-`revocationCert` branch,
  `KeyCatalogStore.updateRevocation`, and tests that blank `revocationCert` to
  force backfill.
- Current callers: revocation export through `KeyManagementService` and key
  detail UI actions.
- Required removal: missing revocation artifact should be treated as current
  data missing required material, not as a signal to unwrap, regenerate, and
  persist a legacy backfill.
- Test action: delete lazy backfill success and metadata-update-failure tests.
  Migrate only current revocation export success and missing-artifact failure
  behavior.

### Delete-Side Legacy Metadata Cleanup

- Surface: key deletion cleanup of legacy metadata rows.
- Current residue: `KeyMutationService.cleanupLegacyMetadataRows`, called from
  `deleteKey`, deleting both default-account and metadata-account rows.
- Current callers: key deletion service tests and any deletion path using
  `KeyMutationService`.
- Required removal: remove delete-time awareness of legacy metadata rows when
  legacy metadata readers and import paths are removed.
- Test action: delete tests that only prove legacy row deletion. Migrate only
  current key deletion invariants.

### Contacts Certification Artifact Compatibility

- Surface: partial-v2 certification artifact decode and old selector synthesis.
- Current residue: `ContactCertificationArtifactReference.init(from:)` defaults
  missing `canonicalSignatureData`, `source`, `targetSelector`, and
  `validationStatus`; `legacyTargetSelector`; `legacyUserIdDisplayText`;
  `ContactCertificationArtifactReference.userId`; and `ContactSnapshotMutator`
  legacy `userId` assignment from selector display text.
- Current callers: Contacts protected-domain snapshot decode, certification
  artifact persistence, contact mutation, and legacy artifact fixtures.
- Required removal: make current certification artifact fields required; remove
  old-shape decode defaults, selector synthesis, and display-shadow backfill.
  Delete `userId` if it is only shadow state; if it becomes a current explicit
  field, it must be written directly rather than derived from compatibility.
- Test action: delete legacy artifact decode/defaulting tests. Migrate only
  current certification artifact validation, projection, and revalidation tests.

### Contacts Unknown Display Sentinel

- Surface: persisted `"Unknown"` display sentinel recognition.
- Current residue: `IdentityPresentation.legacyUnknownDisplayName`, UI special
  casing in identity display presentation, and contact mutation logic that
  treats persisted `"Unknown"` as replaceable old state.
- Current callers: contact import/update display logic and model/UI tests.
- Required removal: stop treating persisted `"Unknown"` as old model state.
  Current localized unknown UI fallback can be reworked later without preserving
  the old persisted sentinel semantics.
- Test action: delete tests that assert persisted sentinel behavior. Migrate
  only current display fallback tests that do not depend on old persisted values.

### Cleanup-Only Old Artifacts

- Surface: local cleanup hooks for old self-test reports, old tutorial defaults,
  and old one-off app keys.
- Current residue: `legacySelfTestReportsDirectory`,
  `legacySelfTestReportDirectory`, `legacyTutorialDefaultsSuitePrefix`,
  `legacyTutorialDefaultsSuiteNames`, `cleanupTutorialDefaultsSuites`, and
  `legacyRequireAuthOnLaunchKey`.
- Current callers: startup cleanup, local-data reset, temporary artifact store,
  app container wiring, and startup/reset/tutorial tests.
- Required removal: remove cleanup-only old artifact discovery and validation
  paths after cutoff. Keep current temporary/export cleanup and the current
  fixed tutorial sandbox cleanup unless a later implementation replaces that
  sandbox model too.
- Test action: delete tests that create old `Documents/self-test/`, old
  `com.cypherair.tutorial.<UUID>` suites, or old `requireAuthOnLaunch` residue.
  Migrate only current startup/reset cleanup coverage.

### Rust And UniFFI Legacy Signature Model

- Surface: legacy signature summary/fold fields in Rust, UniFFI, generated
  Swift bindings, and tests.
- Current residue: `legacy_status`, `legacy_signer_fingerprint`,
  `LegacyFoldMode`, `legacy_stopped`, `state_from_legacy_status`,
  `PasswordDecryptResult.signature_status`,
  `PasswordDecryptResult.signer_fingerprint`, generated Swift `legacyStatus`,
  generated Swift `legacySignerFingerprint`, and stale `SignatureStatus`
  exposure if no current surface still needs it.
- Current callers: Rust verify/decrypt/streaming/external decrypt/password
  paths, public engine result types, generated Swift bindings, FFI integration
  tests, password-message tests, detailed-signature tests, and broad Rust
  message/security tests.
- Required removal: delete the legacy result surface outright and regenerate
  Swift bindings. Tests must assert current `summary_state` / `summaryState`,
  `summary_entry_index` / `summaryEntryIndex`, and detailed signature entries.
- Test action: delete tests that preserve old fold quirks, including expired
  fingerprint preservation through bad/unknown later signatures. Migrate broad
  message tests from legacy status assertions to current summary/detail
  assertions.

## Stale Documentation And Planning Targets

- PR-A1 status drift: Contacts schema v1->v2 migration removal has already
  landed, so any plan text presenting PR-A1 as future work is stale.
- PR-D1 status drift: Swift app-model consumers have already moved off Rust
  legacy signature fields, so any plan text presenting Swift-side PR-D1 as
  future work is stale.
- PRD legacy summary fallback wording: product text describing verify/decrypt
  routes as falling back to legacy summary fields should be removed or rewritten
  around the current signature model.
- Official keep-list / rename-only wording: existing text that says
  `LegacyFoldMode`, `legacy_stopped`, `KeyMetadataStore`,
  `LegacyOrdinarySettingsStore`, or in-domain v1 migration should stay or be
  renamed is stale under this strict retirement doctrine.
- `TESTING.md` old migration/fail-closed coverage language: old-install,
  old-schema, Contacts schema-v1, legacy cleanup, and revocation backfill tests
  should not be future product contracts.
- `PERSISTED_STATE_INVENTORY.md` migration/cleanup source rows: entries for
  legacy UserDefaults, legacy metadata rows, self-test directory, tutorial UUID
  suites, and cleanup-only keys need follow-up updates after implementation.
- Architecture/Security current-state text: descriptions of legacy metadata
  rows, protected-settings v1 migration, raw/root-right migration, lazy
  revocation backfill, and old Documents paths should be removed or recast when
  those surfaces retire.

## Discovery Rule

If implementation work uncovers another app-owned old model, old schema,
migration path, fallback decoder, cleanup-only old hook, or legacy fixture
dependency, add it to the retirement inventory before choosing PR order. Do not
describe it as a supported long-term path unless the maintainer explicitly
approves that separate request.

## Validation Notes

For this draft-only change, validation is limited to Markdown hygiene and symbol
coverage checks. No Xcode or Rust tests are required until implementation code
changes begin.
