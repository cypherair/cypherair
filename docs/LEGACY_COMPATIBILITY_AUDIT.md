# Legacy Compatibility Audit

> Status: Audit snapshot.
> Date: 2026-05-13.
> Scope: First-party Swift app code, `pgp-mobile/src`, repository scripts, workflow entrypoints, and directly related tests. Generated UniFFI Swift bindings are excluded as hand-maintained debt.
> Purpose: Identify retained legacy, migration, compatibility, deprecated, and cleanup-only surfaces; separate code that must remain for old-install protection from residue that can be cleaned up; and name tests that should be retained, rewritten, or removed with those surfaces.
> Audience: CypherAir maintainers, reviewers, and coding agents planning follow-up refactors or cleanup work.
> Truth sources: Current repository files, targeted `rg` reference checks, `docs/DOCUMENTATION_GOVERNANCE.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/PERSISTED_STATE_INVENTORY.md`, and `docs/TESTING.md`.

This document is a point-in-time audit. It does not replace the current code,
security model, persisted-state inventory, or testing guidance. Current code and
canonical current-state documentation outrank this snapshot whenever they drift.

## Summary

The codebase contains a meaningful amount of retained legacy, migration, and
compatibility logic, but most of the high-risk material is not dead code. It
protects old installs, migrates local state into ProtectedData domains, cleans
up historical storage, or preserves FFI/API compatibility while newer detailed
APIs are adopted.

The main cleanup opportunity is not immediate deletion of all migration code.
The safer direction is to isolate retained migration and compatibility logic
away from primary service files, then remove cleanup-only or production-unused
surfaces after their tests are rewritten or retired.

Search snapshot:

- Production/tooling files scanned: 305.
- Files with legacy/migration/compatibility/deprecated-like terms: 88.
- Matching lines: 955.
- Only one Swift `@available(... deprecated ...)` annotation was found:
  `ContactService.publicKeysForRecipientFingerprints(_:)`.
- No `Localizable.xcstrings` entries with `extractionState: stale` were found.
- No confirmed orphan legacy UI screen was found in this pass.

## Classification

| Classification | Meaning | Test treatment |
| --- | --- | --- |
| Retain But Isolate | Still protects old installs, persisted data, security recovery, FFI compatibility, or an active compatibility contract. Keep for now, but move toward dedicated migration/compatibility ownership instead of primary production files. | Keep migration/recovery tests, but regroup them around the isolated migration or compatibility unit. |
| Cleanup Candidate | Not used by current production paths and not needed for persisted-data migration, security recovery, or a current compatibility contract. | Remove tests that only preserve this obsolete behavior, or first rewrite tests that still cover valuable behavior through old APIs. |
| Not Legacy Debt | Current product compatibility or security behavior that can look legacy by keyword search but remains intentional. | Keep normal product/security coverage. |

## Inventory

| Area | Representative files | Classification | Current use | Tests affected | Recommended isolation or cleanup | Cleanup trigger | Risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Contacts legacy file runtime and protected-domain cutover | `Sources/Services/ContactService.swift`, `Sources/Services/ContactRepository.swift`, `Sources/Services/ContactsLegacyMigrationSource.swift`, `Sources/Services/ContactsDomainRepository.swift`, `Sources/App/AppContainer.swift` | Retain But Isolate | Production opens the ProtectedData `contacts` domain after authentication. Legacy `Documents/contacts`, quarantine, and runtime compatibility remain as migration source, cleanup source, test/runtime fallback, and pre-commit failure fallback. | Keep tests that prove legacy contacts migrate once, quarantine is not used as fallback, protected state wins, relock clears runtime state, and reset removes legacy files. Review tests that only exercise legacy flat runtime behavior. | Extract Contacts cutover/quarantine and legacy runtime compatibility out of `ContactService` into a focused Contacts migration/compatibility boundary. Keep `ContactService` as the app-facing facade. | After the supported old-install migration window ends and production/test containers no longer need legacy flat runtime fallback. | High: contacts carry public certificates and trust/verification state; wrong cleanup can lose contacts or reactivate plaintext state. |
| Legacy flat contact key-replacement flow | `Sources/Services/ContactService.swift`, `Sources/App/Contacts/Import/ContactImportWorkflow.swift` | Retain But Isolate | `.keyUpdateDetected` is documented as legacy flat Contacts behavior. Protected-domain Contacts import related different-fingerprint keys as separate identities and reject legacy replacement. UI still handles the legacy result defensively. | `ContactServiceTests` covers `keyUpdateDetected` and confirm-replacement behavior. These should be split into legacy-runtime tests and removed when the legacy runtime exits. | Move key-replacement behavior behind a legacy Contacts runtime adapter. Keep protected-domain import behavior separate. | When `openLegacyCompatibilityForTests` and the legacy flat runtime are retired or no longer part of supported data migration. | Medium: mostly public-key/contact UX, but deletion could break old contact replacement tests before the runtime is removed. |
| Fingerprint recipient encryption compatibility | `Sources/Services/EncryptionService.swift`, `Sources/Services/ContactRecipientResolver.swift`, `Sources/Services/ContactService.swift` | Retain But Isolate, with cleanup candidates inside it | Current production UI passes contact IDs. `recipientFingerprints` overloads and `legacyPublicKeysForRecipientFingerprints` remain for older callers/tests. `publicKeysForRecipientFingerprints(_:)` is explicitly deprecated. | `EncryptionServiceTests`, `StreamingServiceTests`, `DecryptionServiceTests`, `PasswordMessageServiceTests`, and `TutorialSessionStoreTests` still call `recipientFingerprints`. These should be rewritten to contact-ID APIs where the behavior remains valuable. | Extract fingerprint-recipient compatibility into a small adapter. Remove the deprecated forwarding method and no-caller helpers after tests move to current APIs. | When service tests and tutorial tests no longer require fingerprint recipient overloads. | Medium: encryption behavior is security-sensitive, but this layer is recipient lookup compatibility, not cryptographic format selection. |
| No-caller ContactService helpers | `Sources/Services/ContactService.swift` | Cleanup Candidate | `availableContacts(matchingKeyIds:)`, `publicKeys(for:)`, and deprecated `publicKeysForRecipientFingerprints(_:)` have no direct production or test callers in the focused reference check. | No direct test callers were found for these exact symbols. Related fingerprint-recipient tests cover the broader compatibility path, not these helpers directly. | Remove after confirming no external package/API exposure expectation. If kept, move into a compatibility adapter with explicit tests. | Immediate cleanup candidate once maintainers accept there is no future pre-resolved primary-fingerprint use case. | Low to Medium: deletion is straightforward, but `ContactService` is central and should be changed with focused tests. |
| Protected settings and ordinary-settings migration | `Sources/Security/ProtectedData/ProtectedSettingsStore.swift`, `Sources/Models/ProtectedOrdinarySettingsPersistence.swift`, `Sources/Models/AppConfiguration.swift`, `Sources/App/Settings/ProtectedSettingsAccessCoordinator.swift` | Retain But Isolate | Migrates legacy UserDefaults ordinary settings and schema v1 protected-settings payloads to protected-settings schema v2. Removes legacy UserDefaults only after verified creation/open. | Keep `ProtectedDataFrameworkTests`, `SettingsScreenModelTests`, and ordinary-settings coordinator tests that prove migration, failure, recovery, and fail-closed behavior. | Extract legacy settings import/removal and v1-to-v2 payload upgrade into a dedicated settings migration component. Keep the main store focused on current protected-settings persistence. | After the old settings support window ends and there is evidence that supported installs have upgraded to schema v2. | High: wrong behavior can reset auth-adjacent settings, onboarding state, encrypt-to-self preference, or fail-open availability. |
| Private-key control legacy defaults and recovery journal migration | `Sources/Security/ProtectedData/PrivateKeyControlStore.swift`, `Sources/Security/KeyMigrationCoordinator.swift`, `Sources/Security/AuthenticationManager.swift`, `Sources/Services/KeyManagementService.swift` | Retain But Isolate | Migrates `authMode`, rewrap state, and modify-expiry recovery state from legacy UserDefaults into the `private-key-control` ProtectedData domain. Recovery journal handling remains current behavior, not deprecated residue. | Keep tests proving auth-mode migration, interrupted rewrap recovery, modify-expiry recovery, and fail-closed recovery paths. Do not remove recovery tests as "legacy" while those journals remain current. | Separate legacy defaults import/cleanup from current private-key recovery journal operations. Keep journal recovery as current production logic. | Legacy defaults import can be removed only after old-install support expires. Current recovery journal logic should remain while rewrap/modify-expiry can be interrupted. | High: private-key control is security-sensitive and can affect authentication mode and key availability. |
| Key metadata Keychain-to-ProtectedData migration | `Sources/Security/KeyMetadataStore.swift`, `Sources/Security/ProtectedData/KeyMetadataDomainStore.swift`, `Sources/Services/KeyManagementService.swift`, `Sources/Services/KeyManagement/KeyCatalogStore.swift` | Retain But Isolate | Production uses the ProtectedData `key-metadata` domain. Legacy dedicated/default-account Keychain metadata rows remain migration and cleanup sources. `KeyManagementService.migrateLegacyMetadataAfterAppAuthentication` is active only for legacy `KeyMetadataStore` persistence paths; the domain store owns production migration. | Keep tests proving domain creation from legacy metadata, authenticated default-account handoff, retryable cleanup, warning surfacing, and reset removal. Tests that only validate old direct KeyMetadataStore persistence can be reviewed after the migration boundary is extracted. | Move metadata-source enumeration and cleanup into a dedicated key metadata migration adapter shared by the domain store and legacy fallback path. | After all supported installs have migrated metadata into ProtectedData and cleanup retries are no longer needed. | High: metadata is non-secret but indexes private keys and app availability; wrong cleanup can hide keys. |
| ProtectedData root-secret v1/raw and legacy right-store migration | `Sources/Security/ProtectedData/ProtectedDataRightStoreClient.swift`, `Sources/Security/ProtectedData/ProtectedDataRootSecretCoordinator.swift`, `Sources/Security/ProtectedData/ProtectedDataDeviceBinding.swift`, `Sources/App/Settings/LocalDataResetService.swift` | Retain But Isolate | Current root-secret format is the v2 `CAPDSEV2` Secure Enclave device-binding envelope. Legacy raw root-secret payloads and legacy right-store migration remain old-install paths. The format-floor marker is current anti-downgrade protection, not cleanup debt. | Keep tests for v1-to-v2 migration, format-floor downgrade rejection, legacy cleanup marker deletion, legacy right-store migration, reset cleanup, and device-binding failure modes. | Extract legacy raw/right-store migration into a root-secret legacy migration component. Keep v2 envelope, format floor, and device binding in current production ownership. | Only after a formal support cutoff for installs that may hold v1/raw or legacy right-store root secrets. | Critical: incorrect deletion can lock users out of protected app data or weaken downgrade protection. |
| Temporary artifact, self-test, and tutorial legacy cleanup | `Sources/App/Common/AppTemporaryArtifactStore.swift`, `Sources/App/AppStartupCoordinator.swift`, `Sources/App/Settings/LocalDataResetService.swift` | Retain But Isolate | Startup and Reset All Local Data remove legacy `Documents/self-test`, legacy tutorial defaults suites, and old temp/export/tutorial artifacts. Current temporary artifact cleanup also remains active production behavior. | Keep tests that prove startup/reset cleanup and file-protection expectations. Review tests that only create historical UUID tutorial suites once cleanup ownership is isolated. | Move legacy local-data cleanup rules into a single cleanup registry/helper so startup and reset do not duplicate historical path knowledge. | When old tutorial defaults and self-test path cleanup are no longer needed for supported installs. | Medium: mostly cleanup, but Reset All Local Data correctness depends on exhaustive deletion. |
| Swift/Rust signature verification legacy bridges | `pgp-mobile/src/signature_details.rs`, `pgp-mobile/src/verify.rs`, `pgp-mobile/src/decrypt.rs`, `pgp-mobile/src/streaming.rs`, `Sources/Models/DetailedSignatureVerification.swift`, `Sources/Services/SigningService.swift`, `Sources/Services/DecryptionService.swift`, `Sources/Services/PasswordMessageService.swift`, `Sources/Services/SelfTestService.swift` | Retain But Isolate, with rewrite candidates | App UI and main screen models already use detailed APIs. Legacy-returning Swift facade methods internally use detailed APIs, then fold back to `SignatureVerification`. Simple FFI APIs still exist, and `SelfTestService` directly calls `engine.decrypt` and `engine.verifyCleartext`. | Keep detailed API tests. Rewrite tests in `SigningServiceTests`, `DecryptionServiceTests`, `StreamingServiceTests`, `GnuPGInteropTests`, `DeviceMIETests`, and `FFIIntegrationTests` that still use simple APIs when their coverage is still valuable. Remove tests that only compare detailed results to legacy folded summaries after the compatibility contract is retired. | Move legacy fold behavior and simple-API wrappers into explicit compatibility sections/modules. Convert `SelfTestService` to detailed APIs before removing simple FFI coverage. | After SelfTest and tests are rewritten to detailed APIs, and maintainers decide the simple FFI contract can be retired. | High: verification status semantics affect user trust decisions; migration must preserve or intentionally replace legacy summary semantics. |
| Raw User ID first-match FFI APIs | `pgp-mobile/src/cert_signature.rs`, `pgp-mobile/src/keys/revocation.rs`, `pgp-mobile/src/lib.rs`, `Sources/Services/CertificateSignatureService.swift`, `Sources/Services/KeyManagement/SelectiveRevocationService.swift` | Cleanup Candidate after API review | Production Swift services use selector-based APIs for certification and selective revocation. Raw first-match FFI APIs remain exported and tested, primarily for duplicate User ID compatibility. | `FFIIntegrationTests` and Rust tests still cover raw first-match certification/revocation/verification behavior. Swift service tests mostly exercise selector-backed service methods despite older Swift method names. | Mark raw FFI methods as cleanup candidates or explicitly deprecated compatibility APIs. Keep selector APIs as current production contract. Rewrite/remove raw first-match tests with the raw API cleanup. | When generated bindings and downstream callers no longer need raw first-match methods. | Medium to High: duplicate User ID selection is correctness-sensitive; raw deletion must not remove selector coverage. |
| Historical arm64e experiment scripts | `scripts/experiments/README.md`, `scripts/experiments/build_apple_arm64e_xcframework.sh`, `scripts/experiments/repro_arm64e_rust_host_crashes.sh`, `scripts/experiments/sample_arm64e_darwin_toolchains.sh`, `scripts/experiments/probe_arm64e_tls_codegen_gap.sh` | Cleanup Candidate or Archive Candidate | Current formal app build entrypoint is repo-root `./build-xcframework.sh`, which delegates to `scripts/build_apple_arm64e_xcframework.sh`. The experiment directory is documented as historical/diagnostic. | Current script tests target `scripts/build_apple_arm64e_xcframework.sh`, not the experiment predecessor. No formal runtime tests depend on experiment scripts. | Archive, move out of active scripts, or delete after maintainers confirm diagnostics are no longer useful. Keep `docs/ARM64E_STATUS.md` current if script posture changes. | When arm64e diagnostics no longer need local historical reproduction helpers. | Low to Medium: cleanup can confuse future arm64e forensics if historical evidence is removed too early. |
| UI layer | `Sources/App/**` | No confirmed Cleanup Candidate in this pass | Major app, macOS, onboarding/tutorial, settings, encrypt/decrypt/sign/verify, contacts, and shell views all had route, host, or test references in the focused pass. Some private view modifiers look orphaned by type-name search but are used through extension methods. | No legacy UI tests are identified for deletion from this pass. Tests that invoke current screen models through legacy service APIs are covered under the service/API areas above. | Do not remove UI solely from keyword hits. Run a separate route/reachability audit before any UI deletion. | N/A for this snapshot. | Medium: SwiftUI helper references can be indirect, so false positives are easy. |

## Cleanup Candidates

These items are the strongest candidates for direct cleanup or deprecation work,
provided maintainers accept the stated triggers:

- `ContactService.availableContacts(matchingKeyIds:)`: no direct production or
  test callers found. The inline comment also states it currently has zero
  callers and is retained only for possible future use.
- `ContactService.publicKeys(for:)`: no direct production or test callers found.
- `ContactService.publicKeysForRecipientFingerprints(_:)`: explicitly
  deprecated and no direct callers found. Broader fingerprint-recipient tests
  still need to move away from `recipientFingerprints` overloads before the
  whole compatibility layer is removed.
- Raw first-match User ID FFI methods:
  `verify_user_id_binding_signature`, `generate_user_id_certification`, and
  `generate_user_id_revocation`. Production Swift uses selector-based
  equivalents; raw tests should be removed or rewritten once the raw FFI
  contract is retired.
- Legacy folded-summary comparison tests once simple FFI APIs and
  legacy-returning Swift facades are retired. The app UI already uses detailed
  APIs, so remaining simple API usage is mostly compatibility surface,
  SelfTest, and tests.
- `scripts/experiments/build_apple_arm64e_xcframework.sh` and sibling
  experiment helpers, subject to arm64e diagnostic needs.

## Test Handling

| Test category | Current examples | Classification | Action |
| --- | --- | --- | --- |
| Real migration/recovery safety tests | `ProtectedDataFrameworkTests`, `LocalDataResetServiceTests`, private-key control and key metadata migration tests, Contacts cutover/quarantine tests | Retain But Isolate | Keep. Regroup around migration/recovery components when code is split. |
| Fingerprint-recipient tests | `EncryptionServiceTests`, `StreamingServiceTests`, `DecryptionServiceTests`, `PasswordMessageServiceTests`, `TutorialSessionStoreTests` using `recipientFingerprints` | Rewrite Candidate | Rewrite valuable coverage to contact-ID recipient APIs; remove tests that only prove legacy fingerprint overloads. |
| Legacy Contacts flat-runtime tests | `ContactServiceTests` cases around `openLegacyCompatibilityForTests`, `.availableLegacyCompatibility`, and `.keyUpdateDetected` | Mixed | Keep migration/cutover tests. Remove or isolate tests that only preserve legacy flat runtime after the runtime is retired. |
| Simple FFI / legacy verification tests | `SigningServiceTests`, `SigningServiceDetailedResultTests`, `DecryptionServiceTests`, `GnuPGInteropTests`, `DeviceMIETests`, `FFIIntegrationTests` | Mixed | Rewrite useful behavior to detailed APIs. Keep only explicit compatibility tests while simple APIs remain supported. |
| Raw User ID first-match tests | `FFIIntegrationTests`, `pgp-mobile/tests/certification_binding_tests.rs`, `pgp-mobile/tests/revocation_construction_tests.rs`, `pgp-mobile/tests/selector_discovery_tests.rs` | Cleanup or Rewrite Candidate | Preserve selector coverage. Remove raw first-match tests when raw methods are removed or deprecated out of the public FFI surface. |
| Historical script tests | Current script tests for `scripts/build_apple_arm64e_xcframework.sh` | Not cleanup debt | Keep current build script tests. Experiment-script tests were not identified in this pass. |

## Not Legacy Debt

The following surfaced during keyword searches but should not be treated as
deprecated residue:

- Profile A / SEIPDv1 and Profile B / SEIPDv2 behavior.
- GnuPG interoperability and Profile A compatibility language.
- Read-only OpenPGP compatibility support such as compressed input handling,
  where documented by the security/TDD model.
- QR import route/version behavior unless a separate product decision retires
  it.
- Alternative App Icons.
- Device passcode fallback language for Standard mode.
- ProtectedData root-secret v2 format floor and Secure Enclave device-binding
  behavior.
- Current temporary/export artifact cleanup.
- Current app-shell, tutorial, settings, encrypt, decrypt, sign, verify, and
  contacts UI routes.

## Follow-Up Rules For Cleanup Work

Before removing any item from this audit:

1. Confirm the item is not part of old-install migration, security recovery,
   local-data reset, or current compatibility policy.
2. Move valuable tests to current APIs first, especially contact-ID recipient
   APIs, selector-based User ID APIs, and detailed verification/decryption APIs.
3. Keep generated `Sources/PgpMobile/pgp_mobile.swift` out of manual cleanup;
   remove generated symbols only by changing Rust UniFFI exports and regenerating
   through the normal workflow.
4. For ProtectedData, keychain, authentication, contacts cutover, and Rust FFI
   changes, update canonical docs and run the relevant Swift/Rust validation
   suites described in `docs/TESTING.md`.
5. Do not treat keyword hits for `fallback` or `compatible` as cleanup evidence
   without route/call-site and product-policy checks.
