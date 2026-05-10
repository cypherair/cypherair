# AppData Roadmap Status

> **Status:** Archived historical AppData roadmap/status snapshot.
> **Archived on:** 2026-05-02.
> **Archival reason:** AppData Phase 1-7 are complete, Phase 8 Contacts sequencing now lives in Contacts-specific docs, and durable current-state facts have been absorbed into long-lived docs.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md) · [PERSISTED_STATE_INVENTORY](../PERSISTED_STATE_INVENTORY.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**
>
> Original snapshot metadata follows.
>
> **Last reviewed:** 2026-05-02
> **Original pre-archive status:** Current progress record for the AppData protection roadmap.
> **Scope:** Documents code-backed progress for AppData Phase 1-9 and the persistent-state inventory. This file does not change roadmap order or authorize implementation work by itself.
> **Original related documents:** [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)

## 1. Phase Status

| Phase | Name | Current status | Evidence and notes |
|-------|------|----------------|--------------------|
| Phase 1 | Protected App-Data Framework | Implemented | `ProtectedDataRegistry`, registry bootstrap/classification, root-secret authorization, app-session access gate, relock, and recovery dispatch are implemented and covered by `ProtectedDataFrameworkTests`. |
| Phase 2 | File-Protection Baseline | Implemented for ProtectedData storage | `ProtectedDataStorageRoot` applies and verifies `.complete` file protection for registry, bootstrap metadata, scratch writes, and wrapped-DMK files. Coverage lives in `ProtectedDataStorageRootTests`. |
| Phase 3 | First Low-Risk Real Domain | Implemented narrowly | The first real domain is `protected-settings`; Phase 3's original migrated setting was `clipboardNotice`. Phase 7 PR 2 later expanded that domain with ordinary settings. |
| Phase 4 | Post-Unlock Multi-Domain Orchestration And Framework Hardening | Implemented | Phase 4 established production wiring for `protected-settings` plus the framework-owned `protected-framework-sentinel` domain. Post-unlock handoff can create/open the sentinel as a second domain after settings is committed, generic recovery dispatch is keyed by `ProtectedDataDomainID`, and second-domain create/delete/recovery plus pending-create continuation coverage live in `ProtectedDataFrameworkTests`. Phase 5 later adds `private-key-control` to the post-unlock opener path. |
| Phase 5 | Private-Key Control Domain | Implemented | `PrivateKeyControlStore` is wired as the `private-key-control` ProtectedData domain. It migrates `authMode` plus rewrap / modify-expiry recovery journal state out of legacy `UserDefaults` after app authentication, opens through post-unlock orchestration, participates in relock, and is covered by `ProtectedDataFrameworkTests` plus private-key recovery tests. |
| Phase 6 | Key Metadata Domain | Implemented | `KeyMetadataDomainStore` owns ProtectedData domain `key-metadata` for `PGPKeyIdentity` payloads after app unlock. Migration reads both the transitional metadata account and older default-account metadata rows, cleans source rows only after verified domain creation/open, and preserves private-key material in the existing Keychain / Secure Enclave domain. |
| Phase 7 | Non-Contacts Protected-After-Unlock Domains | Implemented / PR 5 documentation gate closed | `ProtectedOrdinarySettingsCoordinator` owns ordinary-settings lock state and now loads/saves grace period, onboarding, theme, encrypt-to-self, and tutorial completion from `protected-settings` schema v2 after app authentication. Legacy ordinary `UserDefaults` keys are cleanup-only after verified migration. Self-test reports are in-memory export-only data, and legacy `Documents/self-test/` is cleanup-only on startup and local-data reset. `AppTemporaryArtifactStore` owns Phase 7 temporary paths, verified `.complete` file protection, owner cleanup, startup/reset cleanup, fixed tutorial defaults cleanup, and legacy tutorial defaults UUID sweep for decrypted, streaming, export handoff, and tutorial artifacts. PR 5 closed the documentation and Phase 8 gate. Architecture-level requirements and auditable PR tracks live in [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md). |
| Phase 8 | Contacts Protected Domain | Pending / unblocked | Contacts migration has not started. Contacts PR1-PR8 belong to Phase 8 and are unblocked by the completed Phase 7 closure; implementation proceeds through the Contacts-specific plan and inventory. |
| Phase 9 | Future Persistent Domains | Pending | Reserved for future app-owned persistent domains not covered by the current inventory. |

## 2. Phase 3 Boundary

Phase 3 is complete only in its narrow first-domain sense:

- `ProtectedSettingsStore` exists as the first real ProtectedData domain.
- `clipboardNotice` is migrated into that domain. Phase 7 PR 2 keeps this domain as the protected settings home for ordinary settings too.
- Settings unlock can reuse a current app-session `LAContext` handoff without an extra prompt.

Phase 3 by itself did not mean all settings had moved. Phase 7 PR 2 owns the ordinary-settings expansion, and Phase 7 PR 3-PR 5 closed the non-Contacts protected-after-unlock documentation gate.

## 3. Phase 4 Boundary

Phase 4 is complete for framework hardening. It proves the ProtectedData substrate can operate more than one committed production domain before later product-domain migrations begin.

Implemented:

- `ProtectedDataPostUnlockCoordinator` opens registered committed domains after app privacy authentication and can run a registered domain's noninteractive `ensureCommittedIfNeeded` hook inside the same authenticated handoff.
- Phase 4 production and UI-test wiring registered both `protected-settings` and `protected-framework-sentinel`.
- The sentinel is framework-owned, non-user, and non-telemetry; it records only a schema version plus a fixed purpose marker.
- The sentinel is created only when another ProtectedData domain is already committed and the shared resource is `.ready`; it never creates the first protected domain on a clean install.
- Recovery accepts a handler list and dispatches by `ProtectedDataDomainID`; mismatched or missing handlers stay in framework recovery.
- Non-first-domain pending creates can resume from `journaled`, `artifactsStaged`, `validated`, or clear `membershipCommitted`.
- First-domain pre-membership pending create remains an explicit reset-required framework policy.
- Unit coverage proves committed multi-domain post-unlock open, missing-context / empty-registry / pending-mutation no-root-secret paths, second-domain create/delete/recovery, last-domain cleanup, and recovery dispatch behavior.

Remaining product migrations:

- contacts and any future protected-after-unlock product surfaces remain Phase 8+ pending implementation. Self-test report persistence is implemented as Phase 7 PR 3 export-only memory state plus legacy cleanup, temporary/export/tutorial hardening is implemented as Phase 7 PR 4 `ephemeral-with-cleanup`, and PR 5 closed the Phase 7 documentation gate.

## 4. Phase 5 Boundary

Phase 5 is complete for the private-key control source of truth:

- `PrivateKeyControlStore` exists as the `private-key-control` ProtectedData domain.
- `authMode` migrates from legacy `UserDefaults` into `private-key-control.settings.authMode`.
- `rewrapInProgress`, `rewrapTargetMode`, `modifyExpiryInProgress`, and `modifyExpiryFingerprint` migrate into `private-key-control.recoveryJournal`.
- Post-unlock orchestration can bootstrap or open the domain with the current authenticated `LAContext` handoff.
- Rewrap and modify-expiry recovery detection runs only after the domain is unlocked.

Phase 5 does not move private-key material into ProtectedData. Permanent and pending SE-wrapped private-key bundle rows remain in the existing Keychain / Secure Enclave private-key material domain.

Phase 6 later moved key metadata only. Ordinary protected-after-unlock settings are implemented by Phase 7 PR 1-PR 2, self-test export-only state by PR 3, temporary/export/tutorial cleanup by PR 4, and documentation/gate closure by PR 5; Contacts are unblocked Phase 8 targets.

## 5. Phase 6 Boundary

Phase 6 is complete for the key metadata source of truth:

- `KeyMetadataDomainStore` exists as the `key-metadata` ProtectedData domain.
- Payload schema v1 stores `schemaVersion` plus sorted `identities: [PGPKeyIdentity]`.
- `KeyCatalogStore` writes through `KeyMetadataPersistence`; production wiring uses ProtectedData metadata while the legacy Keychain store remains a migration source and test helper.
- Post-unlock orchestration creates/opens `key-metadata` after `private-key-control` and before protected settings/sentinel recovery checks, reusing the same authenticated `LAContext`.
- `AppStartupCoordinator` no longer loads key metadata before privacy authentication; Home and My Keys render locked/loading/recovery states until `.loaded`.
- Migration preserves both upgrade paths: current transitional `metadataAccount` rows and older default-account metadata rows. Dedicated metadata rows win by fingerprint during dual-source migration.
- Pending-create recovery must reuse the authenticated `LAContext` for default-account metadata or remain retryable without committing a partial payload; legacy cleanup retry deletes already-migrated source rows by fingerprint membership.

Phase 6 does not move private-key material. Permanent and pending SE-wrapped private-key bundle rows remain in the existing Keychain / Secure Enclave private-key material domain.

## 6. Phase 7 Closure Summary

Phase 7 is complete. PR 1 is complete for ordinary-settings read-path ownership, PR 2 is complete for the ordinary-settings payload migration, PR 3 is complete for the self-test persistence decision, PR 4 is complete for temporary/export/tutorial hardening, and PR 5 closes the documentation and Phase 8 gate:

- `ProtectedOrdinarySettingsCoordinator` is the app-wide source for ordinary-settings `locked`, `loaded(snapshot)`, and `recoveryRequired` state.
- `AppConfiguration` keeps the early-readable `appSessionAuthenticationPolicy` boot exception plus runtime session state; it no longer owns ordinary settings such as grace period, onboarding completion, theme, encrypt-to-self, or guided tutorial completion.
- The ordinary-settings coordinator loads and saves through `protected-settings` schema v2 only after app privacy authentication and an unlocked protected-settings handoff. If protected settings is locked, in recovery, pending mutation, or framework-unavailable after authentication, the coordinator enters `recoveryRequired` and does not read legacy values.
- `protected-settings` schema v2 preserves `clipboardNotice` and adds the ordinary-settings snapshot: `gracePeriod`, `hasCompletedOnboarding`, `colorTheme`, `encryptToSelf`, and `guidedTutorialCompletedVersion`.
- Existing schema v1 protected-settings payloads migrate through an explicit compatibility path; legacy ordinary-setting keys are deleted only after the schema v2 payload is written, reopened, normalized, and verified readable.
- Existing schema v2 protected-settings payloads are authoritative over conflicting legacy `UserDefaults`; legacy keys are cleanup-only, never fallback.
- Resume grace fails closed to immediate authentication until the coordinator has a loaded snapshot. Relock and content-clear paths clear the loaded snapshot.
- `ProtectedSettingsHost` remains a Settings UI host for protected-settings section state such as clipboard notice. It is not the ordinary-settings source of truth.
- `SelfTestService` now produces the latest self-test report as in-memory export-only `Data` with a suggested filename. It no longer writes report history under `Documents/self-test/`.
- `AppStartupCoordinator` and Reset All Local Data remove legacy `Documents/self-test/` content without opening ProtectedData, fetching the root secret, or creating a diagnostics ProtectedData domain.
- `AppTemporaryArtifactStore` creates per-operation streaming and decrypted outputs under `tmp/streaming/op-<UUID>/...` and `tmp/decrypted/op-<UUID>/...`, applies and verifies `.complete` file protection, and removes owner directories on failure, cancellation-after-service-return, view cleanup, startup, or Reset All Local Data.
- `FileExportController.prepareDataExport` writes `tmp/export-<UUID>-<filename>` with atomic complete file protection, verifies the protection class, owns only files it creates, and deletes those handoff files on `finish()`, startup cleanup, or Reset All Local Data.
- `TutorialSandboxContainer` creates `tmp/CypherAirGuidedTutorial-<UUID>/` with verified `.complete` protection, uses the fixed `com.cypherair.tutorial.sandbox` defaults suite for the single active tutorial sandbox, and removes the current tutorial directory plus fixed suite on reset/finish.
- Startup cleanup and Reset All Local Data directly clear `com.cypherair.tutorial.sandbox`, then enumerate the app Preferences directory for legacy `com.cypherair.tutorial.<UUID>.plist` orphans and delete residual plists so tutorial defaults orphaned by crash or system kill do not persist.

Phase 7 closure does not change Rust cryptographic behavior, UniFFI shape, ProtectedData schema, entitlements, Contacts storage, or user-selected export destinations after they leave app custody.

## 7. Inventory Status Rule

The persistent-state inventory in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) is the row-level tracking table. Every in-scope row must carry:

- a target class
- a target phase or explicit exception
- a current status
- migration-readiness detail

`Migration readiness` answers whether the row can move now. `Current status` records whether it has actually moved. A row can be target-classified correctly while still being pending.
