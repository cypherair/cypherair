# AppData Roadmap Status

> **Last reviewed:** 2026-04-28
> **Status:** Current progress record for the AppData protection roadmap.
> **Scope:** Documents code-backed progress for AppData Phase 1-9 and the persistent-state inventory. This file does not change roadmap order or authorize implementation work by itself.
> **Related documents:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)

## 1. Phase Status

| Phase | Name | Current status | Evidence and notes |
|-------|------|----------------|--------------------|
| Phase 1 | Protected App-Data Framework | Implemented | `ProtectedDataRegistry`, registry bootstrap/classification, root-secret authorization, app-session access gate, relock, and recovery dispatch are implemented and covered by `ProtectedDataFrameworkTests`. |
| Phase 2 | File-Protection Baseline | Implemented for ProtectedData storage | `ProtectedDataStorageRoot` applies and verifies `.complete` file protection for registry, bootstrap metadata, scratch writes, and wrapped-DMK files. Coverage lives in `ProtectedDataStorageRootTests`. |
| Phase 3 | First Low-Risk Real Domain | Implemented narrowly | The first real domain is `protected-settings`; the only migrated setting is `clipboardNotice`. Other ordinary settings remain outside this phase and are tracked as Phase 7 targets. |
| Phase 4 | Post-Unlock Multi-Domain Orchestration And Framework Hardening | Implemented | Phase 4 established production wiring for `protected-settings` plus the framework-owned `protected-framework-sentinel` domain. Post-unlock handoff can create/open the sentinel as a second domain after settings is committed, generic recovery dispatch is keyed by `ProtectedDataDomainID`, and second-domain create/delete/recovery plus pending-create continuation coverage live in `ProtectedDataFrameworkTests`. Phase 5 later adds `private-key-control` to the post-unlock opener path. |
| Phase 5 | Private-Key Control Domain | Implemented | `PrivateKeyControlStore` is wired as the `private-key-control` ProtectedData domain. It migrates `authMode` plus rewrap / modify-expiry recovery journal state out of legacy `UserDefaults` after app authentication, opens through post-unlock orchestration, participates in relock, and is covered by `ProtectedDataFrameworkTests` plus private-key recovery tests. |
| Phase 6 | Key Metadata Domain | Pending | `PGPKeyIdentity` metadata remains in the transitional Keychain metadata account. |
| Phase 7 | Non-Contacts Protected-After-Unlock Domains | Pending / partial by surface | Ordinary settings other than `clipboardNotice`, self-test state, and temporary/export/tutorial cleanup or file-protection work remain here unless explicitly classified as an exception. |
| Phase 8 | Contacts Protected Domain | Pending | Contacts migration has not started. Contacts PR1-PR8 belong to Phase 8 and remain gated behind the remaining Phase 6-7 work, with AppData Phase 4 as a prerequisite. |
| Phase 9 | Future Persistent Domains | Pending | Reserved for future app-owned persistent domains not covered by the current inventory. |

## 2. Phase 3 Boundary

Phase 3 is complete only in its narrow first-domain sense:

- `ProtectedSettingsStore` exists as the first real ProtectedData domain.
- `clipboardNotice` is migrated into that domain.
- Settings unlock can reuse a current app-session `LAContext` handoff without an extra prompt.

Phase 3 does not mean all settings have moved. The remaining ordinary settings and related protected-after-unlock control state are Phase 7 work unless another phase explicitly owns them.

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

- `key metadata`, ordinary settings, contacts, and other protected-after-unlock surfaces remain Phase 6-8 work.

## 4. Phase 5 Boundary

Phase 5 is complete for the private-key control source of truth:

- `PrivateKeyControlStore` exists as the `private-key-control` ProtectedData domain.
- `authMode` migrates from legacy `UserDefaults` into `private-key-control.settings.authMode`.
- `rewrapInProgress`, `rewrapTargetMode`, `modifyExpiryInProgress`, and `modifyExpiryFingerprint` migrate into `private-key-control.recoveryJournal`.
- Post-unlock orchestration can bootstrap or open the domain with the current authenticated `LAContext` handoff.
- Rewrap and modify-expiry recovery detection runs only after the domain is unlocked.

Phase 5 does not move private-key material into ProtectedData. Permanent and pending SE-wrapped private-key bundle rows remain in the existing Keychain / Secure Enclave private-key material domain.

Phase 5 also does not complete the `key metadata` domain, ordinary protected-after-unlock settings, Contacts, or temporary/export/tutorial cleanup work. Those remain Phase 6-8 targets.

## 5. Inventory Status Rule

The persistent-state inventory in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) is the row-level tracking table. Every in-scope row must carry:

- a target class
- a target phase or explicit exception
- a current status
- migration-readiness detail

`Migration readiness` answers whether the row can move now. `Current status` records whether it has actually moved. A row can be target-classified correctly while still being pending.
