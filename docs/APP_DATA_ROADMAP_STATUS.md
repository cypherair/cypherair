# AppData Roadmap Status

> **Last reviewed:** 2026-04-26
> **Status:** Current progress record for the AppData protection roadmap.
> **Scope:** Documents code-backed progress for AppData Phase 1-9 and the persistent-state inventory. This file does not change roadmap order or authorize implementation work by itself.
> **Related documents:** [APP_DATA_PROTECTION_PLAN](APP_DATA_PROTECTION_PLAN.md) · [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_VALIDATION](APP_DATA_VALIDATION.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)

## 1. Phase Status

| Phase | Name | Current status | Evidence and notes |
|-------|------|----------------|--------------------|
| Phase 1 | Protected App-Data Framework | Implemented | `ProtectedDataRegistry`, registry bootstrap/classification, root-secret authorization, app-session access gate, relock, and recovery dispatch are implemented and covered by `ProtectedDataFrameworkTests`. |
| Phase 2 | File-Protection Baseline | Implemented for ProtectedData storage | `ProtectedDataStorageRoot` applies and verifies `.complete` file protection for registry, bootstrap metadata, scratch writes, and wrapped-DMK files. Coverage lives in `ProtectedDataStorageRootTests`. |
| Phase 3 | First Low-Risk Real Domain | Implemented narrowly | The first real domain is `protected-settings`; the only migrated setting is `clipboardNotice`. Other ordinary settings remain outside this phase and are tracked as Phase 7 targets. |
| Phase 4 | Post-Unlock Multi-Domain Orchestration And Framework Hardening | Partial | Post-unlock handoff exists and can open registered committed domains with the app-authenticated `LAContext`. Remaining work includes a second real production domain, second-domain create/delete/recovery coverage, and pending-create continuation hardening. |
| Phase 5 | Private-Key Control Domain | Pending | `authMode` and private-key recovery flags remain in `UserDefaults`; this phase must create `private-key-control` before moving them. |
| Phase 6 | Key Metadata Domain | Pending | `PGPKeyIdentity` metadata remains in the transitional Keychain metadata account. |
| Phase 7 | Non-Contacts Protected-After-Unlock Domains | Pending / partial by surface | Ordinary settings other than `clipboardNotice`, self-test state, and temporary/export/tutorial cleanup or file-protection work remain here unless explicitly classified as an exception. |
| Phase 8 | Contacts Protected Domain | Pending | Contacts migration has not started. Contacts PR1-PR8 belong to Phase 8 and remain gated behind Phase 5-7, with AppData Phase 4 as a prerequisite. |
| Phase 9 | Future Persistent Domains | Pending | Reserved for future app-owned persistent domains not covered by the current inventory. |

## 2. Phase 3 Boundary

Phase 3 is complete only in its narrow first-domain sense:

- `ProtectedSettingsStore` exists as the first real ProtectedData domain.
- `clipboardNotice` is migrated into that domain.
- Settings unlock can reuse a current app-session `LAContext` handoff without an extra prompt.

Phase 3 does not mean all settings have moved. The remaining ordinary settings and related protected-after-unlock control state are Phase 7 work unless another phase explicitly owns them.

## 3. Phase 4 Boundary

Phase 4 has working post-unlock orchestration, but it is not complete.

Implemented:

- `ProtectedDataPostUnlockCoordinator` opens registered committed domains after app privacy authentication.
- Production wiring currently registers `protected-settings`.
- Unit coverage proves committed-domain open, missing-context skip, pending-mutation skip, and legacy-migration deferral behavior.

Remaining:

- prove a second real domain can be created, opened, deleted, and recovered without framework-specific assumptions
- remove or replace first-domain pending-create reset-only limitations
- add explicit tests for second-domain create/delete/recovery and last-domain cleanup behavior
- keep this framework-hardening work outside the Contacts-internal PR sequence

## 4. Inventory Status Rule

The persistent-state inventory in [APP_DATA_MIGRATION_GUIDE](APP_DATA_MIGRATION_GUIDE.md) is the row-level tracking table. Every in-scope row must carry:

- a target class
- a target phase or explicit exception
- a current status
- migration-readiness detail

`Migration readiness` answers whether the row can move now. `Current status` records whether it has actually moved. A row can be target-classified correctly while still being pending.
