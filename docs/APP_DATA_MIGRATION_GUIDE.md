# AppData Remaining Migration Guide

> **Status:** Active remaining-roadmap and inventory document.
> **Purpose:** Track the remaining ProtectedData migration work after AppData Phase 1-6, and keep the persisted-state inventory current while Phase 7 and Phase 8 wait for dedicated implementation planning.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Source of truth:** Current implementation details live in [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), [TDD](TDD.md), and [TESTING](TESTING.md). Phase completion status lives in [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md).
> **Last reviewed:** 2026-04-28.
> **Update triggers:** Any ProtectedData domain migration, persistent-state classification change, Contacts protected-domain gate change, or storage/relock/recovery behavior change.

## 1. Scope And Relationship

This guide is no longer the detailed implementation plan for the completed AppData foundation. Phase 1-6 have landed and are now documented as current behavior in the long-lived architecture, security, technical, and testing docs.

This guide remains active for:

- remaining Phase 7 non-Contacts protected-after-unlock surfaces
- Phase 8 Contacts readiness gates
- Phase 9 future app-owned persistent domains
- the reviewed persistent-state inventory
- cross-domain migration rules that future dedicated plans must preserve

This guide does not create the Phase 7 implementation plan. It only records the remaining scope and constraints that a later Phase 7 plan must honor.

## 2. Current Foundation Status

| Phase | Current state | Durable result |
|-------|---------------|----------------|
| Phase 1: Protected App-Data Framework | Implemented | `ProtectedDataRegistry`, shared root-secret authorization, wrapped-DMK lifecycle, relock, recovery dispatch, and app-session access gates exist. |
| Phase 2: File-Protection Baseline | Implemented for ProtectedData storage | Registry, bootstrap metadata, scratch writes, and wrapped-DMK files use explicit file-protection checks where supported. |
| Phase 3: First Low-Risk Real Domain | Implemented narrowly | `protected-settings` exists and currently stores only `clipboardNotice`. |
| Phase 4: Post-Unlock Multi-Domain Orchestration | Implemented | App unlock can open registered committed domains with the authenticated `LAContext`; the framework sentinel proves multi-domain lifecycle behavior. |
| Phase 5: Private-Key Control Domain | Implemented | `private-key-control` owns `authMode` and private-key rewrap / modify-expiry recovery journal state after app unlock. |
| Phase 6: Key Metadata Domain | Implemented | `key-metadata` owns `PGPKeyIdentity` payloads after app unlock and migrates legacy metadata Keychain rows. |

Current ProtectedData implementation details are intentionally not repeated here. Use [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), [TDD](TDD.md), and [TESTING](TESTING.md) for the current technical contract.

## 3. Remaining Roadmap

### Phase 7: Non-Contacts Protected-After-Unlock Domains

Phase 7 remains pending. It should be planned separately before implementation.

Known Phase 7 surfaces:

- ordinary settings that remain in `UserDefaults`, including `gracePeriod`, onboarding completion, theme, encrypt-to-self, and guided tutorial completion state
- self-test reports or diagnostics state under `Documents/self-test/`
- temporary decrypted, streaming, export, and tutorial files that need final cleanup and file-protection review
- tutorial-only defaults and sandbox cleanup guarantees

Phase 7 must not move a setting merely because it is user-visible. It must first remove or replace synchronous/pre-unlock read paths and prove launch authentication strength is unchanged.

### Phase 8: Contacts Protected Domain

Phase 8 remains pending and should continue through the Contacts-specific documents:

- [CONTACTS_PRD](CONTACTS_PRD.md)
- [CONTACTS_TDD](CONTACTS_TDD.md)
- [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
- [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)

Contacts must remain a domain-specific consumer of the shared ProtectedData framework. It must not introduce a second vault architecture or take ownership of registry authority, root-secret lifecycle, wrapped-DMK lifecycle, or app-session grace-window behavior.

Contacts PR1-PR8 remain gated behind Phase 7 unless the roadmap is explicitly revised.

### Phase 9: Future Persistent Domains

Phase 9 is reserved for future app-owned persistent domains not covered by the current inventory. New domains must be classified before implementation and must reuse the shared ProtectedData framework unless an explicit exception is documented.

## 4. Startup And Session Guardrails

Remaining migrations must preserve the current two-stage startup boundary.

Before app-session authentication succeeds, code may:

- read bootstrap-critical settings that are still classified as early-readable exceptions
- classify `ProtectedDataRegistry`
- read per-domain bootstrap metadata
- route to locked/recovery UI states
- clean temporary files that do not require protected-domain contents

Before app-session authentication succeeds, code must not:

- fetch the shared app-data root secret
- unwrap any domain master key
- open protected-domain payload generations
- infer committed domain membership from directory enumeration
- rebuild protected-domain contents from legacy sources after cutover

After app-session authentication succeeds, the app may reuse the authenticated `LAContext` to activate the shared ProtectedData session and open registered committed domains without a redundant prompt. Launch/resume authentication alone does not imply ProtectedData is active unless root-secret retrieval and wrapping-root-key derivation also succeeded.

`AppSessionOrchestrator` remains the only grace-window owner. `ProtectedDataSessionCoordinator` owns app-data root-secret retrieval, wrapping-root-key lifetime, relock fan-out, and runtime-only `restartRequired`.

## 5. Persisted-State Inventory

The long-term goal is to protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.

Allowed target classes:

- `protected-after-unlock`
- `early-readable boot exception`
- `private-key-control target`
- `key-metadata-domain target`
- `private-key-material exception`
- `framework-bootstrap`
- `ephemeral-with-cleanup`
- `out-of-app-custody`
- `legacy cleanup-only`
- `test-only exception`

| Item | Current location | Target class | Target phase / exception | Current status | Migration readiness |
|------|------------------|--------------|--------------------------|----------------|---------------------|
| `appSessionAuthenticationPolicy` | `UserDefaults` | `early-readable boot exception` | Boot exception | Exception retained | n/a in v1 |
| `authMode` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | Phase 5 | Implemented | implemented |
| `gracePeriod` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no |
| `hasCompletedOnboarding` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no |
| `colorTheme` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no |
| `requireAuthOnLaunch` | Retired legacy `UserDefaults` key | `legacy cleanup-only` | Legacy cleanup | Cleanup-only | cleanup only |
| `encryptToSelf` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no |
| `clipboardNotice` | `ProtectedSettingsStore`; legacy `UserDefaults` only as migration source | `protected-after-unlock` | Phase 3 | Implemented | implemented |
| `guidedTutorialCompletedVersion` | `UserDefaults` | `protected-after-unlock` | Phase 7 | Pending | no |
| `uiTestBypassAuthentication` | Test-only `UserDefaults` key | `test-only exception` | Test-only exception | Exception retained | n/a |
| `rewrapInProgress` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | Phase 5 | Implemented | implemented |
| `rewrapTargetMode` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | Phase 5 | Implemented | implemented |
| `modifyExpiryInProgress` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | Phase 5 | Implemented | implemented |
| `modifyExpiryFingerprint` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | Phase 5 | Implemented | implemented |
| Permanent SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Pending SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| `PGPKeyIdentity` metadata rows | `ProtectedData/key-metadata`; legacy metadata-account and default-account rows only as migration sources | `key-metadata-domain target` | Phase 6 | Implemented | implemented |
| Shared app-data root secret | Keychain default account | `framework-bootstrap` | Phase 1 | Implemented with SE device binding | implemented |
| `ProtectedDataRegistry` | `Application Support/ProtectedData/ProtectedDataRegistry.plist` | `framework-bootstrap` | Phase 1 / Phase 2 | Implemented | framework prerequisite |
| Per-domain bootstrap metadata | `Application Support/ProtectedData/<domain>/bootstrap.plist` | `framework-bootstrap` | Phase 2 / domain phase | Implemented for existing domains | domain-specific |
| Protected settings payload | `Application Support/ProtectedData/protected-settings/` | `protected-after-unlock` | Phase 3 | Implemented narrowly | implemented |
| Private-key control payload | `Application Support/ProtectedData/private-key-control/` | `private-key-control target` | Phase 5 | Implemented | implemented |
| Key metadata payload | `Application Support/ProtectedData/key-metadata/` | `key-metadata-domain target` | Phase 6 | Implemented | implemented |
| Framework sentinel payload | `Application Support/ProtectedData/protected-framework-sentinel/` | `framework-bootstrap` | Phase 4 | Implemented | implemented |
| `Documents/contacts/*.gpg` | App sandbox documents | `protected-after-unlock` | Phase 8 | Pending | no |
| `Documents/contacts/contact-metadata.json` | App sandbox documents | `protected-after-unlock` | Phase 8 | Pending | no |
| `Documents/self-test/` | App sandbox documents | `protected-after-unlock` or `ephemeral-with-cleanup` | Phase 7 | Pending | no |
| `tmp/decrypted/` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial |
| `tmp/streaming/` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial |
| `tmp/export-*` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial |
| `tmp/CypherAirGuidedTutorial-*` | App temporary directory | `ephemeral-with-cleanup` | Phase 7 | Partial | partial |
| Tutorial `UserDefaults` suite | Temporary tutorial suite name | `ephemeral-with-cleanup` | Phase 7 | Partial | partial |
| Files exported to user-selected locations | Outside app-controlled sandbox after export | `out-of-app-custody` | Out-of-app-custody exception | Exception retained | n/a |

## 6. Migration Rules

Every future migration from plaintext, Keychain metadata, or non-uniform local state into a protected domain must:

- preserve readable source state until the protected destination is confirmed valid
- validate and normalize source state before writing the protected destination
- verify protected-domain readability before retiring or quarantining source state
- never silently reset unreadable converted state to empty data
- make corrupted committed protected state a recovery surface
- document cleanup or quarantine behavior explicitly
- update [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md) and the long-lived docs in the same change

For Phase 7 settings, no shadow copy may be introduced to preserve pre-unlock behavior. If a setting still controls launch authentication, startup routing, or pre-unlock UI before ProtectedData opens, the implementation must first redesign that read path or keep the setting as an explicit boot exception.

For Phase 8 Contacts, legacy plaintext sources must remain inactive after cutover, must not be treated as a fallback source of truth, and must be deleted only after a later successful Contacts domain open confirms the protected destination is readable.
