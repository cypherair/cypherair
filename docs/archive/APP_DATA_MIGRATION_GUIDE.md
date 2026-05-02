# AppData Migration Guide

> **Status:** Archived historical AppData migration and inventory snapshot.
> **Archived on:** 2026-05-02.
> **Archival reason:** AppData Phase 1-7 current-state facts have been absorbed into long-lived architecture, security, technical, testing, and review docs. Phase 8 Contacts follow-on work now lives in Contacts-specific docs.
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [TESTING](../TESTING.md) · [CODE_REVIEW](../CODE_REVIEW.md) · [CONTACTS_PRD](../CONTACTS_PRD.md) · [CONTACTS_TDD](../CONTACTS_TDD.md) · [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](../CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md) · [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](../CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**
>
> Original snapshot metadata follows.
>
> **Original pre-archive status:** Active current-state, roadmap, and inventory document.
> **Purpose:** Track completed AppData migration state, keep the persisted-state inventory current, and identify remaining Phase 8+ work after Phase 7 closure.
> **Audience:** Engineering, security review, QA, and AI coding tools.
> **Original source of truth:** Current implementation details lived in [ARCHITECTURE](../ARCHITECTURE.md), [SECURITY](../SECURITY.md), [TDD](../TDD.md), and [TESTING](../TESTING.md). Phase 7 implementation-reference requirements lived in [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md). Phase completion status lived in [APP_DATA_ROADMAP_STATUS](APP_DATA_ROADMAP_STATUS.md).
> **Last reviewed:** 2026-05-02.
> **Update triggers:** Any ProtectedData domain migration, persistent-state classification change, Contacts protected-domain gate change, or storage/relock/recovery behavior change.

## 1. Scope And Relationship

This guide is no longer the detailed implementation plan for the completed AppData foundation. Phase 1-7 have landed and are now documented as current behavior in the long-lived architecture, security, technical, and testing docs.

This guide remains active for:

- implemented Phase 7 non-Contacts protected-after-unlock surfaces and closure state
- Phase 8 Contacts readiness and follow-on planning
- Phase 9 future app-owned persistent domains
- the reviewed persistent-state inventory
- cross-domain migration rules that future dedicated plans must preserve

This guide no longer creates Phase 7 implementation work. It records the completed Phase 7 scope and the constraints future Phase 8+ plans must preserve. The Phase 7 architecture-level closure reference lives in [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md).

## 2. Current Foundation Status

| Phase | Current state | Durable result |
|-------|---------------|----------------|
| Phase 1: Protected App-Data Framework | Implemented | `ProtectedDataRegistry`, shared root-secret authorization, wrapped-DMK lifecycle, relock, recovery dispatch, and app-session access gates exist. |
| Phase 2: File-Protection Baseline | Implemented for ProtectedData storage | Registry, bootstrap metadata, scratch writes, and wrapped-DMK files use explicit file-protection checks where supported. |
| Phase 3: First Low-Risk Real Domain | Implemented narrowly | `protected-settings` exists and stores the original `clipboardNotice` payload; Phase 7 PR 2 extends that domain with ordinary settings. |
| Phase 4: Post-Unlock Multi-Domain Orchestration | Implemented | App unlock can open registered committed domains with the authenticated `LAContext`; the framework sentinel proves multi-domain lifecycle behavior. |
| Phase 5: Private-Key Control Domain | Implemented | `private-key-control` owns `authMode` and private-key rewrap / modify-expiry recovery journal state after app unlock. |
| Phase 6: Key Metadata Domain | Implemented | `key-metadata` owns `PGPKeyIdentity` payloads after app unlock and migrates legacy metadata Keychain rows. |
| Phase 7 PR 1: Ordinary Settings Read Paths | Implemented | `ProtectedOrdinarySettingsCoordinator` owns ordinary-settings lock state; PR 2 replaced the temporary legacy persistence source with `protected-settings` schema v2. |
| Phase 7 PR 2: Protected Settings Expansion | Implemented | `protected-settings` schema v2 owns grace period, onboarding completion, theme, encrypt-to-self, and guided tutorial completion after verified migration. |
| Phase 7 PR 3: Self-Test Persistence Decision | Implemented | Current self-test reports are in-memory export-only data; legacy `Documents/self-test/` is cleanup-only on startup and Reset All Local Data. |
| Phase 7 PR 4: Temporary / Export / Tutorial Hardening | Implemented | Streaming/decrypted outputs use per-operation temporary owner directories, export handoff files use verified complete protection, tutorial sandbox directories use verified complete protection, and startup/reset cleanup removes Phase 7 temporary artifacts plus the fixed tutorial defaults suite and legacy UUID tutorial-suite orphans. |
| Phase 7 PR 5: Documentation And Gate Closure | Implemented | Long-lived docs record Phase 7 as complete, and Phase 8 Contacts is unblocked for its Contacts-specific implementation plan. |

Current ProtectedData implementation details are intentionally not repeated here. Use [ARCHITECTURE](../ARCHITECTURE.md), [SECURITY](../SECURITY.md), [TDD](../TDD.md), and [TESTING](../TESTING.md) for the current technical contract.

## 3. Remaining Roadmap

### Phase 7: Non-Contacts Protected-After-Unlock Domains

Phase 7 is complete. PR 1 removed synchronous/pre-auth ordinary-settings read paths and introduced `ProtectedOrdinarySettingsCoordinator` as the app-wide `locked` / `loaded(snapshot)` / `recoveryRequired` source for ordinary settings. PR 2 moved the targeted ordinary settings into `protected-settings` schema v2. PR 3 selected the self-test short-lived/export-only model and made legacy `Documents/self-test/` cleanup-only. PR 4 hardened decrypted, streaming, export handoff, guided tutorial, and tutorial defaults artifacts as `ephemeral-with-cleanup`. PR 5 closes the documentation and roadmap gate. Architecture-level requirements and auditable PR tracks live in [APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE](APP_DATA_PHASE7_IMPLEMENTATION_REFERENCE.md).

Known Phase 7 surfaces:

- ordinary settings now owned by `ProtectedData/protected-settings` schema v2: `gracePeriod`, onboarding completion, theme, encrypt-to-self, and guided tutorial completion state
- self-test reports now generated as in-memory export-only data; legacy `Documents/self-test/` is cleanup-only
- temporary decrypted and streaming files now live under per-operation owner directories with verified `.complete` file protection and owner/startup/reset cleanup
- export handoff files now use atomic `.completeFileProtection` writes, verified `.complete` protection, owner cleanup, startup cleanup, and reset cleanup
- tutorial sandbox directories now use verified `.complete` protection, current tutorial cleanup, startup cleanup, and reset cleanup
- tutorial-only `UserDefaults` now use the fixed `com.cypherair.tutorial.sandbox` suite with current-container cleanup, startup/reset direct cleanup, and legacy startup/reset cleanup for orphaned `com.cypherair.tutorial.<UUID>.plist` files

Phase 7 must not move a setting merely because it is user-visible. It must first remove or replace synchronous/pre-unlock read paths and prove launch authentication strength is unchanged. PR 1 completed that read-path prerequisite for ordinary settings. PR 2 extended the protected-settings payload and retires legacy ordinary-setting sources only after schema v2 write/readback verification. PR 4 intentionally did not add a new ProtectedData domain because these artifacts remain short-lived and app-owned only until cleanup or explicit user export handoff.

The older [APP_DATA_PHASE7_TEMPORARY_RECORD](APP_DATA_PHASE7_TEMPORARY_RECORD.md) is superseded by the implementation reference and should be used only as a recovery/audit note for pre-reference material.

### Phase 8: Contacts Protected Domain

Phase 8 remains pending but is unblocked by Phase 7 closure. Contacts work should continue through the Contacts-specific documents:

- [CONTACTS_PRD](../CONTACTS_PRD.md)
- [CONTACTS_TDD](../CONTACTS_TDD.md)
- [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](../CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
- [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](../CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)

Contacts must remain a domain-specific consumer of the shared ProtectedData framework. It must not introduce a second vault architecture or take ownership of registry authority, root-secret lifecycle, wrapped-DMK lifecycle, or app-session grace-window behavior.

Contacts PR1-PR8 remain Phase 8 work and should follow the Contacts-specific PR sequence. PR5 does not implement Contacts or redesign the Contacts protected-domain schema.

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

`AppSessionOrchestrator` remains the only grace-window owner. Its grace-period provider must fail closed to immediate authentication until `ProtectedOrdinarySettingsCoordinator` has loaded an authenticated snapshot. `ProtectedDataSessionCoordinator` owns app-data root-secret retrieval, wrapping-root-key lifetime, relock fan-out, and runtime-only `restartRequired`.

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
| `gracePeriod` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 7 | Implemented in PR 2 | implemented |
| `hasCompletedOnboarding` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 7 | Implemented in PR 2 | implemented |
| `colorTheme` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 7 | Implemented in PR 2 | implemented |
| `requireAuthOnLaunch` | Retired legacy `UserDefaults` key | `legacy cleanup-only` | Legacy cleanup | Cleanup-only | cleanup only |
| `encryptToSelf` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 7 | Implemented in PR 2 | implemented |
| `clipboardNotice` | `ProtectedData/protected-settings`; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 3 | Implemented | implemented |
| `guidedTutorialCompletedVersion` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | Phase 7 | Implemented in PR 2 | implemented |
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
| Self-test reports / legacy `Documents/self-test/` | In-memory export-only report data; legacy app sandbox `Documents/self-test/` cleanup source only | `ephemeral-with-cleanup` / `legacy cleanup-only` | Phase 7 PR 3 | Implemented | implemented |
| `tmp/decrypted/` | App temporary directory `tmp/decrypted/op-<UUID>/<sanitized output filename>` | `ephemeral-with-cleanup` | Phase 7 PR 4 | Implemented | implemented |
| `tmp/streaming/` | App temporary directory `tmp/streaming/op-<UUID>/<sanitized input filename>.gpg` | `ephemeral-with-cleanup` | Phase 7 PR 4 | Implemented | implemented |
| `tmp/export-*` | App temporary directory `tmp/export-<UUID>-<sanitized filename>` | `ephemeral-with-cleanup` | Phase 7 PR 4 | Implemented | implemented |
| `tmp/CypherAirGuidedTutorial-*` | App temporary directory `tmp/CypherAirGuidedTutorial-<UUID>/` | `ephemeral-with-cleanup` | Phase 7 PR 4 | Implemented | implemented |
| Tutorial `UserDefaults` suite | App Preferences plist/domain `com.cypherair.tutorial.sandbox`, plus legacy orphan cleanup for `com.cypherair.tutorial.<UUID>.plist` | `ephemeral-with-cleanup` | Phase 7 PR 4 | Implemented | implemented |
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

For Phase 7 settings, no shadow copy may be introduced to preserve pre-unlock behavior. If a setting still controls launch authentication, startup routing, or pre-unlock UI before ProtectedData opens, the implementation must first redesign that read path or keep the setting as an explicit boot exception. The only ordinary-settings boot-auth exception is `appSessionAuthenticationPolicy`; PR 1 ordinary settings must remain unavailable until the coordinator loads after app authentication.

For Phase 8 Contacts, legacy plaintext sources must remain inactive after cutover, must not be treated as a fallback source of truth, and must be deleted only after a later successful Contacts domain open confirms the protected destination is readable.
