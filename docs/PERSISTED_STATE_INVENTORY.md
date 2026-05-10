# Persisted State Inventory

> Status: Canonical current-state.
> Purpose: Maintain the row-level classification and migration status for CypherAir-owned persisted and local state.
> Audience: Human developers, security reviewers, QA, and AI coding tools.
> Source of truth: Current code, with `ARCHITECTURE.md`, `SECURITY.md`, `TDD.md`, and `TESTING.md` as companion current-state documents. This file owns the exhaustive row-level inventory.
> Last reviewed: 2026-05-10.
> Update triggers: Any ProtectedData domain migration, storage/defaults/temp-path change, persistent-state classification change, Contacts protected-domain gate change, or storage/relock/recovery behavior change.

## 1. Scope

The long-term goal is to protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.

This inventory tracks current shipped state plus pending classified surfaces. It is not a roadmap narrative. Archived Contacts-specific documents are historical source material only; current persisted-state classification lives here.

Every in-scope row must carry:

- a target class
- a domain or explicit exception
- a current status
- migration-readiness detail

`Migration readiness` answers whether the row can move now. `Current status` records whether it has actually moved. A row can be target-classified correctly while still being pending.

## 2. Target Classes

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

## 3. Inventory

| Item | Current location | Target class | Domain / exception | Current status | Migration readiness |
|------|------------------|--------------|--------------------------|----------------|---------------------|
| `appSessionAuthenticationPolicy` | `UserDefaults` | `early-readable boot exception` | Boot exception | Exception retained | n/a in v1 |
| `authMode` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `gracePeriod` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `hasCompletedOnboarding` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `colorTheme` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `requireAuthOnLaunch` | Retired legacy `UserDefaults` key | `legacy cleanup-only` | Legacy cleanup | Cleanup-only | cleanup only |
| `encryptToSelf` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `clipboardNotice` | `ProtectedData/protected-settings`; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `guidedTutorialCompletedVersion` | `ProtectedData/protected-settings` schema v2; legacy `UserDefaults` only as verified migration cleanup source | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `uiTestBypassAuthentication` | Test-only `UserDefaults` key | `test-only exception` | Test-only exception | Exception retained | n/a |
| `rewrapInProgress` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `rewrapTargetMode` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryInProgress` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryFingerprint` | `ProtectedData/private-key-control`; legacy `UserDefaults` only as migration source | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Permanent SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Pending SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| `PGPKeyIdentity` metadata rows | `ProtectedData/key-metadata`; legacy metadata-account and default-account rows only as migration sources | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Shared app-data root secret | Keychain default account | `framework-bootstrap` | Shared app-data bootstrap | Implemented with SE device binding | implemented |
| `ProtectedDataRegistry` | `Application Support/ProtectedData/ProtectedDataRegistry.plist` | `framework-bootstrap` | Framework registry bootstrap | Implemented | framework prerequisite |
| Per-domain bootstrap metadata | `Application Support/ProtectedData/<domain>/bootstrap.plist` | `framework-bootstrap` | Per-domain bootstrap | Implemented for existing domains | domain-specific |
| Protected settings payload | `Application Support/ProtectedData/protected-settings/` | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| Private-key control payload | `Application Support/ProtectedData/private-key-control/` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Key metadata payload | `Application Support/ProtectedData/key-metadata/` | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Framework sentinel payload | `Application Support/ProtectedData/protected-framework-sentinel/` | `framework-bootstrap` | `protected-framework-sentinel` | Implemented | implemented |
| Contacts payload | `Application Support/ProtectedData/contacts/`; protected `ContactsDomainSnapshot` with `ContactIdentity` records (display name, primary email, tag membership, notes, timestamps), `ContactKeyRecord` records (public certificate bytes, fingerprint/User ID/profile/algorithm metadata, manual verification, usage state, certification projection and artifact references), `ContactTag` records (display and normalized tag names), `RecipientList` records (named contact-ID member lists), and `ContactCertificationArtifactReference` records (canonical signature bytes, digest, source, selector, signer metadata, validation status, target certificate digest, export filename) | `protected-after-unlock` | Contacts protected domain | Implemented | implemented |
| Contacts runtime-only search/filter/selection state | In memory only: `ContactsSearchIndex`, screen search/filter values, tag filters, recipient selection, and pending route state | `ephemeral-with-cleanup` | Contacts runtime exception | Implemented; cleared with relock, content clear, or screen lifecycle as applicable | n/a, not persisted |
| Legacy contacts public-key files | `Documents/contacts/*.gpg` and `Documents/contacts.quarantine/*.gpg` | `legacy cleanup-only` | Contacts legacy cleanup-only | Cutover source and quarantine cleanup only; inactive after protected open; does not carry production Contacts state | cleanup only |
| Legacy contacts metadata | `Documents/contacts/contact-metadata.json` and quarantine copy | `legacy cleanup-only` | Contacts legacy cleanup-only | Cutover source and quarantine cleanup only; inactive after protected open; does not carry production Contacts state | cleanup only |
| Self-test reports / legacy `Documents/self-test/` | In-memory export-only report data; legacy app sandbox `Documents/self-test/` cleanup source only | `ephemeral-with-cleanup` / `legacy cleanup-only` | Self-test export-only exception | Implemented | implemented |
| `tmp/decrypted/` | App temporary directory `tmp/decrypted/op-<UUID>/<sanitized output filename>` | `ephemeral-with-cleanup` | Temporary decrypted artifact cleanup | Implemented | implemented |
| `tmp/streaming/` | App temporary directory `tmp/streaming/op-<UUID>/<sanitized input filename>.gpg` | `ephemeral-with-cleanup` | Temporary streaming artifact cleanup | Implemented | implemented |
| `tmp/export-*` | App temporary directory `tmp/export-<UUID>-<sanitized filename>`, including explicit certification-signature export handoff files before user-selected export/share leaves app custody | `ephemeral-with-cleanup` | Temporary export handoff / certification-signature explicit export boundary | Implemented | implemented |
| `tmp/CypherAirGuidedTutorial-*` | App temporary directory `tmp/CypherAirGuidedTutorial-<UUID>/` | `ephemeral-with-cleanup` | Tutorial sandbox artifact cleanup | Implemented | implemented |
| Tutorial `UserDefaults` suite | App Preferences plist/domain `com.cypherair.tutorial.sandbox`, plus legacy orphan cleanup for `com.cypherair.tutorial.<UUID>.plist` | `ephemeral-with-cleanup` | Tutorial defaults cleanup | Implemented | implemented |
| Files exported to user-selected locations | Outside app-controlled sandbox after export | `out-of-app-custody` | Out-of-app-custody exception | Exception retained | n/a |

## 4. Migration Rules

Every future migration from plaintext, Keychain metadata, or non-uniform local state into a protected domain must:

- preserve readable source state until the protected destination is confirmed valid
- validate and normalize source state before writing the protected destination
- verify protected-domain readability before retiring or quarantining source state
- never silently reset unreadable converted state to empty data
- make corrupted committed protected state a recovery surface
- document cleanup or quarantine behavior explicitly
- update this inventory, [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md), [TDD](TDD.md), [TESTING](TESTING.md), and [CODE_REVIEW](CODE_REVIEW.md) as needed in the same change
- for Contacts protected-domain behavior, storage, or mutation changes, update the long-term docs above and this inventory

For protected ordinary settings, no shadow copy may be introduced to preserve pre-unlock behavior. If a setting still controls launch authentication, startup routing, or pre-unlock UI before ProtectedData opens, the implementation must first redesign that read path or keep the setting as an explicit boot exception. The only ordinary-settings boot-auth exception is `appSessionAuthenticationPolicy`.

For Contacts protected-domain state, legacy plaintext sources must remain inactive after cutover, must not be treated as a fallback source of truth, and must be deleted only after a later successful Contacts domain open confirms the protected destination is readable.

For Contacts protected-domain state, this inventory is the authoritative persisted-state classification. Search indexes, screen filters, and recipient selections are runtime state only; they must not become a second persisted source of truth outside the protected `contacts` payload.
