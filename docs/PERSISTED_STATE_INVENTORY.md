# Persisted State Inventory

> Status: Canonical current-state.
> Purpose: Maintain the row-level classification and migration status for CypherAir-owned persisted and local state.
> Audience: Human developers, security reviewers, QA, and AI coding tools.
> Source of truth: Current code, with `ARCHITECTURE.md`, `SECURITY.md`, `TDD.md`, and `TESTING.md` as companion current-state documents. This file owns the exhaustive row-level inventory.
> Last reviewed: 2026-06-28.
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
- `unsupported legacy` (outside supported app state: not read, migrated, quarantined, reset-cleaned, or proactively deleted)
- `test-only exception`

## 3. Inventory

| Item | Current location | Target class | Domain / exception | Current status | Migration readiness |
|------|------------------|--------------|--------------------------|----------------|---------------------|
| `appSessionAuthenticationPolicy` | `UserDefaults` | `early-readable boot exception` | Boot exception | Exception retained | n/a in v1 |
| `authMode` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `gracePeriod` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `hasCompletedOnboarding` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `colorTheme` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `encryptToSelf` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `clipboardNotice` | `ProtectedData/protected-settings` | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `guidedTutorialCompletedVersion` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `uiTestBypassAuthentication` | Test-only `UserDefaults` key | `test-only exception` | Test-only exception | Exception retained | n/a |
| `rewrapInProgress` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `rewrapTargetMode` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryInProgress` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryFingerprint` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Permanent SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Pending SE-wrapped private-key bundle rows | Keychain default account | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Secure Enclave custody private-operation key rows | Keychain `kSecClassKey` rows tagged `com.cypherair.v1.secure-enclave-custody.<random-id>.<role>`; two distinct P-256 Secure Enclave private keys for signing and key agreement. Tags are Security-private local locators and are not stored in `key-metadata`, logs, UI, Rust, or exports. Reset All Local Data inventories and deletes app-owned custody rows, including malformed app-owned tags, and validates no remaining custody handles using sanitized counts/categories only. Guarded device tests validate real hardware creation/load/delete, biometric private-operation access, handle-state failure, and cleanup behavior. | `private-key-material exception` | Secure Enclave custody handle store (production boundary since P7D) | Implemented production boundary with local reset cleanup and guarded device evidence; user-reachable on Secure Enclave hardware via device-bound key generation (issue #501 Phase 7D; release gate satisfied Phase 9) | implemented |
| `PGPKeyIdentity` metadata rows | `ProtectedData/key-metadata` schema v2 records with explicit OpenPGP configuration identity and private-key custody kind | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Shared app-data root secret | Keychain default account | `framework-bootstrap` | Shared app-data bootstrap | Implemented with SE device binding | implemented |
| `ProtectedDataRegistry` | `Application Support/ProtectedData/ProtectedDataRegistry.plist` | `framework-bootstrap` | Framework registry bootstrap | Implemented | framework prerequisite |
| Per-domain bootstrap metadata | `Application Support/ProtectedData/<domain>/bootstrap.plist` | `framework-bootstrap` | Per-domain bootstrap | Implemented for existing domains | domain-specific |
| Per-domain wrapped domain master key records | Keychain default account services `com.cypherair.v1.protected-data.domain-key.<domainID>` for committed rows and `com.cypherair.v1.protected-data.domain-key.staged.<domainID>` for staged rows. Rows contain only the AES-GCM wrapped DMK record under the wrapping root key; unwrapped DMKs remain memory-only and are cleared on relock. Missing registry plus any app-owned domain-key row enters framework recovery instead of bootstrapping empty state. | `framework-bootstrap` | Per-domain key custody | Implemented | domain-specific |
| Protected settings payload | `Application Support/ProtectedData/protected-settings/` | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| Private-key control payload | `Application Support/ProtectedData/private-key-control/` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Key metadata payload | `Application Support/ProtectedData/key-metadata/`; protected schema v2 `PGPKeyIdentity` metadata only. It records configuration/custody vocabulary, including device-bound P-256 Secure Enclave custody identities, and stores public certificate bytes plus the key-level revocation artifact for export. It does not store Apple handle locators, handle-set ids, access-control policy, salts, sealed boxes, secret certificate bytes, response-file bridge state, digests, signatures beyond the public revocation artifact, recovery reports, or other private material. Recovery derives expected Secure Enclave handles from stored public certificate bindings at load time and keeps the classification in memory only. | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Framework sentinel payload | `Application Support/ProtectedData/protected-framework-sentinel/` | `framework-bootstrap` | `protected-framework-sentinel` | Implemented | implemented |
| Contacts payload | `Application Support/ProtectedData/contacts/contacts.sqlite` plus SQLite/SQLCipher sidecars (`contacts.sqlite-wal`, `contacts.sqlite-shm`, `contacts.sqlite-journal`); protected SQLCipher schema v2 relational storage hydrated into `ContactsDomainSnapshot` with `ContactIdentity` records (display name, primary email, tag membership, notes, timestamps), `ContactKeyRecord` records (public certificate bytes, fingerprint/User ID/profile/algorithm metadata, manual verification, usage state, certification projection and artifact references), `ContactTag` records (display and normalized tag names), and `ContactCertificationArtifactReference` records (canonical signature bytes, digest, source, selector, signer metadata, validation status, target certificate digest, export filename). The database uses the `contacts` domain master key directly through SQLCipher raw-key syntax; missing database authority, wrong key, corrupt DB, application-id mismatch, unsupported `user_version`, or integrity failure routes to recovery. | `protected-after-unlock` | Contacts protected domain | Implemented | implemented |
| Obsolete Contacts snapshot-envelope artifacts | `Application Support/ProtectedData/contacts/current.plist`, `previous.plist`, `pending.plist`, and old file-backed `wrapped-dmk` artifacts | `unsupported legacy` | Contacts ProtectedData cutover cleanup | Not read, migrated, or used as fallback; recovery/reset cleanup deletes these artifacts when cleaning the Contacts domain | unsupported |
| Contacts runtime-only search/filter/selection state | In memory only: `ContactsSearchIndex`, screen search/filter values, tag filters, recipient selection, and pending route state | `ephemeral-with-cleanup` | Contacts runtime exception | Implemented; cleared with relock, content clear, or screen lifecycle as applicable | n/a, not persisted |
| Unsupported legacy contacts public-key files | `Documents/contacts/*.gpg` and historical `Documents/contacts.quarantine/*.gpg` | `unsupported legacy` | Contacts support cutoff | Not read, migrated, quarantined, reset-cleaned, or proactively deleted; existing files may remain on disk but are no longer treated as CypherAir app state | unsupported |
| Unsupported legacy contacts metadata | `Documents/contacts/contact-metadata.json` and historical quarantine copy | `unsupported legacy` | Contacts support cutoff | Not read, migrated, quarantined, reset-cleaned, or proactively deleted; existing files may remain on disk but are no longer treated as CypherAir app state | unsupported |
| Self-test reports | In-memory export-only report data | `ephemeral-with-cleanup` | Self-test export-only exception | Implemented | implemented |
| `tmp/decrypted/` | App temporary directory `tmp/decrypted/op-<UUID>/<sanitized output filename>` | `ephemeral-with-cleanup` | Temporary decrypted artifact cleanup | Implemented | implemented |
| `tmp/streaming/` | App temporary directory `tmp/streaming/op-<UUID>/<sanitized input filename>.gpg` | `ephemeral-with-cleanup` | Temporary streaming artifact cleanup | Implemented | implemented |
| `tmp/export-*` | App temporary directory `tmp/export-<UUID>-<sanitized filename>`, including explicit certification-signature export handoff files before user-selected export/share leaves app custody | `ephemeral-with-cleanup` | Temporary export handoff / certification-signature explicit export boundary | Implemented | implemented |
| `tmp/CypherAirGuidedTutorial-*` | App temporary directory `tmp/CypherAirGuidedTutorial-<UUID>/` | `ephemeral-with-cleanup` | Tutorial sandbox artifact cleanup | Implemented | implemented |
| Tutorial `UserDefaults` suite | App Preferences plist/domain `com.cypherair.tutorial.sandbox` | `ephemeral-with-cleanup` | Tutorial defaults cleanup | Implemented | implemented |
| Files exported to user-selected locations | Outside app-controlled sandbox after export | `out-of-app-custody` | Out-of-app-custody exception | Exception retained | n/a |

## 4. Migration Rules

Every future migration from plaintext, Keychain metadata, or non-uniform local state into a protected domain must:

- preserve readable source state until the protected destination is confirmed valid
- validate and normalize source state before writing the protected destination
- verify protected-domain readability before retiring or quarantining source state
- never silently reset unreadable converted state to empty data
- make corrupted committed protected state a recovery surface
- document cleanup or quarantine behavior explicitly
- update this inventory and the companion canonical docs per [DOCUMENTATION_GOVERNANCE](DOCUMENTATION_GOVERNANCE.md) Section 6 in the same change

For protected ordinary settings, no shadow copy may be introduced to preserve pre-unlock behavior. If a setting still controls launch authentication, startup routing, or pre-unlock UI before ProtectedData opens, the implementation must first redesign that read path or keep the setting as an explicit boot exception. The only ordinary-settings boot-auth exception is `appSessionAuthenticationPolicy`.

For Contacts protected-domain state, legacy plaintext sources must remain inactive after cutover and must not be treated as a fallback source of truth. Current production code does not read, migrate, quarantine, reset-clean, or proactively delete unsupported legacy Contacts files.

For Contacts protected-domain state, this inventory is the authoritative persisted-state classification. SQLCipher `contacts.sqlite` is the only production Contacts payload authority; legacy snapshot-envelope artifacts must not be read as fallback. Search indexes, screen filters, and recipient selections are runtime state only; they must not become a second persisted source of truth outside the protected `contacts` payload.
