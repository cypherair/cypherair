# Persisted State Inventory

> Status: Canonical current-state.
> Purpose: Maintain the row-level classification and migration status for CypherAir-owned persisted and local state.
> Audience: Human developers, security reviewers, QA, and AI coding tools.
> Source of truth: Current code, with `ARCHITECTURE.md`, `SECURITY.md`, `TDD.md`, and `TESTING.md` as companion current-state documents. This file owns the exhaustive row-level inventory.
> Update triggers: Any ProtectedData domain migration, storage/defaults/temp-path change, persistent-state classification change, Contacts protected-domain gate change, or storage/relock/recovery behavior change.

## 1. Scope

The long-term goal is to protect every CypherAir-owned local data surface unless a documented technical or security reason keeps it outside a protected domain.

This inventory tracks current shipped state plus pending classified surfaces. It is not a roadmap narrative. Archived Contacts-specific documents are historical source material only; current persisted-state classification lives here.

Every in-scope row must carry:

- a target class
- a domain or explicit exception
- a current status
- migration-readiness detail

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
| `encryptToSelf` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `clipboardNotice` | `ProtectedData/protected-settings` | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `guidedTutorialCompletedVersion` | `ProtectedData/protected-settings` schema v2 | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| `uiTestBypassAuthentication` | Test-only `UserDefaults` key | `test-only exception` | Test-only exception | Exception retained | n/a |
| `rewrapInProgress` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `rewrapTargetMode` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryInProgress` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| `modifyExpiryFingerprint` | `ProtectedData/private-key-control` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Permanent SE-wrapped private-key envelope row | Keychain default account service `com.cypherair.v1.privkey-envelope.<fingerprint>`; one self-contained `CAPKEV1` envelope per software-custody key (ephemeral-static ECDH against the per-key Secure Enclave public key, HKDF/AAD-bound, with the SE key `dataRepresentation` folded in). Reset All Local Data deletes it by `com.cypherair.v1.` prefix sweep. | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Pending SE-wrapped private-key envelope row | Keychain default account service `com.cypherair.v1.pending-privkey-envelope.<fingerprint>`; transient single-row envelope written during mode-switch re-wrap and modify-expiry, promoted or cleaned by the interrupted-rewrap recovery coordinators. Reset deletes it by the same prefix sweep. | `private-key-material exception` | Private-key-material exception | Exception retained | n/a |
| Secure Enclave custody private-key blob rows | Keychain `kSecClassGenericPassword` rows, service `com.cypherair.v1.secure-enclave-custody.<tier>.<role>` (tier segments `p256`, `post-quantum`, `post-quantum-high`) plus account `<random-handle-set-id>`; two rows per device-bound identity holding the CryptoKit Secure Enclave `dataRepresentation` blob (`kSecValueData`) — P-256 signing/key-agreement for the classical tier, ML-DSA-65 / ML-KEM-768 for Device-Bound Post-Quantum, ML-DSA-87 / ML-KEM-1024 for Device-Bound Post-Quantum · High — plus the role's public key (`kSecAttrGeneric`) for non-prompting locate and binding verification. Data-protection keychain, this-device-only, non-synchronizable; the blob is useless off-device. Handle-set ids are Security-private local locators, not stored in `key-metadata`, logs, UI, Rust, or exports. Reset All Local Data sweeps every tier/role namespace, including rows whose attributes no longer decode, and validates none remain using sanitized counts/categories only. Guarded device tests (`DeviceSecureEnclaveCustodyHandleStoreTests`, `DeviceSecureEnclaveCompositeCustodyTests`) validate real hardware create/load/locate/delete and private operations. | `private-key-material exception` | Secure Enclave custody handle store | Implemented production boundary with local reset cleanup and guarded device evidence; user-reachable on Secure Enclave hardware via device-bound key generation | implemented |
| Composite classical-component envelope row | Keychain default account service `com.cypherair.v1.privkey-envelope.<fingerprint>` (shared software-envelope namespace); one `CAPKEV1` envelope per Device-Bound Post-Quantum key sealing the concatenated classical component secrets — the 32-byte Ed25519 + 32-byte X25519 pair for the base tier, or the 57-byte Ed448 + 56-byte X448 pair for Device-Bound Post-Quantum · High — under a fixed-access (`privateKeyUsage`+`biometryAny`) Secure Enclave wrapping key. The fixed policy — never the mode-dependent app wrapping policy — keeps device-bound keys exempt from mode-switch re-wrap (the rewrap caller enumerates software-custody identities only). Reset and identity deletion remove it by the `com.cypherair.v1.` prefix sweep / fingerprint-keyed keychain-material path. | `private-key-material exception` | Composite split-custody classical component | Exception retained | n/a |
| `PGPKeyIdentity` metadata rows | `ProtectedData/key-metadata` schema v2 records with explicit OpenPGP configuration identity and private-key custody kind | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Shared app-data root-secret envelope row | Keychain default account service `com.cypherair.protected-data.shared-right.v1`; LA-gated binary-plist `CAPDSEV3` envelope containing the wrapped 32-byte ProtectedData root secret. It is a single self-contained row: the ProtectedData-only P-256 Secure Enclave device-binding key `dataRepresentation` is folded into the envelope (its hash bound into the HKDF `sharedInfo` and AES-GCM AAD), so one row reconstructs the handle and reopens the secret after the existing app-session Keychain authentication gate — there is no separate persisted device-binding key item. Reset All Local Data deletes the root-secret service directly and otherwise relies on the normal app-owned Keychain reset sweep; there is no ProtectedData device-binding-key special case. | `framework-bootstrap` | Shared app-data bootstrap | Implemented as a single self-contained SE-device-bound row | implemented |
| `ProtectedDataRegistry` | `Application Support/ProtectedData/ProtectedDataRegistry.plist` | `framework-bootstrap` | Framework registry bootstrap | Implemented | framework prerequisite |
| Per-domain bootstrap metadata | `Application Support/ProtectedData/<domain>/bootstrap.plist` | `framework-bootstrap` | Per-domain bootstrap | Written only by the `key-metadata` domain (expected current generation authority) and the `contacts` domain (presence + schema-version sentinel); other domains persist no bootstrap metadata | domain-specific |
| Per-domain wrapped domain master key records | Keychain default account services `com.cypherair.v1.protected-data.domain-key.<domainID>` for committed rows and `com.cypherair.v1.protected-data.domain-key.staged.<domainID>` for staged rows. Rows contain only the self-describing AES-256-GCM `CADMKV2` wrapped-DMK envelope (magic, algorithm ID, AAD version, strict field validation) under the wrapping root key; unwrapped DMKs remain memory-only and are cleared on relock. Missing registry plus any app-owned domain-key row enters framework recovery instead of bootstrapping empty state. | `framework-bootstrap` | Per-domain key custody | Implemented | domain-specific |
| Protected settings payload | `Application Support/ProtectedData/protected-settings/` | `protected-after-unlock` | `protected-settings` | Implemented | implemented |
| Private-key control payload | `Application Support/ProtectedData/private-key-control/` | `private-key-control target` | `private-key-control` | Implemented | implemented |
| Key metadata payload | `Application Support/ProtectedData/key-metadata/`; protected schema v2 `PGPKeyIdentity` metadata only. It records configuration/custody vocabulary, including device-bound P-256 Secure Enclave custody identities, and stores public certificate bytes plus the key-level revocation artifact for export. It does not store Apple handle locators, handle-set ids, access-control policy, salts, sealed boxes, secret certificate bytes, response-file bridge state, digests, signatures beyond the public revocation artifact, recovery reports, or other private material. Recovery derives expected Secure Enclave handles from stored public certificate bindings at load time and keeps the classification in memory only. | `key-metadata-domain target` | `key-metadata` | Implemented | implemented |
| Framework sentinel payload | `Application Support/ProtectedData/protected-framework-sentinel/` | `framework-bootstrap` | `protected-framework-sentinel` | Implemented | implemented |
| Contacts payload | `Application Support/ProtectedData/contacts/contacts.sqlite` plus SQLite/SQLCipher sidecars (`contacts.sqlite-wal`, `contacts.sqlite-shm`, `contacts.sqlite-journal`); protected SQLCipher schema v2 relational storage hydrated into `ContactsDomainSnapshot` with `ContactIdentity` records (display name, primary email, tag membership, notes, timestamps), `ContactKeyRecord` records (public certificate bytes, fingerprint/User ID/profile/algorithm metadata, manual verification, usage state, certification projection and artifact references), `ContactTag` records (display and normalized tag names), and `ContactCertificationArtifactReference` records (canonical signature bytes, digest, source, selector, signer metadata, validation status, target certificate digest, export filename). The database uses the `contacts` domain master key directly through SQLCipher raw-key syntax; missing database authority, wrong key, corrupt DB, application-id mismatch, unsupported `user_version`, or integrity failure routes to recovery. | `protected-after-unlock` | Contacts protected domain | Implemented | implemented |
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
- update this inventory and the companion canonical docs per the [WORKFLOW](WORKFLOW.md) documentation contract in the same change

The settings shadow-copy prohibition, Contacts legacy-inactive rule, and Contacts runtime-only-state rule are owned by [TDD](TDD.md) Section 6; this inventory's rows are the authoritative classification they apply to.
