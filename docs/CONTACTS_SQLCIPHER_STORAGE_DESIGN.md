# Contacts SQLCipher Storage Design

> Status: Draft implementation reference. This document is future-facing and
> does not describe current shipped behavior.
> Purpose: Define the design constraints, storage shape, lifecycle rules,
> failure semantics, validation gates, and PR boundaries for migrating Contacts
> persistence to device-bound SQLCipher under GitHub issue #540.
> Audience: CypherAir maintainers, security reviewers, QA, and agents planning
> or reviewing Contacts SQLCipher implementation work.
> Companions: [GitHub issue #540](https://github.com/cypherair/cypherair/issues/540),
> [SQLCipher XCFramework Dependency](SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
> [Security](SECURITY.md), [Architecture](ARCHITECTURE.md), [TDD](TDD.md),
> [Testing](TESTING.md), and [Code Review](CODE_REVIEW.md).
> Last reviewed: 2026-06-28.
> Update triggers: Contacts SQLCipher storage path, DB-key custody, Keychain
> record naming, schema versioning, SQLCipher configuration, post-unlock,
> relock, reset, recovery, self-ECDH cleanup, or PR slicing changes.

## 1. Scope And Current Status

GitHub issue #540 tracks migrating Contacts persistence from the current
`ProtectedData/contacts` snapshot domain to SQLCipher-backed storage while
preserving security properties no weaker than the current ProtectedData design.
The issue also tracks the related cleanup to replace the remaining private-key
self-ECDH wrapping design with a standard Secure Enclave public-key ECDH
envelope pattern.

[PR #542](https://github.com/cypherair/cypherair/pull/542) and
[PR #544](https://github.com/cypherair/cypherair/pull/544) are already
dependency groundwork: the app consumes the pinned `SQLCipher.xcframework`,
validates the artifact, and records the formal external dependency. They do not
implement Contacts SQLCipher storage, DB-key wrapping, reset/relock business
logic, or self-ECDH cleanup.

This document is not an issue copy and is not a canonical current-state
document. The issue remains the tracker for implementation progress. Canonical
current-state docs should be updated only by implementation PRs after behavior
actually changes.

No legacy Contacts migration path is required because CypherAir X has not had a
formal App Store release. After the cutover, old `ProtectedData/contacts`
snapshot artifacts must not become a fallback source of truth.

## 2. Evidence Base

Repository sources that constrain this design:

- [SQLCipher XCFramework Dependency](SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md)
  defines the pinned external binary dependency, restore, validation, slice, and
  compliance contract.
- [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md) owns row-level
  persisted-state classification and currently records Contacts as a protected
  `ContactsDomainSnapshot` payload under `Application Support/ProtectedData/contacts/`.
- [Security](SECURITY.md) and [TDD](TDD.md) define ProtectedData root-secret,
  Secure Enclave device-binding, relock, recovery, and self-ECDH constraints.
- `ContactService`, `ContactSnapshotMutator`, and `ContactsSearchIndex` are the
  behavior surface to preserve while the persistence layer changes underneath.
- `SQLCipherPreflightProbe` proves the current artifact can be opened through
  the C API, keyed with bytes, reject wrong keys, report `cipher_version`, and
  clean basic sidecar files.

Primary external references:

- [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/) for
  `sqlite3_key`, PRAGMA keying, `PRAGMA cipher_version`, and
  `PRAGMA cipher_integrity_check`.
- [SQLCipher Design](https://www.zetetic.net/sqlcipher/design/) for page-level
  encryption, per-page authentication, key derivation, and plaintext header
  considerations.
- [SQLite PRAGMA Documentation](https://sqlite.org/pragma.html) for
  `user_version`, `application_id`, `integrity_check`, `journal_mode`, and
  related database metadata semantics.
- Apple [`kSecUseAuthenticationContext`](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext)
  documentation, which states that a previously authenticated `LAContext` can
  satisfy later Keychain item access without asking again.
- Apple [Accessing Keychain Items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id),
  which describes Keychain and LocalAuthentication integration.
- Apple CryptoKit [`SecureEnclave.P256.KeyAgreement.PrivateKey`](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
  documentation, which supports the standard persistent Secure Enclave private
  key plus software ephemeral public-key ECDH envelope model.

## 3. Design Invariants

### App/Auth Boundary

Contacts SQLCipher storage must remain behind the existing app-authenticated
ProtectedData lifecycle. Normal unlock should create or reuse an authenticated
handoff, open ProtectedData, and preload Contacts without a second interactive
authentication prompt.

The DB-key unwrap path must not create an independent normal-flow Keychain or
LocalAuthentication domain. If a Keychain query needs authentication, it must use
the same post-unlock context and preserve the no-second-prompt contract. A path
that requires UI outside the explicit app-authentication operation is a design
failure unless a later human-reviewed plan explicitly changes product behavior.

### DB-Key Custody

The Contacts DB key should be an app-generated 32-byte random key. It must never
be derived from a user passphrase and must not be stored raw.

Persist only a versioned wrapped DB-key record. The recommended Keychain service
is:

```text
com.cypherair.v1.contacts.sqlcipher.db-key
```

with `KeychainConstants.defaultAccount`. The service name must stay under
`KeychainConstants.prefix` so Reset All Local Data can inventory and delete it.

The wrapper should bind to the existing ProtectedData root-secret / Secure
Enclave device-binding authority. It must be a new, explicit Contacts DB-key
record type with its own version, magic, AAD/domain binding, and validation
errors. It must not reuse or reinterpret private-key bundle rows.

### Raw Key Lifetime

The raw DB key may exist only long enough to key and validate a SQLCipher
connection. The implementation must pass bytes to `sqlite3_key` or the chosen
equivalent, then zeroize all Swift-owned copies immediately.

After keying, the SQLCipher connection is itself sensitive runtime state because
SQLCipher retains key material internally until close. The connection owner must
therefore participate in relock and reset, finalize statements, close handles,
and clear any cached runtime projections.

The raw key must not be represented as a `String`, hex passphrase, log field,
trace value, UI value, export value, or persisted app model.

### Storage Location And Files

The recommended database location is:

```text
Application Support/ProtectedData/contacts/contacts.sqlite
```

This keeps Contacts under the existing protected app-data storage root and
preserves the reset/recovery ownership boundary. The implementation must also
account for SQLCipher/SQLite sidecars:

- `contacts.sqlite-wal`
- `contacts.sqlite-shm`
- `contacts.sqlite-journal`
- temporary files created by SQLite or SQLCipher near the database

Reset All Local Data must delete the DB, sidecars, wrapped DB-key record, and
obsolete `ProtectedData/contacts` snapshot artifacts.

### SQLCipher Configuration And Validation

The implementation should keep SQLCipher configuration small and test-proven.
At minimum, open validation must prove:

- SQLCipher is the active library, using `PRAGMA cipher_version`.
- The key is applied before schema reads, metadata reads, or other database
  access.
- The database rejects the wrong key through an actual read after keying.
- The expected schema version and application identity match.
- Integrity checks fail closed when they report corruption.
- Required compile-time assumptions from the dependency contract remain valid,
  including `SQLITE_HAS_CODEC` and `SQLITE_TEMP_STORE=2`.

Use `user_version` for schema versioning and consider `application_id` for an
additional database identity check. Any future PRAGMA choices beyond that must
be justified by tests and by SQLCipher/SQLite documentation.

Do not enable plaintext headers unless a later security review explicitly
accepts the tradeoff. Do not add FTS or new tokenization behavior in the first
cutover; current search ranking is app-derived behavior.

### Fail-Closed Recovery

These states must enter Contacts recovery or an equivalent fail-closed state:

- missing wrapped DB-key record when the DB exists
- corrupt or undecodable wrapped DB-key record
- Secure Enclave device-binding mismatch or unavailable unwrap authority
- wrong DB key
- missing DB when a committed wrapped key indicates a DB should exist
- downgraded or unsupported schema
- SQLCipher config mismatch
- `cipher_integrity_check` or equivalent integrity failure
- stale old `ProtectedData/contacts` snapshot state with no SQLCipher authority
- partial create/cutover artifacts

None of these cases may silently reset Contacts to empty data. None may read old
ProtectedData Contacts state as a fallback source of truth.

### Contacts Behavior Surface

`ContactService` remains the app/UI-facing facade. The implementation should add
a Contacts persistence boundary beneath it rather than moving SQL awareness into
views, screen models, encryption/decryption services, or certification flows.

The first cutover should keep current behavior stable by hydrating a
`ContactsDomainSnapshot`-compatible DTO for `ContactSnapshotMutator`,
`ContactsSearchIndex`, and existing projection code. SQLCipher can persist
relational tables for:

- contact identities
- contact key records
- tags
- tag memberships
- certification projections
- certification artifact references

The cutover must preserve:

- contact import/update/candidate outcomes
- merge behavior
- preferred/additional/historical key usage
- manual verification state
- tag normalization and membership
- current search/filter ranking
- recipient selection expectations
- certification projection and artifact persistence
- verification context used by encryption, signing, decryption,
  password-message, and certificate-signature flows

Do not move search to SQL/FTS in the first cutover unless a separate plan and
golden behavior tests prove exact parity.

### Data Exclusion Rules

Contacts SQLCipher storage must not contain private-key material or
Security-private local locators. Excluded data includes:

- OpenPGP secret certificate bytes
- raw DB keys
- ProtectedData root secret or wrapping root key
- Secure Enclave handle locators or handle-set identifiers
- access-control policy values
- salts and sealed private-key blobs
- response-file bridge state
- authentication contexts or prompt state

Contacts may store public certificates, contact identity fields, tags,
verification state, and certification artifacts that already belong to the
Contacts domain.

## 4. PR Roadmap

### PR 1: Documentation

Add this implementation reference and, at most, a neutral cross-link from
[SQLCipher XCFramework Dependency](SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md). Do not
change canonical current-state docs to say Contacts has migrated.

Validation:

- `git diff --check`
- markdown link audit, if available
- `python3 scripts/check_text_hygiene.py`, if available
- targeted `rg` checks that active canonical docs do not claim SQLCipher
  Contacts is shipped

### PR 2: SQLCipher/DB-Key Foundation

Implement the low-level foundation without cutting over `ContactService`.

Owned behavior:

- DB-key generation and versioned wrapped record
- Keychain service/account ownership
- SQLCipher connection owner
- open, key, schema/config/integrity validation
- statement finalization and connection close
- raw key zeroization
- DB/sidecar cleanup helpers
- focused tests for wrong key, corrupt key, missing DB/key mismatch,
  unsupported schema, and reset cleanup

Do not implement user-visible Contacts behavior changes in this PR.

Validation:

- `scripts/restore_sqlcipher_xcframework.sh --require-attestation`
- `python3 scripts/validate_sqlcipher_xcframework.py --root .`
- `python3 -m unittest discover scripts/tests`
- focused SQLCipher/DB-key XCTest
- generic iOS and visionOS builds
- focused macOS arm64e tests where available

### PR 3: Contacts Cutover

Swap Contacts persistence behind the stable `ContactService` facade.

Owned behavior:

- SQLCipher-backed Contacts store under `Application Support/ProtectedData/contacts/`
- snapshot-compatible load/save boundary for current mutator and search behavior
- no legacy `ProtectedData/contacts` fallback
- post-unlock preload through existing handoff
- relock cleanup of runtime snapshot, search index, statements, and connection
- Reset All Local Data cleanup and postcondition checks
- fail-closed recovery for DB/key/schema/config/integrity errors
- canonical current-state doc updates

Validation:

- full Contacts service/model test coverage affected by the cutover
- new SQLCipher recovery/reset/relock/no-fallback tests
- existing encryption/signing/decryption/password-message/certificate-signature
  verification-context tests affected by Contacts availability
- update [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
  [Security](SECURITY.md), [Architecture](ARCHITECTURE.md), [TDD](TDD.md),
  [Testing](TESTING.md), and [Code Review](CODE_REVIEW.md)

### PR 4: self-ECDH Cleanup

Handle private-key self-ECDH cleanup as a linked but separate security phase.

Owned behavior:

- replace the remaining private-key self-ECDH wrapping with a standard envelope
  using a software ephemeral P-256 private key and the persistent Secure Enclave
  public key
- add new envelope/version/service names so old rows cannot be silently misread
- preserve private-key material red lines, zeroization, and fail-closed recovery
- update canonical docs and tests for the private-key security model

Validation:

- positive and negative envelope tests
- tamper and wrong-binding tests
- guarded Secure Enclave device evidence where required
- reset cleanup checks if Keychain rows or service names change

## 5. Open Decisions For Implementation PRs

The documentation PR should not overfit these details. The implementation PRs
must decide and justify them with tests:

- exact schema table layout and indexes
- whether the SQLCipher store keeps a transitional snapshot blob during cutover
- final PRAGMA set beyond the minimum validation contract above
- integrity-check cadence after open
- whether recovery UI needs any Contacts-specific copy beyond existing recovery
  states
- whether relock/reset/recovery hardening should stay inside PR 2 and PR 3 or
  split into an additional PR if review size grows

## 6. Review Red Lines

Stop and return to design review if a future implementation:

- introduces a normal-flow second authentication prompt
- stores raw DB keys or converts them to strings
- leaves a SQLCipher connection open across relock or reset
- silently creates an empty Contacts DB after corruption or key mismatch
- falls back to old ProtectedData Contacts snapshots
- moves SQL details into UI or unrelated app services
- stores private-key material, Secure Enclave handle locators, salts, sealed
  private-key blobs, or access-control policy in Contacts
- changes the SQLCipher dependency pin or release model as part of Contacts
  cutover without a separate dependency plan
- combines the Contacts cutover and self-ECDH cleanup into one large security PR
  without explicit human approval
