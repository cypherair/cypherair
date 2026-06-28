# Contacts SQLCipher Storage Design

> Status: Draft implementation reference. This document is future-facing and
> does not describe current shipped behavior.
> Purpose: Define the design constraints, storage shape, lifecycle rules,
> failure semantics, validation gates, and PR boundaries for moving ProtectedData
> wrapped domain keys to Keychain and migrating Contacts persistence to
> device-bound SQLCipher under GitHub issue #540.
> Audience: CypherAir maintainers, security reviewers, QA, and agents planning
> or reviewing Contacts SQLCipher implementation work.
> Companions: [GitHub issue #540](https://github.com/cypherair/cypherair/issues/540),
> [SQLCipher XCFramework Dependency](SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md),
> [Security](SECURITY.md), [Architecture](ARCHITECTURE.md), [TDD](TDD.md),
> [Testing](TESTING.md), and [Code Review](CODE_REVIEW.md).
> Last reviewed: 2026-06-28.
> Update triggers: Contacts SQLCipher storage path, ProtectedData wrapped-DMK
> custody, Keychain record naming, schema versioning, SQLCipher configuration,
> post-unlock, relock, reset, recovery, self-ECDH cleanup, or PR slicing changes.

## 1. Scope And Current Status

GitHub issue #540 tracks two related storage/security changes:

- move generic ProtectedData wrapped domain master key records from
  file-backed `wrapped-dmk.plist` artifacts to Keychain rows
- migrate Contacts persistence from the current `ProtectedData/contacts`
  snapshot-envelope payload to SQLCipher-backed storage while preserving
  security properties no weaker than the current ProtectedData design

The issue also tracks the related cleanup to replace the remaining private-key
self-ECDH wrapping design with a standard Secure Enclave public-key ECDH
envelope pattern.

[PR #542](https://github.com/cypherair/cypherair/pull/542) and
[PR #544](https://github.com/cypherair/cypherair/pull/544) are already
dependency groundwork: the app consumes the pinned `SQLCipher.xcframework`,
validates the artifact, and records the formal external dependency. They do not
implement Keychain-backed ProtectedData wrapped-DMK storage, Contacts SQLCipher
storage, reset/relock business logic, or self-ECDH cleanup.

This document is not an issue copy and is not a canonical current-state
document. The issue remains the tracker for implementation progress. Canonical
current-state docs should be updated only by implementation PRs after behavior
actually changes.

No legacy Contacts or ProtectedData wrapped-DMK migration path is required
because CypherAir X has not had a formal App Store release. After the cutover,
old file-backed wrapped-DMK records and old `ProtectedData/contacts` snapshot
artifacts must not become fallback sources of truth.

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
  the C API with SQLCipher raw-key syntax, reject wrong keys, report
  `cipher_version`, and clean basic sidecar files.

Primary external references:

- [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/) for
  `sqlite3_key_v2`, raw-key syntax, PRAGMA keying, `PRAGMA cipher_version`, and
  `PRAGMA cipher_integrity_check`.
- Zetetic [technical guidance for random SQLCipher keys](https://www.zetetic.net/blog/2019/06/07/technical-guidance-using-random-values-as-sqlcipher-keys/)
  for using SQLCipher raw-key syntax instead of passing random bytes through
  the passphrase/KDF path.
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

## 3. Architecture Decision

Contacts SQLCipher is not a new ProtectedData domain and not a cache beside the
old snapshot payload. The `contacts` ProtectedData domain ID and registry
membership remain the app-owned Contacts identity. SQLCipher replaces the
domain's authoritative payload implementation.

The `contacts` domain master key is the SQLCipher database key. It is the same
32-byte CSPRNG domain key that ProtectedData already generates and wraps for a
domain; for Contacts SQLCipher it is handed to SQLCipher through raw-key syntax
instead of being used to seal a snapshot envelope. Do not create a separate
Contacts DB-key record or a second Contacts-specific key custody system.

The wrapped-DMK persistence change is global ProtectedData infrastructure:
committed and staged wrapped domain master key records move from files under
`Application Support/ProtectedData/<domain>/` to Keychain rows under
`KeychainConstants.prefix`. Existing registry membership, app-auth handoff,
relock, recovery, and reset semantics remain the lifecycle boundary.

Old file-backed wrapped-DMK records and old Contacts snapshot-envelope artifacts
are not migrated. A clean first run creates the protected domain key and the
SQLCipher database. A state that has old artifacts, a missing Keychain-backed
domain key, a missing database for a committed SQLCipher Contacts domain, or an
unreadable database enters fail-closed recovery/reset; it must not silently
create empty Contacts data.

## 4. Design Invariants

### App/Auth Boundary

Contacts SQLCipher storage must remain behind the existing app-authenticated
ProtectedData lifecycle. Normal unlock should create or reuse an authenticated
handoff, open ProtectedData, and preload Contacts without a second interactive
authentication prompt.

The domain-key unwrap path must not create an independent normal-flow Keychain
or LocalAuthentication domain. Keychain-backed wrapped-DMK rows must not add
their own `SecAccessControl` prompt. Normal access remains gated by the
ProtectedData root-secret load and the existing app-session authentication
handoff. A path that requires UI outside the explicit app-authentication
operation is a design failure unless a later human-reviewed plan explicitly
changes product behavior.

### ProtectedData Domain-Key Custody

ProtectedData domain master keys remain app-generated 32-byte random keys. They
must never be derived from user passphrases and must not be stored raw.

Persist only versioned wrapped domain master key records. The Keychain service
names are:

```text
com.cypherair.v1.protected-data.domain-key.<domainID>
com.cypherair.v1.protected-data.domain-key.staged.<domainID>
```

with `KeychainConstants.defaultAccount`. The service names must stay under
`KeychainConstants.prefix` so Reset All Local Data can inventory, delete, and
post-condition-check them.

This is a storage-location change for the ProtectedData wrapped-DMK primitive,
not a new Contacts crypto envelope. The wrapped record should keep the existing
ProtectedData root-secret / Secure Enclave device-binding authority and
domain-bound AAD contract unless a later security review explicitly revises the
generic ProtectedData wrapping format. It must not reuse or reinterpret
private-key bundle rows.

Writes must preserve the current staged/committed semantics: write and validate
the staged Keychain row before committing registry membership or replacing the
committed row, treat duplicate/stale staged rows as recovery inputs, and delete
staged rows on successful promotion or reset.

### Raw Key Lifetime

For Contacts SQLCipher, the raw `contacts` domain master key may exist only long
enough to key and validate a SQLCipher connection. Production code must build a
short-lived byte buffer using SQLCipher raw-key syntax:

```text
x'<64 hex characters>'
```

and pass those bytes to `sqlite3_key_v2(db, "main", keySpec, keySpecLength)`,
where key-only raw syntax is 67 bytes. Do not pass the 32 binary key bytes
directly to `sqlite3_key`/`sqlite3_key_v2`; SQLCipher treats that as passphrase
input and runs the KDF path.

After keying, the SQLCipher connection is itself sensitive runtime state because
SQLCipher retains key material internally until close. The connection owner must
therefore participate in relock and reset, finalize statements, close handles,
and clear any cached runtime projections.

The raw key and transient raw-key syntax buffer must be zeroized immediately
after keying and validation. They must not be represented as a Swift `String`,
PRAGMA SQL statement, log field, trace value, UI value, export value, or
persisted app model.

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

The DB and sidecars must use explicit complete file protection where the platform
supports it. Reset All Local Data must close the SQLCipher connection before
removing files, then delete the DB, sidecars, staged and committed
Keychain-backed domain-key rows, and obsolete `ProtectedData/contacts` snapshot
artifacts.

### SQLCipher Configuration And Validation

The implementation should keep SQLCipher configuration small and test-proven.
At minimum, open validation must prove:

- SQLCipher is the active library, using `PRAGMA cipher_version`.
- The raw-key syntax buffer is applied before schema reads, metadata reads, or
  other database access.
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

- missing Keychain-backed wrapped domain master key when the DB exists
- corrupt or undecodable wrapped domain master key
- Secure Enclave device-binding mismatch or unavailable unwrap authority
- wrong SQLCipher key
- missing DB when the committed `contacts` domain and domain key indicate a DB
  should exist
- downgraded or unsupported schema
- SQLCipher config mismatch
- `cipher_integrity_check` or equivalent integrity failure
- stale file-backed wrapped-DMK or old `ProtectedData/contacts` snapshot state
  with no SQLCipher authority
- partial create/cutover artifacts

None of these cases may silently reset Contacts to empty data. None may read old
ProtectedData Contacts state as a fallback source of truth.

### Contacts Behavior Surface

`ContactService` remains the app/UI-facing facade. The implementation should add
a Contacts persistence boundary beneath it rather than moving SQL awareness into
views, screen models, encryption/decryption services, or certification flows.

The first cutover should keep current behavior stable by hydrating an in-memory
`ContactsDomainSnapshot`-compatible DTO for `ContactSnapshotMutator`,
`ContactsSearchIndex`, and existing projection code. SQLCipher is the only
persisted authoritative payload and can persist relational tables for:

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
golden behavior tests prove exact parity. Do not persist a transitional snapshot
blob as a parallel source of truth.

### Data Exclusion Rules

Contacts SQLCipher storage must not contain private-key material or
Security-private local locators. Excluded data includes:

- OpenPGP secret certificate bytes
- raw domain master keys or SQLCipher keys
- ProtectedData root secret or wrapping root key
- Secure Enclave handle locators or handle-set identifiers
- access-control policy values
- salts and sealed private-key blobs
- response-file bridge state
- authentication contexts or prompt state

Contacts may store public certificates, contact identity fields, tags,
verification state, and certification artifacts that already belong to the
Contacts domain.

## 5. PR Roadmap

### PR 1: Documentation And Raw-Key Preflight Alignment

Add this implementation reference and, at most, a neutral cross-link from
[SQLCipher XCFramework Dependency](SQLCIPHER_XCFRAMEWORK_DEPENDENCY.md). Do not
change canonical current-state docs to say Contacts has migrated.

Align runtime and artifact SQLCipher preflight probes with raw-key syntax so the
project does not keep direct 32-byte `sqlite3_key` examples that would exercise
SQLCipher's passphrase/KDF path.

Validation:

- `git diff --check`
- markdown link audit, if available
- `python3 scripts/check_text_hygiene.py`, if available
- `python3 -m unittest discover scripts/tests`
- focused SQLCipher preflight XCTest, where available
- targeted `rg` checks that active canonical docs do not claim SQLCipher
  Contacts is shipped

### PR 2: Keychain-Backed ProtectedData Domain Keys

Move generic ProtectedData wrapped-DMK persistence to Keychain without cutting
over `ContactService` to SQLCipher.

Owned behavior:

- staged and committed Keychain service/account ownership for wrapped domain
  master key records
- reuse of the existing ProtectedData wrapping primitive and domain-bound AAD
- no independent Keychain access-control prompt for wrapped-DMK rows
- staged write, validation, promotion, stale-staged cleanup, and reset cleanup
- registry recovery behavior when a committed domain has a missing/corrupt
  Keychain-backed wrapped-DMK row
- no migration or fallback from old file-backed wrapped-DMK records

Do not implement user-visible Contacts behavior changes or SQLCipher Contacts
cutover in this PR.

Validation:

- `python3 -m unittest discover scripts/tests`
- focused ProtectedData domain-key XCTest
- reset deletion and postcondition tests for new Keychain rows
- no-second-prompt tests through the existing app-auth handoff
- generic iOS, macOS arm64e, and visionOS builds where available
- focused macOS arm64e tests where available

### PR 3: Contacts Cutover

Swap the `contacts` ProtectedData domain payload from snapshot envelopes to
SQLCipher behind the stable `ContactService` facade.

Owned behavior:

- SQLCipher-backed Contacts store under `Application Support/ProtectedData/contacts/`
- `contacts` domain ID and registry membership retained
- direct use of the `contacts` domain master key through SQLCipher raw-key
  syntax
- in-memory snapshot-compatible load/save boundary for current mutator and
  search behavior
- no legacy `ProtectedData/contacts` snapshot fallback and no parallel persisted
  snapshot source of truth
- post-unlock preload through existing handoff
- relock cleanup of runtime snapshot, search index, statements, and connection
- Reset All Local Data cleanup and postcondition checks
- fail-closed recovery for DB/key/schema/config/integrity errors
- canonical current-state doc updates

Validation:

- full Contacts service/model test coverage affected by the cutover
- new SQLCipher recovery/reset/relock/no-fallback tests
- raw-key keyspec zeroization tests where practical
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
- persist the public envelope inputs needed to reseal/open consistently, matching
  the root-secret envelope pattern's explicit public-parameter binding
- add new envelope/version/service names so old rows cannot be silently misread
- preserve private-key material red lines, zeroization, and fail-closed recovery
- update canonical docs and tests for the private-key security model

Validation:

- positive and negative envelope tests
- tamper and wrong-binding tests
- guarded Secure Enclave device evidence where required
- reset cleanup checks if Keychain rows or service names change

## 6. Open Decisions For Implementation PRs

The documentation PR should not overfit these details. The implementation PRs
must decide and justify them with tests:

- exact schema table layout and indexes
- final PRAGMA set beyond the minimum validation contract above
- integrity-check cadence after open
- whether recovery UI needs any Contacts-specific copy beyond existing recovery
  states
- whether relock/reset/recovery hardening should stay inside PR 2 and PR 3 or
  split into an additional PR if review size grows

## 7. Review Red Lines

Stop and return to design review if a future implementation:

- introduces a normal-flow second authentication prompt
- adds a separate Contacts DB-key custody record instead of using the `contacts`
  domain master key
- stores raw domain master keys or SQLCipher keys, or converts raw key material
  to Swift `String` / PRAGMA SQL
- leaves a SQLCipher connection open across relock or reset
- silently creates an empty Contacts DB after corruption or key mismatch
- reads old file-backed wrapped-DMK records as a migration or fallback source
- falls back to old ProtectedData Contacts snapshots
- moves SQL details into UI or unrelated app services
- stores private-key material, Secure Enclave handle locators, salts, sealed
  private-key blobs, or access-control policy in Contacts
- changes the SQLCipher dependency pin or release model as part of Contacts
  cutover without a separate dependency plan
- combines the Contacts cutover and self-ECDH cleanup into one large security PR
  without explicit human approval
