# SQLCipher XCFramework Dependency

> Status: Formal pinned external binary dependency. Contacts storage uses the
> pinned SQLCipher artifact as its authoritative protected-domain payload.
> Purpose: Define CypherAir's consumer contract for the external SQLCipher
> XCFramework build repository and the restore/validation/release process.
> Audience: CypherAir maintainers, release owners, and agents working on
> Contacts persistence, Apple arm64e dependencies, or release compliance.
> Companion: GitHub issue #540, `cypherair/sqlcipher-xcframework`, and
> `third_party/sqlcipher-xcframework.pin.json`.
> Last reviewed: 2026-06-27.
> Update triggers: SQLCipher artifact repository identity, stable release tag,
> asset contract, pin schema, supported slices, or CypherAir consumer validation
> changes.

## Repository Identity

CypherAir maintains a separate public build-wrapper repository for SQLCipher
Apple XCFramework generation:

- Repository: `cypherair/sqlcipher-xcframework`
- Local checkout convention: `/Users/tianren/coding/sqlcipher-xcframework`
- Upstream SQLCipher source: `sqlcipher/sqlcipher`
- Upstream tag: `v4.16.0`
- Upstream peeled commit:
  `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`

The repository is a build-wrapper and release-artifact repository. It is not a
fork of SQLCipher core. A `cypherair/sqlcipher` fork should only be introduced
if CypherAir needs a persistent source patch for arm64e, provider selection,
privacy manifest handling, or another upstream change that cannot stay in the
wrapper build scripts.

## Stable Artifact Contract

The wrapper repository builds a static framework-shaped `SQLCipher.xcframework`
using SQLCipher's Apple CommonCrypto / Security provider configuration:

- `SQLCIPHER_CRYPTO_CC`
- `SQLITE_HAS_CODEC`
- `SQLITE_TEMP_STORE=2`
- `SQLITE_THREADSAFE=1`
- `SQLITE_EXTRA_INIT=sqlcipher_extra_init`
- `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`

The supported slice set is intentionally limited to CypherAir's platform needs:

- iOS device: `arm64`, `arm64e`
- macOS: `arm64`, `arm64e`
- visionOS device: `arm64`, `arm64e`
- iOS Simulator: `arm64`
- visionOS Simulator: `arm64`

Stable releases publish:

- `SQLCipher.xcframework.zip`
- `SQLCipher.xcframework.sha256`
- `SQLCipher.arm64e-build-manifest.json`
- `SQLCipher-PrivacyInfo.xcprivacy`
- `SQLCipher.xcframework.release.json`

Stable SQLCipher releases must be SSH-signed annotated tags, non-prerelease
GitHub Releases, immutable after publication, and verified with all three
layers:

- `gh release verify`
- `gh release verify-asset`
- `gh attestation verify`

## Current Pin

The current consumer contract is tracked in
`third_party/sqlcipher-xcframework.pin.json`:

- Release:
  `sqlcipher-xcframework-v4.16.0-cypherair.1`
- Release URL:
  `https://github.com/cypherair/sqlcipher-xcframework/releases/tag/sqlcipher-xcframework-v4.16.0-cypherair.1`
- Wrapper repository commit:
  `aee70b13ddf0eb262ac1283930760cac44dbe873`
- Release channel: `stable`
- Release immutability: `true`
- Upstream SQLCipher tag: `v4.16.0`
- Upstream SQLCipher peeled commit:
  `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`
- `SQLCipher.xcframework.zip` SHA-256:
  `3544554bcf947fb9329f2ab083cd42f0c7ae9179e98b7f36f26859e2c573062e`

Main-repository policy:

- Do not commit `SQLCipher.xcframework` or downloaded SQLCipher release assets.
  They are ignored local / CI artifacts, like `PgpMobile.xcframework`.
- Track only the consumer contract: the pin file, restore script, validation
  script, tests, and documentation.
- Source-of-truth building happens in `cypherair/sqlcipher-xcframework`. To
  refresh SQLCipher, publish a new stable immutable release there first, then
  update `third_party/sqlcipher-xcframework.pin.json` and the related docs/tests
  in this repository.
- The restore flow reads the pin file, rejects `latest` and non-stable pins,
  verifies the checksum before extraction, validates release metadata, source
  tag/commit, slices, headers, modulemap, compile flags, privacy manifest, and
  macOS smoke behavior, including raw-key syntax through `sqlite3_key_v2`,
  good-key read/write, and wrong-key rejection, then restores
  `SQLCipher.xcframework` at the repository root for Xcode builds.
- CI and Xcode Cloud use `--require-attestation`, which additionally requires
  immutable release verification, release-asset verification, and workflow
  artifact attestation verification.
- The Xcode project validates the restored artifact in a build phase and links
  `SQLCipher.xcframework` through the app target's normal Frameworks phase. The
  artifact uses `SQLCipher.framework` slices so module maps live under the
  framework bundle instead of forcing slice-specific linker or modulemap paths.
- `CypherAir-compliance-manifest.json` and in-app
  `SourceComplianceInfo.json` record SQLCipher under
  `externalBinaryDependencies`; CypherAir stable releases do not mirror
  SQLCipher assets or upstream source.
- The app must keep its zero-network and minimal-permission constraints.

Restore the current artifact locally with:

```bash
scripts/restore_sqlcipher_xcframework.sh
```

CI and Xcode Cloud use:

```bash
scripts/restore_sqlcipher_xcframework.sh --require-attestation
```

## Refresh Flow

To refresh SQLCipher:

1. Build and validate the new artifact in `cypherair/sqlcipher-xcframework`.
2. Publish a new SSH-signed annotated stable tag such as
   `sqlcipher-xcframework-v4.16.0-cypherair.2`.
3. Verify the immutable release with `gh release verify`,
   `gh release verify-asset`, and `gh attestation verify`.
4. Update `third_party/sqlcipher-xcframework.pin.json` with the new release tag,
   wrapper commit, asset hashes, slice hashes, and signer workflow.
5. Run `scripts/restore_sqlcipher_xcframework.sh --require-attestation`.
6. Run `python3 scripts/validate_sqlcipher_xcframework.py --root .`.
7. Update this document and any release/testing docs that quote the pin.

If a stable SQLCipher artifact is wrong after publication, do not replace
release assets. Publish a new semantic stable tag and repin this repository.

## Contacts Consumer Contract

Contacts storage consumes this pinned SQLCipher artifact through the app target's
normal framework linkage. The protected `contacts` domain remains the stable
ProtectedData identity, while `contacts.sqlite` replaces the older snapshot
envelope as the authoritative Contacts payload.

The Contacts implementation uses the existing `contacts` domain master key
directly with SQLCipher raw-key syntax. It must not add a separate
Contacts-specific database-key custody row, fall back to legacy snapshot
artifacts, or change the SQLCipher dependency pin/release model as part of
Contacts persistence work.

Contacts SQLCipher changes remain covered by
[Contacts SQLCipher Storage Design](CONTACTS_SQLCIPHER_STORAGE_DESIGN.md) and
must preserve post-unlock opening without a normal-flow second prompt, relock
connection cleanup, reset cleanup for DB sidecars and obsolete ProtectedData
artifacts, and fail-closed recovery for corrupt, missing, mismatched key,
schema, config, or integrity state.

Private-key wrapping cleanup remains separate issue #540 follow-up work and is
not part of the SQLCipher dependency contract.
