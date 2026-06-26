# SQLCipher XCFramework Experiment

> Status: Active experiment / proposal. This document is not a statement of
> current shipped app behavior.
> Purpose: Record the external SQLCipher XCFramework build repository created
> for arm64e feasibility work before Contacts SQLCipher adoption.
> Audience: CypherAir maintainers, release owners, and agents working on
> Contacts persistence or Apple arm64e dependency planning.
> Companion: GitHub issue #540 and `cypherair/sqlcipher-xcframework`.
> Last reviewed: 2026-06-26.
> Update triggers: SQLCipher artifact repository identity, asset contract,
> adoption status, supported slices, or CypherAir consumer validation changes.

## Repository Identity

CypherAir maintains a separate public experimental repository for SQLCipher
Apple XCFramework generation:

- Repository: `cypherair/sqlcipher-xcframework`
- Local checkout convention: `/Users/tianren/coding/sqlcipher-xcframework`
- Upstream SQLCipher source: `sqlcipher/sqlcipher`
- Initial upstream tag: `v4.16.0`
- Initial upstream peeled commit:
  `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`

The repository is a build-wrapper and release-artifact experiment. It is not a
fork of SQLCipher core. A `cypherair/sqlcipher` fork should only be introduced
if CypherAir needs a persistent source patch for arm64e, provider selection,
privacy manifest handling, or another upstream change that cannot stay in the
wrapper build scripts.

## Experimental Artifact Contract

The experimental repository builds a static-library `SQLCipher.xcframework`
using SQLCipher's Apple CommonCrypto / Security provider configuration:

- `SQLCIPHER_CRYPTO_CC`
- `SQLITE_HAS_CODEC`
- `SQLITE_TEMP_STORE=2`
- `SQLITE_THREADSAFE=1`
- `SQLITE_EXTRA_INIT=sqlcipher_extra_init`
- `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`

The initial slice set is intentionally limited to CypherAir's platform needs:

- iOS device: `arm64`, `arm64e`
- macOS: `arm64`, `arm64e`
- visionOS device: `arm64`, `arm64e`
- iOS Simulator: `arm64`
- visionOS Simulator: `arm64`

Experimental releases are expected to publish:

- `SQLCipher.xcframework.zip`
- `SQLCipher.xcframework.sha256`
- `SQLCipher.arm64e-build-manifest.json`
- `SQLCipher-PrivacyInfo.xcprivacy`
- `sqlcipher-xcframework-experiment.json`

## Main-Repository Boundary

This CypherAir repository does not currently link SQLCipher, consume the
experimental XCFramework, or use a Swift Package dependency for SQLCipher.

Until a later adoption PR explicitly changes that status:

- SQLCipher artifacts are not part of the formal CypherAir stable release
  contract.
- `docs/ARM64E_STATUS.md` remains focused on current app-side arm64e inputs.
- `docs/XCFRAMEWORK_RELEASES.md` remains focused on `PgpMobile.xcframework`.
- App Store candidate validation does not require a SQLCipher manifest.
- The app must keep its zero-network and minimal-permission constraints.

## Adoption Follow-Up

Before Contacts can move to SQLCipher-backed storage, a later CypherAir PR must
add consumer-side validation for the SQLCipher artifact. At minimum, that PR
should verify the exact release tag, checksum, attestation, manifest schema,
upstream source tag and commit, crypto-provider flags, privacy manifest, and all
required `arm64e` slices before linking the XCFramework.

That adoption PR should also update the canonical current-state docs that become
affected at that point, including release, testing, arm64e status, persisted
state inventory, security, and architecture documentation.

