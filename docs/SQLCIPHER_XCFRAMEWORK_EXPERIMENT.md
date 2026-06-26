# SQLCipher XCFramework Experiment

> Status: Active app-build preflight. Contacts storage is not yet migrated.
> Purpose: Record the external SQLCipher XCFramework build repository created
> for arm64e feasibility work before Contacts SQLCipher adoption, and the
> current CypherAir consumer contract.
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

The experimental repository builds a static framework-shaped
`SQLCipher.xcframework` using SQLCipher's Apple CommonCrypto / Security provider
configuration:

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

This CypherAir repository now performs an app-build preflight against the
experimental SQLCipher artifact. The app target links SQLCipher for validation,
but Contacts persistence, DB key wrapping, Keychain records, reset cleanup, and
self-ECDH cleanup remain future work under issue #540.

The pinned consumer input is:

- Release: `sqlcipher-xcframework-experiment-20260626T224724Z-61d7f56-r28269517779-a1`
- Wrapper repository commit:
  `61d7f56baa687a19270c93f85b3663adc22fa9f2`
- Upstream SQLCipher tag: `v4.16.0`
- Upstream SQLCipher peeled commit:
  `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`
- `SQLCipher.xcframework.zip` SHA-256:
  `22bd894ded5bdde119c87f81809b9b99a19dcd7afdf9410858a7fc34555ee20d`

Main-repository policy:

- Do not commit `SQLCipher.xcframework` or downloaded release assets. They are
  ignored local / CI artifacts, like `PgpMobile.xcframework`.
- Track only the consumer contract: exact release tag, expected SHA values,
  restore script, validation script, tests, and documentation.
- Source-of-truth building happens in `cypherair/sqlcipher-xcframework`. To
  refresh SQLCipher, publish a new experimental release there first, then update
  the pinned tag/hash/manifest expectations in this repository.
- The restore flow downloads the pinned assets, verifies the checksum before
  extraction, validates release metadata, source tag/commit, slices, headers,
  modulemap, compile flags, privacy manifest, and macOS smoke behavior, then
  restores `SQLCipher.xcframework` at the repository root for Xcode builds.
- CI requires GitHub artifact attestation verification with
  `gh attestation verify`. Local developers may omit attestation, or may use
  `--from-local-build` for experiments, but validation still runs.
- The Xcode project validates the restored artifact in a build phase and links
  `SQLCipher.xcframework` through the app target's normal Frameworks phase. The
  artifact uses `SQLCipher.framework` slices so module maps live under the
  framework bundle instead of forcing slice-specific linker or modulemap paths.
- `docs/ARM64E_STATUS.md` records SQLCipher as an app-build preflight input.
- `docs/XCFRAMEWORK_RELEASES.md` remains focused on `PgpMobile.xcframework`.
- App Store candidate validation does not yet treat SQLCipher as a stable
  release input.
- The app must keep its zero-network and minimal-permission constraints.

Restore the current artifact locally with:

```bash
scripts/restore_sqlcipher_xcframework.sh
```

CI uses:

```bash
scripts/restore_sqlcipher_xcframework.sh --require-attestation
```

## Adoption Follow-Up

Before Contacts can move to SQLCipher-backed storage, a later CypherAir PR must
add the actual Contacts persistence layer and security lifecycle:

- app-generated high-entropy DB key
- wrapped DB key Keychain record tied to the existing ProtectedData / Secure
  Enclave device-binding authority
- post-unlock preload without a normal-flow second authentication prompt
- relock connection/statement/key cleanup
- reset cleanup for DB, sidecars, Keychain record, and obsolete Contacts
  ProtectedData artifacts
- fail-closed recovery for corrupt/missing/mismatched key, schema, config, or
  integrity state

That adoption PR should also update the canonical current-state docs that become
affected at that point, including release, testing, arm64e status, persisted
state inventory, security, and architecture documentation.
