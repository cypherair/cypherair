# App Release Process

> Status: Canonical current-state.
> Purpose: Document the current release flows for CypherAir app builds and the stable build contract that backs formal App Store candidate archives.
> Audience: Human developers, release owners, and AI coding tools.
> Source of truth: `CypherAir` and `CypherAir AppStore Candidate` scheme behavior, `SourceComplianceInfo.json` build integration, and `.github/workflows/stable-build-release.yml`.
> Last reviewed: 2026-04-20.
> Update triggers: stable tag rules, stable asset names, `Source & Compliance` archive metadata, App Store candidate gating, or release-ordering changes.
> Scope: App build release flow and the exact stable GitHub release contract used by the app. `XCFramework` channel discovery and verification remain in [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md).

## 1. Release Modes

CypherAir uses two release modes:

- `Internal / Experimental TestFlight`
- `App Store Candidate`

These modes are intentionally different.

- Internal and experimental uploads prioritize iteration speed.
- App Store candidate uploads prioritize traceability, exact release linkage, and compliance review readiness.

## 2. Stable Build Contract

CypherAir's formal stable app-build release uses a unified GitHub release page.

- Stable release tags use the format `cypherair-vX.Y.Z-buildN`.
- Pushing a stable tag triggers the stable build release workflow; manual runs can dry-run the same contract without publishing the immutable release.
- The stable release page is the exact source and compliance landing page for both the tagged App build and the stable `PgpMobile.xcframework` assets.
- The stable workflow validates that the tag's marketing version and build number match `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` before assets are published.

Every published stable build release must include these assets:

- `CypherAir-source-bundle.tar.zst`
- `CypherAir-compliance-manifest.json`
- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
- `PgpMobile-relink-kit.tar.zst`

Stable build binding and immutability rules:

- The source bundle, compliance manifest, XCFramework zip/checksum, and relink kit are rebuilt from the tagged commit; formal stable assets are not promoted from edge or drill prereleases.
- Stable assets must bind to one exact marketing version, build number, release tag, and commit SHA.
- App Store candidate archives must embed the exact stable release tag, stable release URL, and commit SHA in `SourceComplianceInfo.json`.
- Stable assets are immutable once published. If the asset set is wrong, fix it with a new build number, new stable tag, and new release rather than replacing assets in place.

## 3. Internal / Experimental TestFlight

Use this path for:

- day-to-day development builds
- internal TestFlight experiments
- exploratory QA uploads
- any build that is not yet intended to serve as the formal App Store candidate

### Entry Point

Use the standard shared scheme:

- `CypherAir`

### Expectations

- No GitHub stable release is required before archive.
- `Source & Compliance` may show no exact stable release URL.
- The build may be uploaded to TestFlight for internal or experimental review.
- This build is **not** treated as the formal candidate for App Store release.

### Typical Flow

1. Update code and version/build metadata as needed.
2. Run the relevant local validation.
3. Archive from the standard `CypherAir` scheme.
4. Upload to TestFlight for internal or experimental use.

## 4. App Store Candidate

Use this path only for the build that is intended to act as the formal App Store candidate.

### Entry Point

Use the dedicated shared scheme:

- `CypherAir AppStore Candidate`

Its `Archive` action uses:

- build configuration: `AppStore Candidate Release`

### Candidate Rules

The App Store candidate path is intentionally strict:

- it is only allowed from `main`
- it requires a clean tracked worktree and index
- it requires a GitHub stable release to already exist
- it requires `HEAD` to match the remote stable tag commit exactly
- it requires the app archive to embed the exact stable release tag and URL in `SourceComplianceInfo.json`
- it requires the app archive to embed an exact commit SHA in `SourceComplianceInfo.json`

The candidate archive path performs an automatic pre-archive validation:

- confirms the current branch is `main`
- confirms the tracked worktree and index are clean
- derives `cypherair-vX.Y.Z-buildN` from `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION`
- checks that `gh release view <tag> -R cypherair/cypherair` succeeds
- resolves the remote stable tag commit from `origin`
- blocks archive if `HEAD` does not match that remote stable tag commit
- blocks archive if the release does not exist

### Required Order

This order is mandatory for App Store candidates:

1. Finish the intended candidate code changes.
2. Update the version and build number.
3. Commit and push the candidate commit to `main`.
4. Create the stable tag:
   - `cypherair-vX.Y.Z-buildN`
5. Wait for the GitHub stable release workflow to complete successfully.
6. Confirm the stable release page and required assets exist.
7. Return to a clean `main` checkout whose `HEAD` exactly matches the stable tag commit.
8. Open Xcode and archive using `CypherAir AppStore Candidate`.
9. Upload that archive to TestFlight as the App Store candidate validation build.

Do **not** archive the App Store candidate before the GitHub stable release exists, or from a checkout whose tracked state or `HEAD` differs from the published stable tag commit.

## 5. Candidate Verification Checklist

Before uploading the App Store candidate to TestFlight, confirm:

- the branch is `main`
- the tracked worktree and index are clean
- the version/build pair is final
- the stable tag matches the app version/build
- the GitHub stable release completed successfully
- the release page includes the expected stable assets:
  `CypherAir-source-bundle.tar.zst`,
  `CypherAir-compliance-manifest.json`,
  `PgpMobile.xcframework.zip`,
  `PgpMobile.xcframework.sha256`,
  and `PgpMobile-relink-kit.tar.zst`
- `HEAD` matches the remote stable tag commit
- the archive was built from `CypherAir AppStore Candidate`

After archiving, confirm in the app:

- `About -> Source & Compliance` is present
- the page shows the expected version/build
- the page shows the expected exact commit SHA
- the page shows the expected exact stable release tag and URL

## 6. Notes

- Ordinary TestFlight uploads do not need to follow the App Store candidate path.
- The App Store candidate path exists specifically to ensure that the build uploaded for serious release evaluation is traceable to an exact GitHub stable release page and its compliance assets.
