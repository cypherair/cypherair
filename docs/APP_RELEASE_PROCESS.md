# App Release Process

> Purpose: Document the operational release flows for CypherAir app builds, including the lightweight internal TestFlight path and the strict App Store candidate path.
> Audience: Human developers, release owners, and AI coding tools.
> Scope: App build release flow only. `XCFramework` asset-channel details remain in [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md). Compliance policy and asset-contract rationale remain in [COMPLIANCE_REMEDIATION_PLAN.md](COMPLIANCE_REMEDIATION_PLAN.md).

## 1. Release Modes

CypherAir uses two release modes:

- `Internal / Experimental TestFlight`
- `App Store Candidate`

These modes are intentionally different.

- Internal and experimental uploads prioritize iteration speed.
- App Store candidate uploads prioritize traceability, exact release linkage, and compliance review readiness.

## 2. Internal / Experimental TestFlight

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

## 3. App Store Candidate

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

## 4. Candidate Verification Checklist

Before uploading the App Store candidate to TestFlight, confirm:

- the branch is `main`
- the tracked worktree and index are clean
- the version/build pair is final
- the stable tag matches the app version/build
- the GitHub stable release completed successfully
- the release page includes the expected compliance assets
- `HEAD` matches the remote stable tag commit
- the archive was built from `CypherAir AppStore Candidate`

After archiving, confirm in the app:

- `About -> Source & Compliance` is present
- the page shows the expected version/build
- the page shows the expected exact commit SHA
- the page shows the expected exact stable release tag and URL

## 5. Notes

- Ordinary TestFlight uploads do not need to follow the App Store candidate path.
- The App Store candidate path exists specifically to ensure that the build uploaded for serious release evaluation is traceable to an exact GitHub stable release page and its compliance assets.
