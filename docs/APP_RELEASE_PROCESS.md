# App Release Process

> Status: Canonical current-state.
> Purpose: Document the release flows for CypherAir app builds and the stable build contract that backs formal App Store releases.
> Audience: Human developers, release owners, and AI coding tools.
> Source of truth: `CypherAir` and `CypherAir AppStore Candidate` scheme behavior, `SourceComplianceInfo.json` build integration, the Xcode Cloud `PgpMobile XCFramework` + `CypherAir Release` workflows ([XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md)), and `.github/workflows/stable-release-attest.yml`.
> Last reviewed: 2026-06-18.
> Update triggers: stable tag rules, stable asset names, arm64e stage1 pin changes, `Source & Compliance` archive metadata, App Store candidate gating, or release-ordering changes.
> Scope: App build release flow and the exact stable GitHub release contract used by the app. `XCFramework` channel discovery and verification remain in [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md).
> Agent choreography: `.claude/skills/release-stable` sequences this flow for agent sessions; this document stays canonical for every rule it cites.

## 1. Release Modes

CypherAir uses two release modes:

- `Internal / Experimental TestFlight`
- `App Store Candidate`

These modes are intentionally different.

- Internal and experimental uploads prioritize iteration speed.
- App Store candidate uploads prioritize traceability, exact release linkage, and compliance review readiness.

The formal App Store path runs on **Xcode Cloud** (Apple-blessed release Xcode/SDK). The end-to-end design, the two-workflow split, credentials, and setup live in [XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md); this document stays canonical for the tag rules, the stable asset contract, and the release ordering.

## 2. Stable Build Contract

CypherAir's formal stable app-build release uses a unified GitHub release page, built and published by Xcode Cloud.

- Stable release tags use the format
  `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`, using the
  exact Xcode project build setting values.
- Stable release tags must be SSH-signed annotated tags. Do not publish
  lightweight or unsigned stable tags.
- Formal publishing is tag-first. Create and push the SSH-signed stable tag on
  the intended `main` commit; that tag push is the trigger for the Xcode Cloud
  release.
- Pushing a stable tag triggers the Xcode Cloud `PgpMobile XCFramework` workflow
  (WF1), which builds the XCFramework and the compliance assets, creates the
  GitHub Release as a draft, and starts the `CypherAir Release` workflow (WF2),
  which archives/signs/delivers the app, attaches the app binaries, and publishes
  the release. See [XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md).
- The stable release page is the exact source and compliance landing page for both the tagged App build and the stable `PgpMobile.xcframework` assets.
- The release flow validates that the tag's marketing version and build number
  match `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` before the release is
  published (WF1 `ci_post_xcodebuild`, and the App Store candidate validator in
  WF2).
- WF1 revalidates that the stable tag is an SSH-signed annotated tag for the
  release commit before creating the release;
  `.github/workflows/stable-release-attest.yml` re-verifies the signed tag and
  the XCFramework checksum on `release.published` before generating the
  provenance attestation.
- The Rust dependency audit (`cargo audit --file pgp-mobile/Cargo.lock --deny warnings`,
  official stable toolchain) runs as a gate in WF1 `ci_post_clone` before the
  XCFramework build; if it fails, the build stops and no release is produced.
- WF1 uses the pinned arm64e Rust stage1 prerelease recorded in
  `docs/ARM64E_STATUS.md` (consumed via
  `scripts/build_apple_arm64e_xcframework.sh`'s `DEFAULT_ARM64E_STAGE1_RELEASE_TAG`).
  If the intended release requires a newer Rust fork stage1, complete the re-pin
  per the `docs/ARM64E_STATUS.md` re-pin rule (agent checklist:
  `.claude/skills/repin-arm64e`) in a normal PR before creating the stable tag.
- Release owners choose and set the Xcode release metadata in the project. The
  release flow reads those values; it does not invent, increment, reset, or
  formula-generate `CURRENT_PROJECT_VERSION`.

Every published stable build release must include these SDK/compliance assets:

- `CypherAir-source-bundle.tar.zst`
- `CypherAir-compliance-manifest.json`
- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
- `PgpMobile.arm64e-build-manifest.json`
- `PgpMobile-relink-kit.tar.zst`

CypherAir also records formal external binary dependencies in
`CypherAir-compliance-manifest.json`, including the pinned SQLCipher
`SQLCipher.xcframework` release from `cypherair/sqlcipher-xcframework`. Those
external binary assets and the SQLCipher upstream source are not mirrored into
the CypherAir stable release.

It also carries the App Store upload artifacts (Transporter payloads — App
Store-signed, not directly installable; see [XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md) §8):
`CypherAir-iOS-AppStore.ipa`, `CypherAir-visionOS-AppStore.ipa`, and
`CypherAir-macOS-AppStore.pkg`.

Stable build binding and immutability rules:

- The source bundle, compliance manifest, XCFramework zip/checksum, arm64e manifest, and relink kit are built from the tagged commit by WF1; formal stable assets are not promoted from edge or drill prereleases.
- Stable assets must bind to one exact marketing version, build number, release tag, and commit SHA.
- App Store candidate archives must embed the exact stable release tag, stable release URL, and commit SHA in `SourceComplianceInfo.json`.
- Stable assets are immutable once published. WF1 creates the release as a draft and WF2 publishes it once the app binaries are attached, so "published" is atomic. WF2 upload retries skip an already-present asset only when the digest matches; a same-name different-digest asset fails and requires a cleaned draft or a new build. If the asset set is wrong, fix it with a new build number, new stable tag, and new release rather than replacing assets in place.

Version and build-number rules:

- `MARKETING_VERSION` maps to `CFBundleShortVersionString`; it is the app
  version shown to users.
- `CURRENT_PROJECT_VERSION` maps to `CFBundleVersion`; it identifies the exact
  build uploaded or archived.
- For macOS App Store uploads, `CURRENT_PROJECT_VERSION` / `CFBundleVersion`
  must be higher than the highest macOS build previously uploaded for the app,
  even when `MARKETING_VERSION` has increased.
- The project does not require a fixed formula for `CURRENT_PROJECT_VERSION`.
  Use the final value recorded in the Xcode project when creating the stable
  tag and App Store candidate archive.

Stable tag signing requirements:

- Use Git SSH signing for stable tags. Configure `gpg.format=ssh` and
  `user.signingkey` to an SSH public key trusted for release signing before
  creating the tag.
- Create stable tags with `git tag -s -m "<tag>" <tag> <main-commit>` so the
  tag is annotated and signed. For example, after choosing the final project
  values:

  ```bash
  TAG="cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>"  # e.g. cypherair-v1.3.6-build13601
  MAIN_COMMIT="$(git rev-parse main)"
  git -c gpg.format=ssh tag -s -m "$TAG" "$TAG" "$MAIN_COMMIT"
  ```
- Verify the tag signature locally with `git tag -v <tag>` before pushing it.

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

1. Update code and Xcode project version/build metadata as needed.
2. Run the relevant local validation.
3. Archive from the standard `CypherAir` scheme (locally, on a non-beta macOS).
4. Upload to TestFlight for internal or experimental use.

## 4. App Store Candidate

Use this path only for the build that is intended to act as the formal App Store
candidate. It runs on Xcode Cloud (the `CypherAir Release` workflow, WF2); a
local Xcode archive of the same scheme remains available as a break-glass
fallback.

### Entry Point

Xcode Cloud WF2 (and the local break-glass archive) uses the dedicated shared
scheme:

- `CypherAir AppStore Candidate`

Its `Archive` action uses:

- build configuration: `AppStore Candidate Release`

### Candidate Rules

The App Store candidate path is intentionally strict:

- the archive's commit must be the stable tag commit
- it requires a GitHub stable release for the tag to already exist
- it requires that release to include a valid `PgpMobile.arm64e-build-manifest.json`
- it requires the restored SQLCipher artifact to match `third_party/sqlcipher-xcframework.pin.json`
- it requires `HEAD` to match the remote stable tag commit exactly
- it requires the app archive to embed the exact stable release tag and URL in `SourceComplianceInfo.json`
- it requires the app archive to embed an exact commit SHA in `SourceComplianceInfo.json`

The candidate path performs an automatic pre-archive validation
(`scripts/validate_app_store_candidate_release.py`), run by Xcode Cloud WF2
`ci_post_clone` and by the scheme's local pre-action:

- under Xcode Cloud: confirms `CI_TAG` equals the derived
  `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>` and `HEAD`
  equals `CI_COMMIT` (the checkout is a detached HEAD at the tag)
- locally (break-glass): confirms the current branch is `main` and the tracked
  worktree and index are clean
- both: derives the tag, confirms the GitHub stable release exists, downloads and
  validates `PgpMobile.arm64e-build-manifest.json`, validates the restored
  SQLCipher formal external dependency against
  `third_party/sqlcipher-xcframework.pin.json`, resolves the remote stable tag
  commit from `origin`, and blocks archive if `HEAD` does not match it or the
  release does not exist

In WF2, `ci_post_clone` also downloads and `shasum`-verifies the exact
`PgpMobile.xcframework.zip` from the (draft) stable release before linking it, so
the shipped binary links the same attested XCFramework that is published.

### Required Order

This order is mandatory for App Store candidates:

1. Finish the intended candidate code changes.
2. Update the Xcode project version and build number. For macOS App Store
   candidates, confirm `CURRENT_PROJECT_VERSION` is higher than the highest
   macOS build previously uploaded for the app.
3. Commit and push the candidate commit to `main`.
4. Confirm the pinned arm64e stage1 tag in `docs/ARM64E_STATUS.md` is the
   intended stage1 input for this release.
5. Create the SSH-signed stable tag on the intended `main` commit:
   - `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`
   - annotated and SSH-signed; lightweight and unsigned tags are not allowed
   - push the tag to `origin`; that tag push triggers Xcode Cloud WF1
6. WF1 audits Rust dependencies, builds the XCFramework and the six compliance
   assets, creates the draft stable release, and starts WF2.
7. WF2 downloads and checksum-verifies the published XCFramework, runs the
   candidate validation, archives iOS/macOS/visionOS with cloud signing, delivers
   to TestFlight (internal), attaches the App Store upload artifacts, and
   publishes the release.
8. `.github/workflows/stable-release-attest.yml` runs on `release.published` and
   attests the SDK/compliance assets.
9. Confirm the stable release page, assets, and TestFlight builds. Submit for
   App Store review manually in App Store Connect when ready.

Break-glass (Xcode Cloud unavailable): after a stable release for the tag exists,
archive `CypherAir AppStore Candidate` locally on a non-beta macOS and upload via
Transporter. The local pre-action enforces the same candidate validation. Do
**not** archive before the stable release exists, or from a checkout whose
tracked state or `HEAD` differs from the published stable tag commit.

## 5. Candidate Verification Checklist

Before promoting the App Store candidate, confirm:

- the version/build pair is final
- the macOS App Store build number is higher than any previously uploaded
  macOS build for the app
- the stable tag matches the app version/build and is SSH-signed
- the pinned arm64e stage1 tag in `docs/ARM64E_STATUS.md` is the intended stage1
  input for this release
- the Xcode Cloud WF1→WF2 run completed and published the stable release
- WF1's Rust dependency audit passed without warnings
- the release page includes all six SDK/compliance assets listed in Section 2
  plus the three App Store upload artifacts
- `stable-release-attest.yml` completed and `gh attestation verify` passes
  (see [XCFRAMEWORK_RELEASES.md](XCFRAMEWORK_RELEASES.md))
- the archive was built from `CypherAir AppStore Candidate`

After the candidate build is available on TestFlight, confirm in the app:

- `About -> Source & Compliance` is present
- the page shows the expected version/build
- the page shows the expected exact commit SHA
- the page shows the expected exact stable release tag and URL

## 6. Notes

- Ordinary TestFlight uploads do not need to follow the App Store candidate path.
- The App Store candidate path exists specifically to ensure that the build uploaded for serious release evaluation is traceable to an exact GitHub stable release page and its compliance assets.
