# XCFramework Releases

> Status: Canonical current-state.
> Purpose: Describe the current edge, drill, and stable `PgpMobile.xcframework` release channels, including discovery, verification, and the stable channel's relationship to the unified app-build release page.
> Audience: Human developers and automation that consume prebuilt `PgpMobile.xcframework` assets.
> Source of truth: `.github/workflows/xcframework-edge-release.yml`, `.github/workflows/stable-build-release.yml`, and published GitHub releases.
> Last reviewed: 2026-05-12.
> Update triggers: channel naming/routing, asset names, verification commands, stable asset contract, or relink-kit semantics.

## 1. Release Channels

### Edge Channel

CypherAir publishes a unique edge prerelease XCFramework from the current `main` branch for each successful edge release workflow run.

- Edge prerelease tags use the `pgpmobile-edge-` prefix.
- Tag format: `pgpmobile-edge-YYYYMMDDTHHMMSSZ-shortsha-rRUN_ID-aRUN_ATTEMPT`.
- This channel is updated automatically on every successful push to `main` and may be manually re-run from `main` only with the exact `pgpmobile-edge` prefix.
- It is intended for CI, integration, and manual validation of the current `main` tip.
- It is not treated as a stable SDK release.

The legacy rolling `pgpmobile-edge` tag/release is deprecated and removed during the migration to unique edge prereleases. Consumers must not use the fixed `pgpmobile-edge` tag.

### Drill Channel

Non-`main` manual validation must use a `pgpmobile-drill-*` prefix.

- Drill prerelease tags use the `pgpmobile-drill-*` prefix supplied to `workflow_dispatch`.
- Drill releases are branch- or ref-specific validation artifacts, not part of the canonical edge discovery channel.
- Drill releases publish `PgpMobile.xcframework.zip`, `PgpMobile.xcframework.sha256`, `PgpMobile.arm64e-build-manifest.json`, and `pgpmobile-drill.json`.
- Consumers must not discover or consume drill artifacts by scanning for the latest edge prerelease.

Each edge prerelease publishes exactly these assets:

- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
- `PgpMobile.arm64e-build-manifest.json`
- `pgpmobile-edge.json`

`pgpmobile-edge.json` is machine-readable metadata with these fields:

- `release_tag`
- `release_url`
- `release_channel`
- `source_ref`
- `commit_sha`
- `built_at`
- `run_id`
- `run_attempt`
- `marketing_version`
- `project_build_number`
- `xcode_version`
- `rustc_version`
- `arm64e_manifest`
- `workflow_url`

This is intentional: a single app marketing version can have multiple Xcode build numbers during development, so XCFramework metadata must carry both values to identify the exact build instance that produced the binary.

### Stable Channel

CypherAir publishes stable XCFramework assets through the same unified stable GitHub release page used by formal app builds.

- Stable release tags use the app-build format defined in
  [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md):
  `cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>`.
- The stable release page is the exact source and compliance landing page for both the tagged App build and the stable `PgpMobile.xcframework` assets.
- Stable releases publish these assets together:
  `CypherAir-source-bundle.tar.zst`,
  `CypherAir-compliance-manifest.json`,
  `PgpMobile.xcframework.zip`,
  `PgpMobile.xcframework.sha256`,
  `PgpMobile.arm64e-build-manifest.json`,
  and `PgpMobile-relink-kit.tar.zst`.
- `PgpMobile.arm64e-build-manifest.json` records the Rust stage1 prerelease
  provenance, the resolved `openssl-src-rs` carry commit, the OpenSSL submodule
  commit, and the verified XCFramework slice layout.
- `PgpMobile-relink-kit.tar.zst` is a technical supplement for SDK consumers and relink-focused compliance review. It does not replace the shared source bundle and is not an in-app asset.
- Stable assets are immutable once published. If a stable asset set is wrong, publish a new build number under a new stable tag instead of replacing assets in place.
- Edge and drill prereleases remain separate from the stable channel.

### CI Cache Policy

CypherAir release and validation workflows intentionally avoid Cargo cache
actions. The arm64e XCFramework build force-downloads the selected Rust fork
stage1 prerelease inside `./build-xcframework.sh --release`; caching Cargo
`target/` artifacts before that resolution can reuse objects built by an older
stage1 compiler. Clean Rust builds are slower, but they keep edge, drill, PR,
nightly, and stable release artifacts deterministic across stage1 updates.

## 2. Edge Discovery And Downloading

First discover the newest edge prerelease by matching the `pgpmobile-edge-` prefix:

```bash
TAG="$(gh release list \
    --repo cypherair/cypherair \
    --json tagName,isPrerelease,publishedAt \
    --jq '[.[] | select(.isPrerelease and (.tagName | startswith("pgpmobile-edge-")))] | sort_by(.publishedAt) | last | .tagName')"

test -n "$TAG"
```

Then download the assets from that unique tag:

```bash
gh release download "$TAG" \
    --repo cypherair/cypherair \
    --pattern 'PgpMobile.xcframework.zip' \
    --pattern 'PgpMobile.xcframework.sha256' \
    --pattern 'PgpMobile.arm64e-build-manifest.json' \
    --pattern 'pgpmobile-edge.json'
```

Extract the XCFramework after verification:

```bash
ditto -x -k PgpMobile.xcframework.zip .
```

## 3. Edge Verification

First validate the checksum:

```bash
shasum -a 256 -c PgpMobile.xcframework.sha256
```

Then verify the immutable release and downloaded asset:

```bash
gh release verify "$TAG" -R cypherair/cypherair
gh release verify-asset "$TAG" PgpMobile.xcframework.zip -R cypherair/cypherair
```

Finally, verify the GitHub artifact attestation for the zip:

```bash
gh attestation verify PgpMobile.xcframework.zip \
    -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/xcframework-edge-release.yml \
    --source-ref refs/heads/main
gh attestation verify PgpMobile.arm64e-build-manifest.json \
    -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/xcframework-edge-release.yml \
    --source-ref refs/heads/main
```

Drill releases are verified using the exact ref-pinned command rendered in that release's notes. Do not reuse the canonical edge command for drill artifacts.

## 4. Stable Release Retrieval

Stable releases are retrieved by their exact app-build tag:

```bash
TAG="cypherair-v1.3.6-build13601" # replace with the exact stable tag

gh release download "$TAG" \
    --repo cypherair/cypherair \
    --pattern 'CypherAir-source-bundle.tar.zst' \
    --pattern 'CypherAir-compliance-manifest.json' \
    --pattern 'PgpMobile.xcframework.zip' \
    --pattern 'PgpMobile.xcframework.sha256' \
    --pattern 'PgpMobile.arm64e-build-manifest.json' \
    --pattern 'PgpMobile-relink-kit.tar.zst'
```

Validate the stable XCFramework artifact with:

```bash
shasum -a 256 -c PgpMobile.xcframework.sha256
gh release verify "$TAG" -R cypherair/cypherair
gh release verify-asset "$TAG" PgpMobile.xcframework.zip -R cypherair/cypherair
gh release verify-asset "$TAG" PgpMobile.arm64e-build-manifest.json -R cypherair/cypherair
```

Use the source bundle, compliance manifest, and relink kit together when you need exact source-compliance materials for that stable SDK build.

## 5. Failed Run Cleanup

The workflow performs best-effort cleanup if a run fails after creating a draft release or tag.

- If the release still exists as a draft, the workflow deletes the draft and its tag automatically.
- If the release was never created but the tag exists, the workflow deletes the orphan tag automatically.
- If cleanup itself fails, manual cleanup may still be required.

Manual cleanup commands:

```bash
gh release delete <tag> -R cypherair/cypherair --cleanup-tag --yes
git push origin ":refs/tags/<tag>"
```

For the App-side release ordering, including when a stable GitHub release must exist before an Xcode archive is allowed, see [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md).
