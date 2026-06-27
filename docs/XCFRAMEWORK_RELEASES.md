# XCFramework Releases

> Status: Canonical current-state.
> Purpose: Describe the current edge, drill, and stable `PgpMobile.xcframework` release channels, including discovery, verification, and the stable channel's relationship to the unified app-build release page.
> Audience: Human developers and automation that consume prebuilt `PgpMobile.xcframework` assets.
> Source of truth: `.github/workflows/xcframework-edge-release.yml`, the Xcode Cloud release workflows ([XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md)), `.github/workflows/stable-release-attest.yml`, and published GitHub releases.
> Last reviewed: 2026-06-18.
> Update triggers: channel naming/routing, asset names, verification commands, stable asset contract, or relink-kit semantics.

## 1. Release Channels

### Edge Channel

CypherAir publishes a unique edge prerelease XCFramework from the current `main` branch for each successful edge release workflow run.

- Edge prerelease tags use the `pgpmobile-edge-` prefix.
- Tag format: `pgpmobile-edge-YYYYMMDDTHHMMSSZ-shortsha-rRUN_ID-aRUN_ATTEMPT`.
- This channel is updated automatically on every successful push to `main` and may be manually re-run from `main` only with the exact `pgpmobile-edge` prefix.
- Edge publication is gated on the Rust dependency audit; a failed audit prevents release/tag creation and asset publication.
- It is intended for CI, integration, and manual validation of the current `main` tip.
- It is not treated as a stable SDK release.

The legacy rolling `pgpmobile-edge` tag/release was removed when unique edge prereleases were introduced. Consumers must not use the fixed `pgpmobile-edge` tag.

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

CypherAir publishes stable XCFramework assets through the same unified stable GitHub release page used by formal app builds, built and published by Xcode Cloud (WF1 `PgpMobile XCFramework` → WF2 `CypherAir Release`; see [XCODE_CLOUD_RELEASE.md](XCODE_CLOUD_RELEASE.md)).

- The stable tag format, six-asset contract, binding rules, and immutability
  rules are defined in [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md)
  Section 2. The stable release page is the exact source and compliance landing
  page for both the tagged App build and the stable `PgpMobile.xcframework`
  assets.
- `PgpMobile.arm64e-build-manifest.json` records the Rust stage1 prerelease
  provenance, the resolved `openssl-src-rs` carry commit, the OpenSSL submodule
  commit, and the verified XCFramework slice layout.
- `PgpMobile-relink-kit.tar.zst` is a technical supplement for SDK consumers and relink-focused compliance review. It does not replace the shared source bundle and is not an in-app asset.
- Edge and drill prereleases remain separate from the stable channel.
- Provenance attestation for the stable SDK/compliance assets is produced by `.github/workflows/stable-release-attest.yml` on `release.published` (publication-witness semantics); verify it with the attestation command in Section 4.

### CI Cache Policy

CypherAir release and validation workflows intentionally avoid Cargo cache
actions. GitHub Actions downloads the pinned Rust fork stage1 prerelease recorded
in `docs/ARM64E_STATUS.md` in a dedicated pre-build step, then invokes
`./build-xcframework.sh --release` with the local `ARM64E_STAGE1_DIR` and
manifest path while GitHub token variables are absent from Cargo/build
subprocesses. Stage1 downloads use direct public `cypherair/rust` GitHub release
asset URLs for the pinned tag without `GH_TOKEN`, `GITHUB_TOKEN`, or anonymous
release API discovery, so checked-out workflow scripts never receive a token for
this download and do not depend on shared runner API quota. Caching Cargo
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

Drill releases are verified using the exact ref-pinned command rendered in that release's notes. The rendered command shell-quotes the source ref so it is safe to copy even for unusual branch names. Do not reuse the canonical edge command for drill artifacts.

## 4. Stable Release Retrieval

Stable releases are retrieved by their exact app-build tag:

```bash
TAG="cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>" # replace with the exact stable tag, e.g. cypherair-v1.3.6-build13601

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
gh attestation verify PgpMobile.xcframework.zip \
    -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/stable-release-attest.yml
gh attestation verify PgpMobile.arm64e-build-manifest.json \
    -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/stable-release-attest.yml
```

Use the source bundle, compliance manifest, and relink kit together when you need exact source-compliance materials for that stable SDK build.

SQLCipher is a separate formal external binary dependency. It is restored from
`cypherair/sqlcipher-xcframework` using
`third_party/sqlcipher-xcframework.pin.json`; CypherAir stable releases record
that pin in `CypherAir-compliance-manifest.json` but do not mirror
`SQLCipher.xcframework.zip`, SQLCipher release metadata, or upstream SQLCipher
source as CypherAir release assets.

## 5. Failed Run Cleanup

The Xcode Cloud release runs in two stages: WF1 creates the stable release as a draft, and WF2 publishes it after attaching the app binaries. If a run fails before WF2 publishes, the draft release (and sometimes the tag) can remain and requires manual cleanup.

- If the release still exists as a draft, delete the draft and its tag.
- If the tag exists but no release was created, delete the orphan tag.

Manual cleanup commands:

```bash
gh release delete <tag> -R cypherair/cypherair --cleanup-tag --yes
git push origin ":refs/tags/<tag>"
```

For the App-side release ordering, including when a stable GitHub release must exist before an Xcode archive is allowed, see [APP_RELEASE_PROCESS.md](APP_RELEASE_PROCESS.md).
