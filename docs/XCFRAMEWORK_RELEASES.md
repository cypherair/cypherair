# XCFramework Releases

> Purpose: Describe the current XCFramework distribution channel, how to discover and verify releases, and how future stable releases will differ.
> Audience: Human developers and automation that consume prebuilt `PgpMobile.xcframework` assets.

## Current Channel

CypherAir publishes a unique edge prerelease XCFramework from the current `main` branch for each successful edge release workflow run.

- Edge prerelease tags use the `pgpmobile-edge-` prefix.
- Tag format: `pgpmobile-edge-YYYYMMDDTHHMMSSZ-shortsha-rRUN_ID-aRUN_ATTEMPT`.
- This channel is updated automatically on every successful push to `main` and may be manually re-run from `main` only with the exact `pgpmobile-edge` prefix.
- It is intended for CI, integration, and manual validation of the current `main` tip.
- It is not treated as a stable SDK release.

The legacy rolling `pgpmobile-edge` tag/release is deprecated and removed during the migration to unique edge prereleases. Consumers must not use the fixed `pgpmobile-edge` tag.

Non-`main` manual validation must use a `pgpmobile-drill-*` prefix.

- Drill prerelease tags use the `pgpmobile-drill-*` prefix supplied to `workflow_dispatch`.
- Drill releases are branch- or ref-specific validation artifacts, not part of the canonical edge discovery channel.
- Drill releases publish `PgpMobile.xcframework.zip`, `PgpMobile.xcframework.sha256`, and `pgpmobile-drill.json`.
- Consumers must not discover or consume drill artifacts by scanning for the latest edge prerelease.

Each edge prerelease publishes exactly these assets:

- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
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
- `workflow_url`

This is intentional: a single app marketing version can have multiple Xcode build numbers during development, so XCFramework metadata must carry both values to identify the exact build instance that produced the binary.

## Downloading

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
    --pattern 'pgpmobile-edge.json'
```

Extract the XCFramework after verification:

```bash
ditto -x -k PgpMobile.xcframework.zip .
```

## Verification

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
```

Drill releases are verified using the exact ref-pinned command rendered in that release's notes. Do not reuse the canonical edge command for drill artifacts.

## Failed Run Cleanup

The workflow performs best-effort cleanup if a run fails after creating a draft release or tag.

- If the release still exists as a draft, the workflow deletes the draft and its tag automatically.
- If the release was never created but the tag exists, the workflow deletes the orphan tag automatically.
- If cleanup itself fails, manual cleanup may still be required.

Manual cleanup commands:

```bash
gh release delete <tag> -R cypherair/cypherair --cleanup-tag --yes
git push origin ":refs/tags/<tag>"
```

## Future Stable Releases

Future stable XCFramework releases are reserved for versioned tags of the form:

- `pgpmobile-vX.Y.Z-buildN`

Stable releases should:

- point to a fixed marketing-version + build-number pair instead of only a marketing version
- keep the same asset naming convention where practical
- publish release notes that describe compatibility and consumer expectations
- use immutable releases and release attestation verification
