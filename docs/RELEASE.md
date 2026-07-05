# Release

> Status: Canonical current-state.
> Purpose: The one release document — app-build stable releases, the Xcode Cloud flow, the asset contract, and the `PgpMobile.xcframework` SDK channels.
> Audience: Release owners and AI coding tools.
> Source of truth: `CypherAir` / `CypherAir AppStore Candidate` schemes, the Xcode Cloud `PgpMobile XCFramework` + `CypherAir Release` workflows, `.github/workflows/*.yml`, and [ARM64E_STATUS.md](ARM64E_STATUS.md) (stage1 pin).
> Update triggers: tag rules, asset names, workflow behavior, version-bump policy, or XCFramework channel changes.

## 1. Versioning

Stable releases are identified by the exact Xcode project build settings:

- `MARKETING_VERSION` → `CFBundleShortVersionString` (the user-facing version, e.g. `1.5.0`).
- `CURRENT_PROJECT_VERSION` → `CFBundleVersion` (the build number, e.g. `15000`). The convention in this project encodes the marketing version (`1.5.0` → `15000`); for macOS App Store uploads it must be strictly higher than the highest macOS build previously uploaded, even when the marketing version increases.

Set both in the project before tagging. Bumping the version is a normal, in-scope part of preparing a release — read the current values, choose the next pair, and commit them. Confirm the intended version with the maintainer before creating the release tag itself (below), since publishing is outward-facing.

## 2. Stable release flow (tag-first, Xcode Cloud)

Releases are **tag-first**: pushing the SSH-signed stable tag is the trigger. Two Xcode Cloud workflows then own the release end to end.

1. Land the release commit on `main` (final code + the version bump).
2. Confirm the pinned arm64e stage1 tag in [ARM64E_STATUS.md](ARM64E_STATUS.md) is the intended stage1 input; re-pin first (`.claude/skills/repin-arm64e`) in a normal PR if a newer fork is needed.
3. Create the SSH-signed annotated stable tag on that commit and push it:

   ```bash
   TAG="cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>"   # e.g. cypherair-v1.5.0-build15000
   git -c gpg.format=ssh tag -s -m "$TAG" "$TAG" "$(git rev-parse main)"
   git tag -v "$TAG"        # verify the signature locally
   git push origin "$TAG"   # this push triggers WF1
   ```

   Lightweight or unsigned stable tags are not allowed. Never treat a `workflow_dispatch` as a substitute for the signed tag. Ask the maintainer before pushing any release tag.

4. **WF1 — `PgpMobile XCFramework`** (start condition: tag `cypherair-v*-build*`): audits Rust dependencies (`cargo audit --deny warnings`), builds the arm64e `PgpMobile.xcframework` from source using the pinned stage1, restores the pinned SQLCipher dependency with mandatory attestation verification, packages the six SDK/compliance assets, records the SQLCipher pin in the compliance manifest, creates the stable GitHub Release as a **draft**, and starts WF2 via the App Store Connect API.
5. **WF2 — `CypherAir Release`** (start condition: manual/API only — started by WF1): downloads and `shasum`-verifies the exact XCFramework from the draft, re-restores SQLCipher with attestation, runs the App Store candidate validator, archives iOS / macOS / visionOS with cloud-managed signing, delivers to TestFlight (internal), attaches the App Store upload artifacts, and **publishes** the draft once all platform artifacts are present.
6. **`stable-release-attest.yml`** runs on `release.published`: re-verifies the signed tag and the XCFramework checksum, then generates the provenance attestation over the published assets.
7. Confirm the release page, assets, and TestFlight builds; submit for App Store review manually in App Store Connect when ready.

The Xcode Cloud scripts branch on `$CI_WORKFLOW`, so the workflow names must match exactly (`PgpMobile XCFramework`, `CypherAir Release`) or be overridden via `XCFRAMEWORK_WORKFLOW_NAME` / `RELEASE_WORKFLOW_NAME`. Setup/credential details for standing up the two workflows live in the workflow Environment configuration in App Store Connect (fine-grained `GITHUB_PAT`, the `ASC_*` App Store Connect API key, and `XCODE_CLOUD_RELEASE_WORKFLOW_ID`); the arm64e stage1 pin stays repo-controlled via `DEFAULT_ARM64E_STAGE1_RELEASE_TAG` in `scripts/build_apple_arm64e_xcframework.sh`, not an env var.

**Break-glass (Xcode Cloud unavailable):** after a stable release for the tag exists, archive `CypherAir AppStore Candidate` locally on a non-beta macOS and upload via Transporter. The scheme's local pre-action enforces the same candidate validation (`scripts/validate_app_store_candidate_release.py`): current branch `main`, clean worktree/index, the GitHub stable release exists, `PgpMobile.arm64e-build-manifest.json` validates, and the restored SQLCipher matches `third_party/sqlcipher-xcframework.pin.json`. Do not archive before the stable release exists.

## 3. Stable asset contract

Every published stable release includes these SDK/compliance assets (built from the tagged commit by WF1; immutable once published):

- `CypherAir-source-bundle.tar.zst`
- `CypherAir-compliance-manifest.json` (records the pinned SQLCipher external dependency)
- `PgpMobile.xcframework.zip`
- `PgpMobile.xcframework.sha256`
- `PgpMobile.arm64e-build-manifest.json`
- `PgpMobile-relink-kit.tar.zst`

Plus the App Store upload artifacts (App-Store-signed Transporter payloads — for upload only, **not** directly installable, and not notarized; the Mac App Store build is Apple-reviewed, so there is no Developer ID / notarization step): `CypherAir-iOS-AppStore.ipa`, `CypherAir-visionOS-AppStore.ipa`, `CypherAir-macOS-AppStore.pkg`.

Immutability: WF1 fixes the SDK/compliance asset set when it creates the draft; WF2 only adds the app `.ipa`/`.pkg` and flips the draft to published, so "published" is atomic. A retry skips an already-present asset only when the digest matches; a same-name different-digest asset fails. If an asset set is wrong, fix it with a new build number, new stable tag, and new release — never replace assets in place. Stable assets bind to one exact marketing version, build number, release tag, and commit SHA; App Store candidate archives embed the exact stable release tag, URL, and commit SHA in `SourceComplianceInfo.json`.

## 4. Internal / experimental TestFlight

For day-to-day and exploratory uploads that are **not** the formal App Store candidate: archive the standard `CypherAir` scheme locally on a non-beta macOS and upload to TestFlight. No GitHub stable release is required; `Source & Compliance` may show no exact stable release URL. This build is not the formal candidate.

## 5. PgpMobile.xcframework SDK channels

The `PgpMobile.xcframework` binary is published on three channels for downstream SDK consumers:

- **Edge** — every push to `main` via `xcframework-edge-release.yml`, tag `pgpmobile-edge-<timestamp>-<sha>-<run>-a<attempt>`. Continuous validation channel; discovered by timestamp/sha.
- **Drill** — manual `workflow_dispatch` validation runs from non-`main` refs, tag prefix `pgpmobile-drill-*`. Never discovered or consumed as if it were edge.
- **Stable** — the `PgpMobile.xcframework.zip` + `.sha256` attached to each app stable release (§3), built by WF1 from the tagged commit. This is the release-grade binary.

CI caches the edge artifact (`pgpmobile-xcframework`) within a run so downstream jobs restore the exact build product on a clean runner.

**Verification** — download `PgpMobile.xcframework.zip` and its `.sha256`, confirm `shasum -a 256 -c`, then verify provenance against the workflow that attested the channel:

```bash
# Edge (attested in-run by the edge workflow):
gh attestation verify PgpMobile.xcframework.zip -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/xcframework-edge-release.yml \
    --source-ref refs/heads/main

# Stable (attested on release.published):
gh attestation verify PgpMobile.xcframework.zip -R cypherair/cypherair \
    --signer-workflow cypherair/cypherair/.github/workflows/stable-release-attest.yml
```

The same commands verify `PgpMobile.arm64e-build-manifest.json`. SQLCipher is verified separately by `scripts/restore_sqlcipher_xcframework.sh --require-attestation` against `third_party/sqlcipher-xcframework.pin.json`.

## 6. Candidate verification checklist

Before promoting an App Store candidate, confirm: the version/build pair is final; the macOS build number is higher than any previously uploaded macOS build; the stable tag matches the app version/build and is SSH-signed; the arm64e stage1 pin is the intended input; WF1→WF2 completed and published; WF1's `cargo audit` passed; the release page has all six SDK/compliance assets plus the three App Store artifacts; `stable-release-attest.yml` completed and `gh attestation verify` passes; the archive was built from `CypherAir AppStore Candidate`. After the build reaches TestFlight, confirm in-app `About → Source & Compliance` shows the expected version/build, commit SHA, and stable tag/URL.
