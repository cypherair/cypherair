# Xcode Cloud Release Flow (Setup & Migration)

> Status: Canonical — setup and operations guide for the Xcode Cloud release path.
> Purpose: Stand up the two Xcode Cloud workflows that build, sign, deliver, and
> publish CypherAir releases, and define the cutover from the GitHub Actions
> stable-build path.
> Audience: Release owners.
> Source of truth for the asset contract and tag rules: docs/APP_RELEASE_PROCESS.md
> (Section 2) and docs/ARM64E_STATUS.md (stage1 pin). This document does not
> redefine those; it describes the Xcode Cloud execution of the same contract.
> Last reviewed: 2026-06-18.

The legacy GitHub Actions stable build/publish workflow has been retired;
`.github/workflows/stable-release-attest.yml` now provides post-publish
provenance attestation. Xcode Cloud is the release path.

## 1. Overview

Releases stay tag-first: a human pushes the SSH-signed
`cypherair-v<MARKETING_VERSION>-build<CURRENT_PROJECT_VERSION>` tag (ask-first per
CLAUDE.md). Two Xcode Cloud workflows then own the release end to end:

| Workflow | Start condition | What it does |
|---|---|---|
| **PgpMobile XCFramework** (WF1) | Tag `cypherair-v*-build*` | `ci_post_clone.sh` builds the arm64e `PgpMobile.xcframework` from source (audit + freshness gated); the build action probes that the app links it; `ci_post_xcodebuild.sh` packages the six SDK/compliance assets, creates the stable GitHub Release as a **draft**, and starts WF2 for the same tag via the App Store Connect API. |
| **CypherAir Release** (WF2) | **Manual / API only** (started by WF1) | `ci_post_clone.sh` downloads + checksum-verifies the exact xcframework from the draft release and runs the App Store candidate gate; Archive actions build iOS / macOS / visionOS with cloud signing and deliver to TestFlight; `ci_post_xcodebuild.sh` attaches the App Store upload `.ipa`/`.pkg` (`CypherAir-*-AppStore.*`, Transporter payloads) to the release and **publishes** the draft once all platform artifacts are present. |

A lean GitHub Actions job (`stable-release-attest.yml`, added at cutover) runs on
`release.published` to attest the published assets, restoring
`gh attestation verify`.

The repo-side machinery already in place:
- `ci_scripts/ci_post_clone.sh`, `ci_scripts/ci_pre_xcodebuild.sh`, `ci_scripts/ci_post_xcodebuild.sh`
- `scripts/asc_start_build.py` (WF1 → WF2 trigger via `ciBuildRuns`)
- `scripts/validate_app_store_candidate_release.py` (Xcode Cloud detached-HEAD aware)
- `scripts/generate_source_compliance_build_phase.sh` (derives in-app compliance from `CI_TAG`/`CI_COMMIT`)

The scripts branch on `$CI_WORKFLOW`, so the workflow **names must match exactly**
(`PgpMobile XCFramework` and `CypherAir Release`) or be overridden via the
`XCFRAMEWORK_WORKFLOW_NAME` / `RELEASE_WORKFLOW_NAME` environment variables.

## 2. Credentials & environment variables

Configure these in App Store Connect → Xcode Cloud workflow **Environment**
(mark every secret as **Secret**).

WF1 (PgpMobile XCFramework):
- `GITHUB_PAT` *(secret)* — fine-grained PAT with `contents: write` on `cypherair/cypherair` (create the draft release).
- `ASC_ISSUER_ID`, `ASC_KEY_ID` *(secret)*, `ASC_PRIVATE_KEY` *(secret, the `.p8` contents)* — App Store Connect API key to start WF2.
- `XCODE_CLOUD_RELEASE_WORKFLOW_ID` — WF2's workflow id (from its App Store Connect URL).
- `ARM64E_DEPENDENCY_FRESHNESS_LEVEL` — `error` (recommended).

WF2 (CypherAir Release):
- `GITHUB_PAT` *(secret)* — same PAT (download draft assets, attach binaries, publish).
- `XCODE_CLOUD_RELEASE_ARTIFACTS` *(optional)* — defaults to `CypherAir-iOS-AppStore.ipa CypherAir-visionOS-AppStore.ipa CypherAir-macOS-AppStore.pkg`; the draft publishes only once all listed artifacts are attached.

The arm64e stage1 pin is **not** an Xcode Cloud env var: it stays repo-controlled
via `DEFAULT_ARM64E_STAGE1_RELEASE_TAG` in `scripts/build_apple_arm64e_xcframework.sh`
(WF1 runs `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ./build-xcframework.sh --release`). Re-pin
with `.claude/skills/repin-arm64e` as usual.

## 3. App Store Connect signing & app records

- Grant Xcode Cloud **cloud-managed signing** when connecting the workflows (no manual cert upload). The project already uses `CODE_SIGN_STYLE = Automatic`.
- Confirm App Store Connect app records exist for **iOS, macOS, and visionOS** under the single distribution team, and that the app target's `DEVELOPMENT_TEAM` is that team in every config WF2 archives (see Step 5 — the project currently mixes `7P9PPXP2SF` and `Y2ZPV6SKBT`).

## 4. Create WF1 — "PgpMobile XCFramework"

1. New workflow, name exactly `PgpMobile XCFramework`.
2. Start condition: **Tag Changes**, pattern `cypherair-v*-build*`.
3. Action: **Build**, scheme `CypherAir`, platform iOS (a compile-only link probe; signing not required).
4. Environment: set the WF1 variables from Section 2; select the release Xcode/macOS.
5. No post-actions (the GitHub release + WF2 trigger happen in `ci_post_xcodebuild.sh`).

## 5. Create WF2 — "CypherAir Release"

1. New workflow, name exactly `CypherAir Release`.
2. Start condition: **none** (manual / API only — WF1 starts it). Do **not** add a tag condition, or it will race WF1.
3. Actions: three **Archive** actions — iOS, macOS, visionOS — scheme `CypherAir AppStore Candidate`, Deployment Preparation **TestFlight & App Store**.
4. Post-actions: **TestFlight Internal Testing** for each platform's archive artifact. Do **not** add a macOS **notarization** post-action or a **Developer ID** archive action (see §8 — the macOS asset is an App Store package, reviewed by Apple, not notarized).
5. Enable **Restrict Editing** (required for external-testing delivery later).
6. Environment: set the WF2 variables from Section 2.
7. Reconcile `DEVELOPMENT_TEAM` to the single distribution team across the archived configs and resolve the stray `Y2ZPV6SKBT` configs in `CypherAir.xcodeproj/project.pbxproj` (security-sensitive pbxproj edit — itemize for review).

## 6. Cutover (completed 2026-06-18)

The legacy GitHub Actions stable build/publish workflow has been retired. The cutover PR made these changes:
1. Replace `.github/workflows/stable-build-release.yml` with `stable-release-attest.yml` (`on: release.published`, tag `cypherair-v*-build*`): re-verify the signed tag + asset checksums and run `actions/attest-build-provenance` over the published assets.
2. Update `scripts/tests/test_workflow_security_hardening.py`: drop `stable-build-release.yml` from `workflows_with_xcframework_build`; replace the two stable-publish tests with assertions for the attest workflow.
3. Update `docs/XCFRAMEWORK_RELEASES.md` verify commands to `--signer-workflow .../stable-release-attest.yml` (attestation is now a publication witness, not in-process build provenance — note this).
4. Update `docs/APP_RELEASE_PROCESS.md`, `docs/ARM64E_STATUS.md`, and `.claude/skills/release-stable/SKILL.md` to the tag → WF1 → WF2 → attestation choreography.
5. Leave `xcframework-edge-release.yml`, `nightly-full.yml`, `pr-checks.yml` unchanged (CI / edge-SDK validation channels).

## 7. Verification

- **Dry run** on a throwaway tag against a test app record: confirm WF1 builds the xcframework (watch for the `ci_post_clone` heartbeat; total < 120 min), creates the draft, and triggers WF2; confirm WF2 downloads + `shasum -c` the xcframework, archives 3 platforms, delivers TestFlight, attaches `.ipa`/`.pkg`, and publishes the draft.
- **In-app compliance:** install a TestFlight build → About → Source & Compliance shows the expected version/build, commit SHA, and stable tag/URL.
- **Attestation:** `gh attestation verify PgpMobile.xcframework.zip -R cypherair/cypherair --signer-workflow .../stable-release-attest.yml`.
- **Local break-glass** still works: the candidate scheme/validator behave unchanged off Xcode Cloud (covered by `scripts/tests/test_validate_app_store_candidate_release.py`).

## 8. Notes & risks

- **120-min cap / 30-min inactivity:** the heavy Rust build lives in WF1 alone (no archive); `ci_post_clone.sh` emits a heartbeat. If WF1 ever exceeds budget, fall back to having GitHub Actions build the attested xcframework and WF2 consume it.
- **Immutability:** the SDK/compliance asset set is fixed when WF1 creates the draft; WF2 only adds the app `.ipa`/`.pkg` and flips the draft to published. If a run fails mid-way, delete the draft + tag and re-release with a new build number.
- **Compute hours:** each release spends ~1 compute-hour on the clean Rust build; releases are infrequent.
- **macOS artifact is App Store, not notarized:** the attached `CypherAir-macOS-AppStore.pkg` (and the `CypherAir-*-AppStore.ipa`s) come from `CI_APP_STORE_SIGNED_APP_PATH` — App-Store-signed payloads for **upload to App Store Connect via Transporter only**. They are **not directly installable** (double-clicking gives "unidentified developer") and **cannot be notarized**: notarization is exclusively for *Developer ID* builds distributed outside the App Store, whereas Apple reviews App Store builds. CypherAir ships through the Mac App Store (consistent with iOS/visionOS, which can only ship via the App Store), so there is no Developer ID / notarization step. If you ever need a directly-installable macOS download, that is a separate Developer ID distribution channel (a distinct Archive action; note Xcode Cloud's post-build environment has no signing identities, so a notarized `.pkg` is hard to produce there).
