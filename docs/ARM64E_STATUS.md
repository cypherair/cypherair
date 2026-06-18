# CypherAir Apple arm64e Status

> Status: Canonical current-state — source of truth for Apple arm64e support.
> Purpose: Current arm64e toolchain chain, packaging posture, automation contract, and pinned stage1 consumption policy.
> Audience: Human developers, release owners, and AI coding tools.
> Update triggers: See "Update Rules" at the end of this file.
> Last reviewed: 2026-06-18.

## Repo Identity

- Primary app repository: `cypherair/cypherair`
- Remote repository: `cypherair/cypherair`
- Canonical app branch: `main`
- Apple `arm64e` app support landed on `main` through PR #222.
- Merge commit: `98e9e9fcdcc3760538b2b0e260a5daf52dc67c0e`
- The former app-side integration branch
  `codex/apple-arm64e-unified-experiment` is now historical/diagnostic context,
  not the canonical app branch.

## Mainline Support State

- CypherAir's app-side Apple `arm64e` support is present on `main`.
- `./build-xcframework.sh --release` is the official app-side build entrypoint.
  It delegates to `scripts/build_apple_arm64e_xcframework.sh`.
- Historical experiment scripts under `scripts/experiments/` were removed during
  Phase 1 legacy cleanup. The repo no longer carries a parallel experiment
  build entrypoint or local arm64e repro helper scripts.
- iOS, macOS, and visionOS device artifacts are packaged as dual
  `arm64` + `arm64e` slices because Apple distribution requires `arm64` whenever
  a shipped app bundle contains `arm64e`.
- iOS and visionOS simulator artifacts remain `arm64`.
- UniFFI bindgen uses an `arm64e-apple-darwin` host dylib.
- The build emits `PgpMobile.arm64e-build-manifest.json` with Rust stage1
  provenance, OpenSSL carry-chain commits, runner metadata, and verified
  XCFramework slice metadata.
- PR #222 run `24915498511` passed `rust-full-tests`, the formal
  `xcframework-package` build/probe path, and the hosted Swift preview job.
- Pre-merge release validation passed through edge drill run `24897042096` and
  stable dry-run `24897042109`. Post-merge main validation passed through edge
  run `24916588574` and stable dry-run `24916629353`.
- Current edge prereleases (`pgpmobile-edge-*`) and stable build releases
  (`cypherair-v*-build*`) are published on the repository's GitHub Releases
  page; consult it for the latest verified runs rather than this file.

## Current Verified Chain

- Rust toolchain contract:
  - the repo root intentionally has no `rust-toolchain.toml` custom override;
    ordinary local development and CI validation use explicit Rust official
    stable commands such as `cargo +stable`
  - Rust fork repository: `cypherair/rust`
  - Rust stage1 carry branch: `carry/cypherair-arm64e-toolchain-stable-1.96`
  - current Rust stage1 carry head: `abeb8459f2`
  - Rust stable base release: `1.96.0`
  - Rust stable base commit: `ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`
  - the former `carry/cypherair-arm64e-toolchain` line and its
    `rust-arm64e-stage1-*` prereleases are retained for diagnostics but are no
    longer the app's default stage1 consumption path
  - Rust upstream-prep branch:
    `prep/upstream-ready-arm64e-ptrauth-core-diagnostics-2026-04-24-u9836b06`
  - current Rust upstream-prep head: `77e2e3639785`
  - Rust downstream integration branch: `integration/arm64e-upstream-prs`
  - current Rust downstream integration head: `a9d110acd4fc`
  - `stage1-arm64e-patch` is an optional local rustup-linked stage1 compiler
    for Rust-fork development and diagnostics; it must include host
    `std`/`proc_macro` plus prebuilt std for arm64e Darwin, iOS, tvOS, and
    visionOS to be usable for app packaging
  - local app-side full packaging should use
    `ARM64E_STAGE1_FORCE_DOWNLOAD=1 ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-stable196-20260618T140657Z-abeb845-r27765229620-a1 ./build-xcframework.sh --release`
    so it consumes the same pinned `cypherair/rust` stage1 prerelease path as
    GitHub Actions instead of implicitly trusting local rustup-linked toolchain
    state
  - `ARM64E_RUSTC`, `ARM64E_STAGE1_DIR`, and `stage1-arm64e-patch` remain
    supported only when deliberately testing a local compiler build
  - GitHub-hosted PR, nightly, and edge workflows force-download the pinned Rust
    fork stage1 prerelease and record the resolved tag, commit, and checksums in
    `PgpMobile.arm64e-build-manifest.json`; the Xcode Cloud `PgpMobile XCFramework`
    workflow (WF1) does the same via `build_apple_arm64e_xcframework.sh`
  - GitHub-hosted Rust and XCFramework jobs intentionally do not use Cargo
    cache actions; clean CI builds avoid reusing `target/` artifacts produced
    by an older Rust fork stage1 compiler
  - arm64e builds call the patched compiler through explicit `RUSTC` while
    using stable Cargo with prebuilt std payloads; the official app path does
    not use nightly Cargo or `-Zbuild-std`
  - current pinned stage1 prerelease:
    `rust-arm64e-stage1-stable196-20260618T140657Z-abeb845-r27765229620-a1`
  - current pinned stage1 source ref:
    `refs/heads/carry/cypherair-arm64e-toolchain-stable-1.96`
  - current pinned stage1 source commit:
    `abeb8459f2b459704c1d698c01d8b8c0df8ffffd`
  - current pinned stage1 workflow run: `27765229620`
  - current pinned stage1 manifest declares `stableBaseRelease: "1.96.0"`,
    `stableBaseCommit: "ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96"`,
    `requiresBuildStd: false`, `asset.purpose: "rust-stage1-for-arm64e"`,
    a host-specific `hostTriple`/`includedHostStdTarget`, and Apple arm64e std
    targets for Darwin, iOS, tvOS, and visionOS. The prerelease publishes
    separate `rust-stage1-for-arm64e-aarch64-apple-darwin.*` and
    `rust-stage1-for-arm64e-x86_64-apple-darwin.*` asset sets; app-side
    downloaders must select the asset matching the build host.
  - when publishing a new official stage1 prerelease, update every pinned-tag
    location in the same PR: the GitHub Actions workflow env values, the script
    default, the workflow hardening tests, this file (the pin lines above and
    the local packaging command), `CLAUDE.md` Build Commands, `AGENTS.md` Build
    And Validation, and `docs/TESTING.md` Section 2.4 workflow C; `latest` is
    not allowed in the CI/default download path (agent checklist:
    `.claude/skills/repin-arm64e`)
  - latest hosted LLVM-workaround-shrink validation force-downloaded the
    prerelease above and recorded the same source and checked-out commit in
    `PgpMobile.arm64e-build-manifest.json`
- XCFramework packaging posture:
  - iOS/macOS/visionOS device artifacts are merged from stable `arm64` and
    patched `arm64e` archives
  - iOS/visionOS simulator artifacts remain stable `arm64`
  - UniFFI bindgen continues to use an `arm64e-apple-darwin` host dylib
  - app-side release workflows publish `PgpMobile.arm64e-build-manifest.json`
    with Rust stage1 provenance, OpenSSL carry-chain commits, and verified
    XCFramework slice metadata
- OpenSSL source carry:
  - `pgp-mobile/Cargo.toml` patches `openssl-src` to
    `https://github.com/cypherair/openssl-src-rs`
  - tracked downstream branch line: `carry/apple-arm64e-openssl-fork`
  - current resolved branch head: `32b278bf9317`
  - `pgp-mobile/Cargo.lock` records the resolved git commit for repeatable
    local builds, while `Cargo.toml` intentionally tracks the carry branch
- OpenSSL target-definition carry:
  - the `openssl-src-rs` carry branch is expected to point at the CypherAir
    OpenSSL fork
  - intended downstream branch line: `carry/apple-arm64e-targets`
  - current carry branch head: `d228bf84e32e`
  - current `openssl-src-rs` submodule pointer: `d228bf84e32e`

## Automation Posture

- `cypherair/rust`:
  - `arm64e-stage1-prerelease.yml` validates the stable196 stage1 carry branch,
    builds the patched stage1 compiler, host `std`/`proc_macro`, and arm64e
    Apple std payloads, smoke-tests the packaged toolchain with
    `cargo +stable`, and publishes host-specific
    `rust-stage1-for-arm64e-<host-triple>.*` prerelease assets for app CI
  - `arm64e-upstream-sync-prep.yml` performs manual upstream-sync dry-runs and
    can open a refresh PR without force-pushing the integration branch
- `cypherair/cypherair`:
  - PR, nightly, and edge workflows call the official arm64e
    `./build-xcframework.sh --release` path; the Xcode Cloud `PgpMobile
    XCFramework` workflow (WF1) calls it too
  - no active workflow or script path depends on the removed
    `scripts/experiments/` diagnostics
  - ordinary Rust validation and release metadata use explicit `+stable`
    commands; arm64e never depends on a repo-wide rustup override
  - hosted Rust and XCFramework workflows deliberately avoid Cargo cache
    actions after the May 2026 stale-cache incident where an old `target/`
    cache mixed with a newer stage1 prerelease and broke `rustversion`
    proc-macro resolution during `generic-array` builds
  - edge and stable releases include `PgpMobile.arm64e-build-manifest.json`
  - stable compliance assets embed the arm64e manifest and the relink kit covers
    both stable `arm64` and patched `arm64e` target archives
  - formal stable releases are tag-first: the stable tag must exist on the
    intended `main` commit before the immutable GitHub release is published
  - App Store candidate validation requires the stable release to include a
    valid arm64e manifest before archiving is allowed
  - the hosted macOS Swift unit-test preview requires an `arm64e` macOS
    destination and runs `CypherAir-UnitTests` on `platform=macOS,arch=arm64e`;
    readiness preflight and warn-skip semantics live in `docs/TESTING.md`
    Section 2.2
- `cypherair/openssl-src-rs`:
  - `arm64e-carry-chain.yml` checks that the OpenSSL submodule URL, branch, and
    pointer stay aligned with `cypherair/openssl:carry/apple-arm64e-targets`,
    then packages and tests the crate

## Related Forks And Repositories

- App repository:
  - remote `cypherair/cypherair`
  - canonical branch: `main`
- Rust fork:
  - remote `cypherair/rust`
  - stage1 carry branch: `carry/cypherair-arm64e-toolchain-stable-1.96`
  - downstream integration branch: `integration/arm64e-upstream-prs`
  - upstream-prep branch:
    `prep/upstream-ready-arm64e-ptrauth-core-diagnostics-2026-04-24-u9836b06`
- OpenSSL fork:
  - remote `cypherair/openssl`
  - carry branch `carry/apple-arm64e-targets`
  - prep branch `prep/apple-arm64e-targets`
- openssl-src-rs fork:
  - remote `cypherair/openssl-src-rs`
  - carry branch `carry/apple-arm64e-openssl-fork`

## Upstreaming Posture

- The upstream-facing Rust work has been split into ready PRs against
  `rust-lang/rust`, with the CypherAir fork integration branch kept as the
  downstream validation stack until upstream review lands or reshapes it.
- The OpenSSL and `openssl-src-rs` branches remain downstream carry branches
  until equivalent Apple `arm64e` target support lands upstream.
- App-side documentation should record the current dependency chain and current
  level of app-side functionality without implying the OpenSSL carry chain is
  upstreamed.

## Historical: LLVM Workaround-Shrink Validation (2026-05-03)

This dated record predates the current stable196 stage1 pin and consumed the
deprecated `carry/cypherair-arm64e-toolchain` line; it is retained as evidence
only.

- Date: 2026-05-03.
- Local app validation: `cypherair/cypherair` branch `main`, commit
  `ea37581`.
- GitHub-hosted app validation: `cypherair/cypherair` branch `main`, commit
  `b50b211`.
- Rust carry validation source: `cypherair/rust` branch
  `carry/cypherair-arm64e-toolchain`, commit `b402b926a05`, which keeps
  Rust-side ptrauth cleanup only for `callbr` and no longer strips direct
  function calls carrying `"ptrauth"` operand bundles.
- Rust-consumed LLVM source:
  `cypherair-llvm-from-rust-lang-integration` branch
  `cypherair-arm64e-ptrauth-rust-llvm`, commit `18a66001b`.
- Hosted Rust stage1 prerelease:
  `rust-arm64e-stage1-20260503T220008Z-b402b92-r25291584825-a1`, published by
  workflow run `25291584825` from source and checked-out commit
  `b402b926a05317680538f34e5d06495572b8b3cf`.
- Hosted-prerelease command:
  - `env ARM64E_STAGE1_FORCE_DOWNLOAD=1
    ARM64E_STAGE1_RELEASE_TAG=rust-arm64e-stage1-20260503T220008Z-b402b92-r25291584825-a1
    ARM64E_DEPENDENCY_FRESHNESS_LEVEL=warn ./build-xcframework.sh --release`
- Result: passed. The build produced `PgpMobile.xcframework` and
  `PgpMobile.arm64e-build-manifest.json`; the manifest reports
  `xcframework.requiredSlicesPresent: true`, fresh OpenSSL carry-chain
  dependencies, and hosted stage1 provenance for the prerelease above.
- Verified slices:
  - iOS device: `arm64 arm64e`
  - macOS: `arm64 arm64e`
  - visionOS device: `arm64 arm64e`
  - iOS simulator: `arm64`
  - visionOS simulator: `arm64`
- Generated UniFFI Swift/header files were unchanged in the tracked worktree.
- GitHub-hosted `XCFramework Edge Release` run `25292443961` passed and
  published
  `pgpmobile-edge-20260503T222049Z-b50b211-r25292443961-a1`. The published
  `PgpMobile.arm64e-build-manifest.json` records Rust stage1 tag
  `rust-arm64e-stage1-20260503T220008Z-b402b92-r25291584825-a1`, source and
  checked-out commit `b402b926a05317680538f34e5d06495572b8b3cf`, freshness
  level `error` with `isFresh: true`, and all required XCFramework slices.
- GitHub-hosted `PR Checks` run `25292443966` passed `rust-full-tests` and
  `xcframework-package`. At that point the overall workflow conclusion was
  failure only because `swift-unit-tests-hosted-preview` ran on hosted macOS
  26.3 while `CypherAirTests` required a newer macOS deployment target; current
  workflows preflight that hosted environment mismatch and skip the preview with
  a warning. Hosted Swift unit-test preview now targets `arm64e`; missing Mac
  App Development provisioning profiles remain regular CI failures until CI
  signing is configured.

## Update Rules

Update this file whenever any of the following changes:

- the explicit Rust stage1 toolchain contract, local linked toolchain name, or
  remote stage1 prerelease consumption policy
- the `pgp-mobile/Cargo.toml` `openssl-src` patch target, branch, or lockfile
  policy
- the role of `openssl` or `openssl-src-rs` in the chain
- the app-side arm64e readiness status
- the Rust stage1 prerelease workflow contract or arm64e release manifest shape
- the edge, drill, stable release, or App Store candidate validation contract
