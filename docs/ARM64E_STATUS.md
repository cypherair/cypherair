# CypherAir Apple arm64e Status

Snapshot date: 2026-04-24

## Repo Identity

- Primary local main worktree: `/Users/tianren/coding/cypherair-main`
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
  After the build-14 release-prep update, the hosted Swift preview is again a
  blocking signal: if GitHub-hosted macOS lags the app's deployment target, the
  PR check can show a red X until the runner image catches up or the workflow
  moves to a self-hosted macOS runner.
- Pre-merge release validation passed through edge drill run `24897042096` and
  stable dry-run `24897042109`. Post-merge main validation also passed through
  edge run `24916588574` and stable dry-run `24916629353`.

## Current Verified Chain

- Rust toolchain contract:
  - the repo root intentionally has no `rust-toolchain.toml` custom override;
    ordinary local development and CI validation use explicit Rust official
    stable commands such as `cargo +stable`
  - local Rust fork path: `/Users/tianren/coding/rust`
  - Rust integration branch:
    `codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`
  - current Rust integration head: `02240c72a377`
  - `stage1-arm64e-patch` is an optional local rustup-linked stage1 compiler,
    rebuilt from that Rust branch with host `std`/`proc_macro` plus the arm64e
    Darwin std payload
  - local full packaging uses `ARM64E_RUSTC` or `ARM64E_STAGE1_DIR` when
    supplied, then the locally linked `stage1-arm64e-patch` toolchain when
    present, and otherwise downloads the Rust fork prerelease
  - GitHub-hosted PR, nightly, edge, and stable release workflows force-download
    the Rust fork stage1 prerelease and record the resolved tag, commit, and
    checksums in `PgpMobile.arm64e-build-manifest.json`
  - arm64e builds call the patched compiler through explicit `RUSTC` while
    using nightly Cargo as the driver for `-Zbuild-std`
  - latest verified stage1 prerelease:
    `rust-arm64e-stage1-20260424T150813Z-02240c7-r24895825853-a1`; its manifest
    declares `includedRustSrc: true` so GitHub-hosted app builds can run
    `cargo -Zbuild-std` without relying on a runner-local Rust source tree
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
  - `arm64e-stage1-prerelease.yml` validates the integration branch, builds the
    patched stage1 compiler, host `std`/`proc_macro`, and
    `arm64e-apple-darwin` std, smoke-tests the packaged toolchain, and publishes
    a prerelease asset for app CI
  - `arm64e-upstream-sync-prep.yml` performs manual upstream-sync dry-runs and
    can open a refresh PR without force-pushing the integration branch
- `cypherair/cypherair`:
  - PR, nightly, edge, and stable workflows call the official arm64e
    `./build-xcframework.sh --release` path
  - ordinary Rust validation and release metadata use explicit `+stable`
    commands; arm64e never depends on a repo-wide rustup override
  - edge and stable releases include `PgpMobile.arm64e-build-manifest.json`
  - stable compliance assets embed the arm64e manifest and the relink kit covers
    both stable `arm64` and patched `arm64e` target archives
  - App Store candidate validation requires the stable release to include a
    valid arm64e manifest before archiving is allowed
  - hosted macOS Swift unit-test preview is blocking again for release
    readiness, so a hosted runner image below the app deployment target will
    fail visibly until GitHub updates the image or the workflow uses a
    self-hosted macOS runner
- `cypherair/openssl-src-rs`:
  - `arm64e-carry-chain.yml` checks that the OpenSSL submodule URL, branch, and
    pointer stay aligned with `cypherair/openssl:carry/apple-arm64e-targets`,
    then packages and tests the crate

## Related Forks And Paths

- App repo main worktree:
  - `/Users/tianren/coding/cypherair-main`
- Rust fork:
  - `/Users/tianren/coding/rust`
  - remote `cypherair/rust`
  - integration branch:
    `codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`
- OpenSSL fork:
  - `/Users/tianren/coding/openssl`
  - remote `cypherair/openssl`
  - carry branch `carry/apple-arm64e-targets`
  - prep branch `prep/apple-arm64e-targets`
- openssl-src-rs fork:
  - `/Users/tianren/coding/openssl-src-rs`
  - remote `cypherair/openssl-src-rs`
  - carry branch `carry/apple-arm64e-openssl-fork`
- Related but currently unconfirmed in the active chain:
  - `/Users/tianren/coding/rust-openssl`
  - remote `cypherair/rust-openssl`

## Upstreaming Posture

- The upstream-facing Rust work has been split into ready PRs against
  `rust-lang/rust`, with the CypherAir fork integration branch kept as the
  downstream validation stack until upstream review lands or reshapes it.
- The OpenSSL and `openssl-src-rs` branches remain downstream carry branches
  until equivalent Apple `arm64e` target support lands upstream.
- App-side documentation should record the current dependency chain and current
  level of app-side functionality without implying the OpenSSL carry chain is
  upstreamed.

## Update Rules

Update this file whenever any of the following changes:

- the explicit Rust stage1 toolchain contract, local linked toolchain name, or
  remote stage1 prerelease consumption policy
- the `pgp-mobile/Cargo.toml` `openssl-src` patch target, branch, or lockfile
  policy
- the role of `openssl`, `openssl-src-rs`, or `rust-openssl` in the chain
- the app-side arm64e readiness status
- the Rust stage1 prerelease workflow contract or arm64e release manifest shape
- the edge, drill, stable release, or App Store candidate validation contract
