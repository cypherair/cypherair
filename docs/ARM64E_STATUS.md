# CypherAir Apple arm64e Status

Snapshot date: 2026-04-24

## Repo Identity

- Local path: `/Users/tianren/coding/cypherair-apple-arm64e-unified-experiment`
- Git form: worktree owned by `/Users/tianren/coding/cypherair-main`
- Owning repository local main branch: `main`
- This worktree's local branch: `codex/apple-arm64e-unified-experiment`
- Remote repository: `cypherair/cypherair`
- Relevant remote branches:
  - `origin/main`
  - `origin/codex/apple-arm64e-unified-experiment`

## Role In The arm64e Chain

This worktree is the app-side integration point for the Apple `arm64e` effort.
It is where the CypherAir app consumes the patched Rust toolchain and the
OpenSSL carry chain, packages `PgpMobile.xcframework`, and validates that the
full dependency chain is usable by the app.

## Current Progress

- The app-side Apple `arm64e` adaptation builds and passes the unit-test path
  in this worktree with the patched Rust stage1 toolchain.
- The experiment branch contains branch-local build helpers, a patched Rust
  toolchain pin, and a reproducible vendored OpenSSL carry chain.
- Apple distribution rules require `arm64` whenever a shipped app bundle also
  contains `arm64e`, so the experiment output must now package dual device
  slices (`arm64` + `arm64e`) while keeping simulator slices on `arm64`.
- The experiment still keeps `arm64e` as a first-class validation path by
  generating UniFFI bindings from an `arm64e-apple-darwin` host dylib and by
  building explicit `arm64e` device archives before they are merged with the
  stable `arm64` device archives.
- The build and release infrastructure now has a formal arm64e path:
  `./build-xcframework.sh --release` is the official app-side entrypoint, and
  it emits `PgpMobile.arm64e-build-manifest.json` alongside the XCFramework.
- The remaining work is no longer "can CypherAir run with arm64e at all?".
  The remaining work is validating the new release automation end to end before
  merging the app experiment branch into `main`, then continuing upstream work.

## Current Verified Chain

- Rust toolchain pin:
  - `rust-toolchain.toml` points to `stage1-arm64e-patch`
  - local Rust fork path: `/Users/tianren/coding/rust`
  - Rust experiment branch: `codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`
  - current branch head: `9a76bf1a7524`
  - `stage1-arm64e-patch` is a local rustup-linked stage1 compiler, rebuilt
    from that Rust branch with host `std`/`proc_macro` plus the arm64e Darwin
    std payload; Cargo calls it through `RUSTC` while using nightly Cargo as
    the driver for `-Zbuild-std` arm64e builds
  - the Rust fork now has an `arm64e Stage1 Prerelease` workflow that publishes
    `rust-arm64e-stage1-*` prereleases containing a minimal stage1 toolchain,
    checksums, provenance JSON, diagnostics, and artifact attestations
- XCFramework packaging posture:
  - iOS/macOS/visionOS device artifacts are merged from stable `arm64` and
    experiment `arm64e` archives
  - iOS/visionOS simulator artifacts remain stable `arm64`
  - UniFFI bindgen continues to use an `arm64e-apple-darwin` host dylib
  - app-side release workflows publish `PgpMobile.arm64e-build-manifest.json`
    with Rust stage1 provenance, OpenSSL carry-chain commits, and verified
    XCFramework slice metadata
- OpenSSL source carry:
  - `pgp-mobile/Cargo.toml` patches `openssl-src` to `https://github.com/cypherair/openssl-src-rs`
  - tracked downstream branch line: `carry/apple-arm64e-openssl-fork`
  - current resolved branch head: `be17d917887a`
  - `pgp-mobile/Cargo.lock` records the resolved git commit for repeatable
    local builds, while `Cargo.toml` intentionally tracks the carry branch
- OpenSSL target-definition carry:
  - the `openssl-src-rs` carry branch is expected to point at the CypherAir OpenSSL fork
  - intended downstream branch line: `carry/apple-arm64e-targets`
  - current carry branch head: `d228bf84e32e`
  - current `openssl-src-rs` submodule pointer: `d228bf84e32e`

## Automation Posture

- `cypherair/rust`:
  - `arm64e-stage1-prerelease.yml` validates the integration branch, builds the
    patched stage1 compiler, host `std`/`proc_macro`, and
    `arm64e-apple-darwin` std, smoke-tests the packaged toolchain, and
    publishes a prerelease asset for app CI.
  - `arm64e-upstream-sync-prep.yml` performs manual upstream-sync dry-runs and
    can open a refresh PR without force-pushing the integration branch.
- `cypherair/cypherair`:
  - PR, nightly, edge, and stable workflows call the official arm64e
    `./build-xcframework.sh --release` path.
  - edge and stable releases include `PgpMobile.arm64e-build-manifest.json`.
  - stable compliance assets embed the arm64e manifest and the relink kit covers
    both stable `arm64` and patched `arm64e` target archives.
  - App Store candidate validation requires the stable release to include a
    valid arm64e manifest before archiving is allowed.
- `cypherair/openssl-src-rs`:
  - `arm64e-carry-chain.yml` checks that the OpenSSL submodule URL, branch, and
    pointer stay aligned with `cypherair/openssl:carry/apple-arm64e-targets`,
    then packages and tests the crate.

## Branch Posture

At the time of this snapshot, `codex/apple-arm64e-unified-experiment` contains
the current `main` branch and is ahead with experiment-specific commits. Treat
it as an active worktree that still needs branch hygiene as `main` continues to
move, but not as a branch that is currently lagging behind `main`.

## Related Forks And Paths

- App repo owner/main worktree:
  - `/Users/tianren/coding/cypherair-main`
- Rust fork:
  - `/Users/tianren/coding/rust`
  - remote `cypherair/rust`
  - experiment branch `codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`
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

- This worktree itself is an experiment/integration branch, not an upstream PR
  target.
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

- the local or remote experiment branch name
- the ownership/worktree relationship with `/Users/tianren/coding/cypherair-main`
- the `rust-toolchain.toml` arm64e toolchain pin
- the `pgp-mobile/Cargo.toml` `openssl-src` patch target, branch, or lockfile
  policy
- the role of `openssl`, `openssl-src-rs`, or `rust-openssl` in the chain
- the app-side arm64e readiness status
- the branch posture between `main` and `codex/apple-arm64e-unified-experiment`
- the Rust stage1 prerelease workflow contract or arm64e release manifest shape
