# CypherAir Apple arm64e Status

Snapshot date: 2026-04-23

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

- The app-side Apple `arm64e` adaptation is basically working in this worktree.
- The experiment branch contains branch-local build helpers, a patched Rust
  toolchain pin, and a reproducible vendored OpenSSL carry chain.
- The remaining work is no longer "can CypherAir run with arm64e at all?".
  The remaining work is:
  - keeping this experiment branch current with the evolving `main` branch
  - keeping the dependency chain explicit and reproducible
  - upstreaming the supporting changes in the Rust and crypto forks

## Current Verified Chain

- Rust toolchain pin:
  - `rust-toolchain.toml` points to `stage1-arm64e-patch`
  - local Rust fork path: `/Users/tianren/coding/rust`
  - Rust experiment branch: `codex/arm64e-darwin-ptrauth-spike`
- OpenSSL source carry:
  - `pgp-mobile/Cargo.toml` patches `openssl-src` to `https://github.com/cypherair/openssl-src-rs`
  - pinned revision: `36d52f499d71d90c8c4b89c53210cbdde34e0528`
  - intended downstream branch line: `carry/apple-arm64e-openssl-fork`
- OpenSSL target-definition carry:
  - the `openssl-src-rs` carry branch is expected to point at the CypherAir OpenSSL fork
  - intended downstream branch line: `carry/apple-arm64e-targets`

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
  - experiment branch `codex/arm64e-darwin-ptrauth-spike`
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
- The upstream-facing work is expected to happen in the supporting forks,
  especially `cypherair/rust`.
- App-side documentation should record the current dependency chain and current
  level of app-side functionality, but should not pretend that the supporting
  fork work is already upstream-ready.

## Update Rules

Update this file whenever any of the following changes:

- the local or remote experiment branch name
- the ownership/worktree relationship with `/Users/tianren/coding/cypherair-main`
- the `rust-toolchain.toml` arm64e toolchain pin
- the `pgp-mobile/Cargo.toml` `openssl-src` patch target or revision
- the role of `openssl`, `openssl-src-rs`, or `rust-openssl` in the chain
- the app-side arm64e readiness status
- the branch posture between `main` and `codex/apple-arm64e-unified-experiment`
