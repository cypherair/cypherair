# Apple arm64e Main Migration Checklist

> Status: Active migration checklist, temporary.
> Purpose: Guide the documentation and release-infrastructure cleanup after merging the Apple `arm64e` integration branch into `main`.
> Audience: Release owners, reviewers, and AI coding tools preparing or reviewing the `arm64e` mainline merge.
> Source of truth: Current `main`, source branch `codex/apple-arm64e-unified-experiment`, the successful edge drill run `24897042096`, and the successful stable dry-run `24897042109`.
> Last reviewed: 2026-04-24.
> Update triggers: Any change to the planned `arm64e` merge scope, release workflow contract, Rust stage1 consumption path, OpenSSL carry chain, or post-merge documentation cleanup plan.
> Removal trigger: Remove or archive this checklist after the `arm64e` integration lands on `main`, the main-branch edge drill and stable dry-run pass, and the permanent documentation is normalized.

This is a temporary migration checklist. It does not replace the permanent
current-state docs. After the merge, current code, workflows, and normalized
canonical docs outrank this file.

## Migration Log

- 2026-04-24T21:54:25Z: Created PR #222,
  `https://github.com/cypherair/cypherair/pull/222`, from source branch
  `codex/apple-arm64e-unified-experiment` to `main`.

## 1. Merge Facts

- `origin/main` is an ancestor of the source branch.
- The source branch is currently `22` commits ahead and `0` commits behind `origin/main`.
- `git merge-tree origin/main origin/codex/apple-arm64e-unified-experiment` reported no conflict blocks.
- A disposable `git merge --no-commit --no-ff origin/codex/apple-arm64e-unified-experiment` dry run reported `merge_status=0` and `unmerged_count=0`.
- The merge is expected to be review-heavy rather than conflict-heavy: the main risk is stale experimental wording in docs, not Git conflict resolution.

## 2. Expected Main Changes

- Pointer authentication is expected to be enabled in the Xcode project. `ENABLE_POINTER_AUTHENTICATION = YES` is the intended mainline posture.
- `build-xcframework.sh` should become the official thin entrypoint. The full implementation should live in `scripts/build_apple_arm64e_xcframework.sh`.
- Normal `arm64` slices should build with the official Rust stable channel. `arm64e` slices should build with nightly Cargo plus explicit `RUSTC=<stage1>/bin/rustc`.
- Local full packaging may use a linked `stage1-arm64e-patch` toolchain when available. GitHub release workflows must force-download the attested `cypherair/rust` `rust-arm64e-stage1-*` prerelease.
- `pgp-mobile/Cargo.toml` is expected to track `cypherair/openssl-src-rs` branch `carry/apple-arm64e-openssl-fork`; `pgp-mobile/Cargo.lock` records the resolved commit for repeatability.
- Edge, drill, and stable release assets should include `PgpMobile.arm64e-build-manifest.json`.
- The arm64e manifest must record the Rust stage1 prerelease, Rust source commit, OpenSSL carry-chain commits, runner/Xcode/Rust metadata, and the verified XCFramework slice layout.

## 3. Docs To Normalize After Merge

- `AGENTS.md`: replace source-branch local path and branch-specific instructions with mainline guidance. Keep the related fork inventory only if it is worded as durable dependency context.
- `docs/ARM64E_STATUS.md`: convert the source-branch snapshot into a mainline status page. It should say that `arm64e` support is present on `main`, not that the branch still needs validation prior to landing.
- `docs/APP_RELEASE_PROCESS.md`, `docs/TESTING.md`, `docs/XCFRAMEWORK_RELEASES.md`, and `docs/TDD.md`: keep the arm64e release, compliance, and build contracts, but remove wording that describes the whole feature as an experiment-only chain once it is mainline behavior.
- `scripts/experiments/README.md`: keep the historical investigation files if useful, but state clearly that the scripts and notes are historical or diagnostic material, not the official build entrypoint.
- `docs/ARM64E_STATUS.md` should remain the place for the current Rust stage1 pin, OpenSSL carry-chain pin, and release-manifest shape after the merge.

## 4. Validation Checklist

After the merge lands on `main`, run these checks before treating the documentation migration as complete:

- `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`
- `./build-xcframework.sh --release`
- `XCFramework Edge Release` or an equivalent main-branch drill run
- `Stable Build Release` with `create_release=false`
- Download `PgpMobile.arm64e-build-manifest.json` from the generated release or dry-run artifact and confirm:
  - the Rust stage1 release tag and source commit are present
  - the OpenSSL carry-chain commits are present and fresh
  - iOS, macOS, and visionOS device libraries contain `arm64` and `arm64e`
  - simulator libraries remain `arm64`
- Confirm that no stable dry-run created a formal GitHub release or tag.
- Run a final wording sweep for stale source-branch and local-worktree phrases in `AGENTS.md` and `docs/ARM64E_STATUS.md` after `docs/ARM64E_STATUS.md` lands on `main`.
  - Any remaining source-branch references must be historical, diagnostic, or explicitly transitional.
