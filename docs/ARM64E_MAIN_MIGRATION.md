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
- 2026-04-24T23:19:38Z: Re-ran PR Checks after workflow fix
  `bc7b676db778768c0f0a244f06938fc328c5d96d`; run `24915498511`
  passed `rust-full-tests`, `xcframework-package`, and the hosted Swift preview.
- 2026-04-24T23:21:22Z: Merged PR #222 into `main` using a regular merge
  commit, `98e9e9fcdcc3760538b2b0e260a5daf52dc67c0e`.
- 2026-04-24T23:29:08Z: Post-merge main worktree passed
  `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.

## 1. Merge Facts

- Before PR creation, `origin/main` was an ancestor of the source branch.
- The pre-PR source branch was `22` commits ahead and `0` commits behind
  `origin/main`.
- `git merge-tree origin/main origin/codex/apple-arm64e-unified-experiment`
  reported no conflict blocks.
- A disposable `git merge --no-commit --no-ff
  origin/codex/apple-arm64e-unified-experiment` dry run reported
  `merge_status=0` and `unmerged_count=0`.
- The merge was conflict-light; the main post-merge work is normalizing stale
  experimental wording in docs and rerunning main-branch release validation.

## 2. Landed Main Changes

- Pointer authentication is enabled in the Xcode project.
  `ENABLE_POINTER_AUTHENTICATION = YES` is the intended mainline posture.
- `build-xcframework.sh` is the official thin entrypoint. The full
  implementation lives in `scripts/build_apple_arm64e_xcframework.sh`.
- Normal `arm64` slices build with the official Rust stable channel. `arm64e`
  slices build with nightly Cargo plus explicit `RUSTC=<stage1>/bin/rustc`.
- Local full packaging may use a linked `stage1-arm64e-patch` toolchain when
  available. GitHub release workflows force-download the attested
  `cypherair/rust` `rust-arm64e-stage1-*` prerelease.
- `pgp-mobile/Cargo.toml` tracks `cypherair/openssl-src-rs` branch
  `carry/apple-arm64e-openssl-fork`; `pgp-mobile/Cargo.lock` records the
  resolved commit for repeatability.
- Edge, drill, and stable release assets include
  `PgpMobile.arm64e-build-manifest.json`.
- The arm64e manifest must record the Rust stage1 prerelease, Rust source commit, OpenSSL carry-chain commits, runner/Xcode/Rust metadata, and the verified XCFramework slice layout.

## 3. Post-Merge Docs Normalization

- `AGENTS.md` has been rewritten around mainline arm64e support and no longer
  tells agents to work in the former app experiment worktree.
- `docs/ARM64E_STATUS.md` has been converted from a source-branch snapshot into
  a mainline status page. It now says that `arm64e` support is present on
  `main`.
- `docs/TDD.md` now describes the OpenSSL override as part of the current
  arm64e build chain, not an experiment-only chain.
- `scripts/experiments/README.md` now states that the scripts and notes are
  historical or diagnostic material, not the official build entrypoint.
- `docs/ARM64E_STATUS.md` remains the place for the current Rust stage1 pin,
  OpenSSL carry-chain pin, and release-manifest shape after the merge.

## 4. Validation Checklist

After the merge lands on `main`, run these checks before treating the migration
as complete:

- PR #222 run `24915498511` passed `rust-full-tests`.
- PR #222 run `24915498511` passed `xcframework-package`, including
  `./build-xcframework.sh --release`, artifact upload, iOS probe, and visionOS
  probe.
- PR #222 run `24915498511` passed the hosted Swift preview as an
  observational warning-only job.
- Post-merge main worktree passed
  `cargo +stable test --manifest-path pgp-mobile/Cargo.toml`.
- Mainline wording sweep after merge:

  ```bash
  rg --glob '!docs/ARM64E_MAIN_MIGRATION.md' \
    "cypherair-apple-arm64e-unified-experiment|Current purpose: this worktree|Update experiment-specific|remaining work is validating|needs validation prior to landing|prior to landing|experiment chain" \
    AGENTS.md docs scripts/experiments
  ```
- `XCFramework Edge Release` or an equivalent main-branch drill run
- `Stable Build Release` with `create_release=false`
- Download `PgpMobile.arm64e-build-manifest.json` from the generated release or dry-run artifact and confirm:
  - the Rust stage1 release tag and source commit are present
  - the OpenSSL carry-chain commits are present and fresh
  - iOS, macOS, and visionOS device libraries contain `arm64` and `arm64e`
  - simulator libraries remain `arm64`
- Confirm that no stable dry-run created a formal GitHub release or tag.
