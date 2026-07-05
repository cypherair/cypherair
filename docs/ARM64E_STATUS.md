# CypherAir Apple arm64e Status

> Status: Canonical current-state — source of truth for Apple arm64e support.
> Purpose: The pinned arm64e Rust stage1 toolchain, the packaging policy, and the external SQLCipher pin.
> Audience: Human developers, release owners, and AI coding tools.
> Update triggers: See "Update Rules" at the end of this file.
> Last reviewed: 2026-07-04.

## Packaging Policy

- `./build-xcframework.sh --release` is the official app-side build entrypoint (delegates to `scripts/build_apple_arm64e_xcframework.sh`). Build mechanics and the local packaging workflow live in [TESTING.md](TESTING.md) §2.4 workflow C.
- iOS, macOS, and visionOS **device** artifacts ship dual `arm64` + `arm64e` slices because Apple distribution requires `arm64` whenever a bundle contains `arm64e`. iOS/visionOS **simulator** artifacts remain `arm64`-only. UniFFI bindgen uses an `arm64e-apple-darwin` host dylib.
- `arm64` slices build with official stable Rust; `arm64e` slices use stable Cargo with `RUSTC` pointing at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo or `-Zbuild-std`. The repo has no `rust-toolchain.toml` override; ordinary validation uses explicit `cargo +stable`.
- Every build emits `PgpMobile.arm64e-build-manifest.json` (Rust stage1 provenance, OpenSSL carry-chain commits, verified slice metadata). Edge and stable releases publish it; App Store candidate validation requires a valid manifest in the stable release before archiving ([RELEASE.md](RELEASE.md)).

## Pinned Rust stage1 Toolchain

- Fork repository: `cypherair/rust`; stable base `1.96.0` (`ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96`).
- **Pinned prerelease tag:** `rust-arm64e-stage1-stable196-20260618T140657Z-abeb845-r27765229620-a1`
- Pinned source ref/commit: `refs/heads/carry/cypherair-arm64e-toolchain-stable-1.96` @ `abeb8459f2b459704c1d698c01d8b8c0df8ffffd` (workflow run `27765229620`).
- The prerelease publishes host-specific `rust-stage1-for-arm64e-<host-triple>.*` asset sets (`aarch64-apple-darwin` and `x86_64-apple-darwin`); downloaders select the asset matching the build host and verify the packaged checksum and manifest (`requiresBuildStd: false`, arm64e std targets for Darwin, iOS, tvOS, visionOS).
- CI and local packaging force-download this pinned prerelease via direct release-asset URLs with token variables scrubbed. **`latest` is never allowed** — `scripts/download_arm64e_stage1_toolchain.sh` rejects it. `ARM64E_RUSTC` / `ARM64E_STAGE1_DIR` / a locally linked `stage1-arm64e-patch` toolchain are for deliberate Rust-compiler testing only.
- App-side Rust or UniFFI changes never require a new stage1 prerelease; only changes to the Rust compiler fork itself do.

**Re-pin rule.** When a new stage1 prerelease becomes the official input, update every pinned location in the same PR (agent checklist: `.claude/skills/repin-arm64e`):

1. `.github/workflows/pr-checks.yml`, `nightly-full.yml`, `xcframework-edge-release.yml` (env values)
2. `scripts/build_apple_arm64e_xcframework.sh` and `scripts/download_arm64e_stage1_toolchain.sh` (defaults)
3. This file (the pin lines above)
4. `CLAUDE.md` Build Commands and `AGENTS.md` Build And Validation
5. `docs/TESTING.md` §2.4 workflow C

After rotating: the old tag greps to zero hits, the new tag greps to exactly these locations, and one pinned rebuild plus the macOS unit lane passes.

## OpenSSL Carry Chain

`pgp-mobile/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork (branch `carry/apple-arm64e-openssl-fork`), whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions. `Cargo.lock` records the resolved commits — the lockfile, not this file, is the machine-checked truth for the current heads. The carry branches remain downstream until equivalent arm64e support lands upstream.

## SQLCipher Formal External Dependency

- Wrapper repository: `cypherair/sqlcipher-xcframework`; pinned release `sqlcipher-xcframework-v4.16.0-cypherair.1` (wrapper commit `aee70b13ddf0eb262ac1283930760cac44dbe873`).
- Upstream SQLCipher `v4.16.0`, peeled commit `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`.
- Zip SHA-256: `3544554bcf947fb9329f2ab083cd42f0c7ae9179e98b7f36f26859e2c573062e`; consumer pin file: `third_party/sqlcipher-xcframework.pin.json`.
- Release shape: SSH-signed annotated tag on a non-prerelease immutable GitHub Release, verified with `gh release verify`, `gh release verify-asset`, and `gh attestation verify`. Slices mirror the app policy (device `arm64`+`arm64e`, simulator `arm64`), each a static `SQLCipher.framework`.
- Restore/validation mechanics: [TESTING.md](TESTING.md) §2.4. Refreshes publish a new stable immutable wrapper release first, then re-pin here; never commit the restored artifact or downloaded assets.

## Update Rules

Update this file whenever any of the following changes:

- the pinned stage1 tag, its source ref/commit, or the stage1 consumption policy
- the `openssl-src` patch target or the role of the OpenSSL forks in the chain
- the dual-arch packaging policy or the build-manifest contract
- the SQLCipher wrapper pin (tag, commits, checksum, pin file)
