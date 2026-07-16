# CypherAir Apple arm64e Status

> Status: Canonical current-state — source of truth for Apple arm64e support.
> Purpose: The pinned arm64e Rust stage1 toolchain, the packaging policy, and the external SQLCipher pin.
> Audience: Human developers, release owners, and AI coding tools.
> Update triggers: The pinned stage1 tag or its source ref/commit, the stage1 consumption policy, the `openssl-src` patch target or the OpenSSL forks' role, the dual-arch packaging policy or build-manifest contract, or the SQLCipher wrapper pin.
> Last reviewed: 2026-07-15.

## Packaging Policy

- `./build-xcframework.sh --release` is the official app-side build entrypoint (delegates to `scripts/build_apple_arm64e_xcframework.sh`). Build mechanics and the local packaging workflow live in [TESTING.md](TESTING.md) §2.4 workflow C.
- iOS, macOS, and visionOS **device** artifacts ship dual `arm64` + `arm64e` slices because Apple distribution requires `arm64` whenever a bundle contains `arm64e`. iOS/visionOS **simulator** artifacts remain `arm64`-only. UniFFI bindgen uses an `arm64e-apple-darwin` host dylib.
- `arm64` slices build with official stable Rust; `arm64e` slices use stable Cargo with `RUSTC` pointing at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo or `-Zbuild-std`. The repo has no `rust-toolchain.toml` override; ordinary validation uses explicit `cargo +stable`.
- Every build emits `PgpMobile.arm64e-build-manifest.json` (schema-v3 Rust stage1 and bundled-LLVM provenance, OpenSSL carry-chain commits, verified slice metadata). Edge and stable releases publish it; App Store candidate validation requires the exact pinned Rust source/LLVM identity in the stable-release manifest before archiving ([RELEASE.md](RELEASE.md)).

## Pinned Rust stage1 Toolchain

- Fork repository: `cypherair/rust`; stable base `1.97.0` (`2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`). New stage1 prereleases are published by that fork's `arm64e-stage1-prerelease.yml` workflow.
- **Pinned prerelease tag:** `rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1`
- Pinned source ref/commit: `refs/heads/carry/cypherair-arm64e-toolchain-stable-1.97` @ `c405db836704af8307c5c41d6dbdc92068dec0d6` (workflow run `29390775624`).
- The immutable prerelease publishes host-specific `rust-stage1-for-arm64e-<host-triple>.*` asset sets (`aarch64-apple-darwin` and `x86_64-apple-darwin`). Each schema-v3 manifest records `requiresBuildStd: false`, the prebuilt Darwin/iOS/tvOS/visionOS arm64e std targets, bundled LLVM gitlink `08c84e69a84d95936296dfcab0e38b34100725d5`, `downloadCiLlvm: false`, and LLVM 22.1.6 as reported by source, `llvm-config`, packaged `rustc`, and packaged `llc`. The tar contains a checksum-bound copy of that LLVM identity.
- CI and local packaging force-download this pin via HTTPS with release-token variables scrubbed. **`latest` is never allowed.** Before extraction, `scripts/download_arm64e_stage1_toolchain.sh` requires the exact repository/tag and per-asset SHA-256 and byte-size values committed in `third_party/arm64e-stage1-toolchain.pin.json`. Before executing the compiler, `scripts/verify_arm64e_stage1_release.sh` verifies release immutability, tag-to-commit binding, the GitHub release attestation, and per-asset SLSA provenance; the official build path then validates the exact outer manifest (including its host-specific asset names and pinned archive size) and packaged LLVM identity and executes the selected `rustc` and its host `llc` to confirm LLVM 22.1.6. `ARM64E_STAGE1_PIN_FILE`, `ARM64E_RUSTC`, `ARM64E_STAGE1_DIR`, and a locally linked `stage1-arm64e-patch` are deliberate testing overrides and are never set in CI.
- Historical warning: the first stable197 publication (source `027700f412b05d0148e6eb4e865d618582cbb63f`, run `29277996466`) used schema 2 and Rust CI LLVM 22.1.8. It is marked superseded and is prohibited as a CypherAir input.
- App-side Rust or UniFFI changes never require a new stage1 prerelease; only changes to the Rust compiler fork itself do.
- Carry-set strategy — a patch-by-patch enumeration of the fork's carried commits, the LLVM/rustc/keep upstreaming assessment, and the minimization + rebase plan — lives in [ARM64E_UPSTREAMING.md](ARM64E_UPSTREAMING.md). That companion records ownership, carried history, and validation evidence; this file remains the production pin source of truth.

**Re-pin rule.** When a new stage1 prerelease becomes the official input, update every pinned location in the same PR (agent checklist: `.claude/skills/repin-arm64e`):

1. `.github/workflows/pr-checks.yml`, `nightly-full.yml`, `xcframework-edge-release.yml` (env values)
2. `scripts/build_apple_arm64e_xcframework.sh` and `scripts/download_arm64e_stage1_toolchain.sh` (defaults)
3. This file (the pin lines above)
4. `CLAUDE.md` Build Commands and `AGENTS.md` Build And Validation
5. `docs/TESTING.md` §2.4 workflow C
6. `third_party/arm64e-stage1-toolchain.pin.json` — refresh the full release identity (tag, url, commit, source ref, run id, publishedAt) **and every per-asset SHA-256 and byte size for both host triples**. Take digests and sizes from `gh api repos/cypherair/rust/releases/tags/<tag>` and confirm them against a real download; then run `scripts/verify_arm64e_stage1_release.sh` against the downloaded assets so the attestation chain is proven before the pin lands.
7. `scripts/validate_arm64e_stage1_toolchain.py` — release repository/ref/commit come from the machine pin, but review its stable-series prefix, stable base, schema, bundled-LLVM gitlink/version, and tests whenever the new release changes any semantic contract rather than only rotating the build identity.

After rotating: the old tag greps to zero hits, the new tag greps to exactly these locations, the selected package passes release and semantic verification before the compiler executes, and one pinned rebuild plus the macOS unit lane passes.

## OpenSSL Carry Chain

`pgp-mobile/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork (branch `carry/apple-arm64e-openssl-fork`), whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions. `Cargo.lock` records the resolved commits — the lockfile, not this file, is the machine-checked truth for the current heads. The carry branches remain downstream until equivalent arm64e support lands upstream.

## SQLCipher Formal External Dependency

- Wrapper repository: `cypherair/sqlcipher-xcframework`; pinned release `sqlcipher-xcframework-v4.16.0-cypherair.1` (wrapper commit `aee70b13ddf0eb262ac1283930760cac44dbe873`).
- Upstream SQLCipher `v4.16.0`, peeled commit `e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc`.
- Zip SHA-256: `3544554bcf947fb9329f2ab083cd42f0c7ae9179e98b7f36f26859e2c573062e`; consumer pin file: `third_party/sqlcipher-xcframework.pin.json`.
- Release shape: SSH-signed annotated tag on a non-prerelease immutable GitHub Release, verified with `gh release verify`, `gh release verify-asset`, and `gh attestation verify`. Slices mirror the app policy (device `arm64`+`arm64e`, simulator `arm64`), each a static `SQLCipher.framework`.
- Restore/validation mechanics: [TESTING.md](TESTING.md) §2.4. Refreshes publish a new stable immutable wrapper release first, then re-pin here; never commit the restored artifact or downloaded assets.
