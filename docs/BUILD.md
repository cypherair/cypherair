# Build and Release

## 1. Stable release

**Build numbers.** `CURRENT_PROJECT_VERSION` encodes `MARKETING_VERSION` (`1.5.5` → `15500`). For macOS App Store uploads the build number must be strictly higher than the highest macOS build previously uploaded, *even when the marketing version increases* — an Apple-side fact no gate here can see.

## 3. arm64e toolchain contract

- **Device slices ship `arm64` alongside `arm64e`** because Apple distribution requires an `arm64` slice whenever a bundle contains `arm64e`.
- **`UIRequiredDeviceCapabilities` is declared (`arm64`) in `CypherAir-Info.plist`** because Xcode injects it only while every architecture in `ARCHS` is arm64 or arm64e; the arm64e.x1 slice silences the injection, and App Store Connect rejects a 64-bit iOS binary without the key.
- **`arm64e` builds use stable Cargo with `RUSTC` pointed at the pinned stage1 compiler and its prebuilt std payloads — never nightly Cargo, never `-Zbuild-std`.** The repo has no `rust-toolchain.toml`; every ordinary validation names its toolchain (`cargo +stable`).
- **App-side Rust or UniFFI changes never require a new stage1 prerelease** — only a change to the Rust compiler fork itself does. The opposite assumption costs a publication cycle.
- The pinned tag and the never-`latest` red line live in [ARM64E_STATUS.md](ARM64E_STATUS.md).

**Re-pin rule.** A new stage1 prerelease becomes the official input only when every pinned location rotates in the same PR. One part of a rotation is not derivable from the scripts: refresh every per-asset SHA-256 and byte size for both host triples, confirmed against a real download rather than an API-reported digest.

## 4. Owned carry chains

`engine/Cargo.toml` patches `openssl-src` to the `cypherair/openssl-src-rs` fork, whose submodule points at the `cypherair/openssl` fork carrying the Apple arm64e target definitions — the entire reason the chain exists. `Cargo.lock`, never prose, is the truth for the current heads; the branches stay downstream until equivalent arm64e support lands upstream. The compiler fork (`cypherair/rust`, plus its LLVM work) has no output-time `ptrauth` operand-bundle stripper — each layer enforces its own contract — and production stage1 forces the unmodified bundled-LLVM gitlink.

## 5. FFI artifact shape

The engine is a **static-library** XCFramework: static linking is what preserves the single-binary MIE posture.

## 7. Swift packages

`Packages/CypherCore` is the one local package the app links; it brings `Packages/CypherVault` and `Packages/CypherEngine` with it. Two rules keep the packages whole across all three device slices: the shared workspace setting `iOSPackagesShouldBuildARM64e` stays committed in the project's embedded workspace, and each manifest mirrors the project's Swift language mode and upcoming features. Both are Apple's mechanisms; neither is a workaround.

`Packages/CypherEngine` holds the engine. `scripts/build-engine.sh` writes the static-library XCFramework and the generated Swift into it; neither is committed. Its platforms state the app's exact deployment target, because with `.v27` the linker warns once for every object file in the library. The script reads the deployment targets from that manifest. It stores a hash of the engine's sources, its lock file, the manifest, the compiler pin and itself beside the library, and the app's "Check engine library" phase fails when the checkout no longer matches it, or when the library lacks a slice the build needs: a list of targets builds only those slices.
