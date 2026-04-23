# Apple `arm64e` Experiment Notes

This directory contains branch-local experiment helpers for CypherAir's Apple
`arm64e` work.

## Toolchain

This experiment branch is expected to use the locally linked Rust toolchain:

- `stage1-arm64e-patch`

That toolchain currently comes from the local Rust fork checkout at:

- `/Users/tianren/coding/rust`

The branch-level `rust-toolchain.toml` points repo-root cargo/rustc invocations
at that patched stage1 toolchain so local `pgp-mobile` validation uses the
current upstream-fix spike by default.

## Carry Chain

The current experiment intentionally uses a layered downstream carry chain:

- `pgp-mobile` pins a CypherAir `openssl-src-rs` fork commit on
  `carry/apple-arm64e-openssl-fork`
- that `openssl-src-rs` fork commit points at a CypherAir `openssl` fork commit
  on `carry/apple-arm64e-targets`

This is deliberate.

The Apple `arm64e` target definitions live first in the `openssl` fork. Until
equivalent support lands upstream in OpenSSL, the `openssl-src-rs` fork branch
must be treated as a **carry branch**, not as an independently upstreamable
change.

In other words:

- do not assume the `openssl-src-rs` branch can be proposed upstream on its own
- keep the OpenSSL fork branch and the `openssl-src-rs` fork branch named and
  commented as downstream carry branches
- update the pinned commit in `pgp-mobile/Cargo.toml` only after the
  corresponding fork commits exist

## Script

- `build_apple_arm64e_xcframework.sh`
  Unified Apple experiment entrypoint. Extends the experiment to:
  iOS device `arm64e`, Darwin host `arm64e`, macOS XCFramework `arm64e`,
  visionOS device `arm64e`, while keeping iOS and visionOS simulators on
  stable `arm64`.
- `repro_arm64e_rust_host_crashes.sh`
  Minimal host-side repro matrix for the current macOS `arm64e` crash
  investigation. Uses existing `pgp-mobile` Rust tests plus a standalone
  scratch Cargo binary, and avoids relaunching the full Xcode macOS test host.
- `sample_arm64e_darwin_toolchains.sh`
  Samples a small set of nightly toolchains against the standalone scratch
  binary and the smallest `pgp-mobile` merge test, to distinguish target-wide
  host instability from a recent nightly regression.
- `probe_arm64e_tls_codegen_gap.sh`
  Builds matching `arm64e` C++ and Rust TLS samples, then shows the current
  wrapper-level codegen gap between clang and Rust. Also includes a manual LLVM
  IR attribute experiment that changes Rust's wrapper from `blr` to `blraaz`.

## Investigation Notes

- `arm64e-macos-unit-crash-investigation.md`
  Current evidence summary for the macOS unit-test crash investigation,
  including the pure Rust `arm64` vs `arm64e` control/repro results and the
  standalone `arm64e` host-binary crash evidence.
- `arm64e-apple-darwin-rust-issue-draft.md`
  Draft upstream-facing issue text for Rust/toolchain reporting. Packages the
  current minimal reproduction, environment, and sampled nightly results in a
  format that can be adapted into a GitHub issue.

## Local Recovery

If the locally linked `stage1-arm64e-patch` toolchain or the packaged
`PgpMobile.xcframework` is missing or broken, use this recovery flow.

1. Restore the local Rust stage1 toolchain from
   `/Users/tianren/coding/rust` on branch
   `codex/arm64e-darwin-ptrauth-spike`.
2. Create a local `bootstrap.toml` in the Rust fork if one is missing.
   Keep `build = "aarch64-apple-darwin"` and
   `host = ["aarch64-apple-darwin"]`, but include
   `target = ["aarch64-apple-darwin", "arm64e-apple-darwin"]`.
   Set `profile = "compiler"`, `llvm.download-ci-llvm = true`, and
   `rust.download-rustc = false`.
   This file is local bootstrap state and is typically ignored, not committed.
3. Rebuild the Rust stage1 sysroot:

   ```bash
   cd /Users/tianren/coding/rust
   python3 x.py build library -j$(sysctl -n hw.ncpu)
   rustup toolchain link stage1-arm64e-patch \
       /Users/tianren/coding/rust/build/aarch64-apple-darwin/stage1
   rustc +stage1-arm64e-patch -vV
   ```

4. Recreate the app-side Apple arm64e artifacts:

   ```bash
   cd /Users/tianren/coding/cypherair-apple-arm64e-unified-experiment
   CARGO_NET_GIT_FETCH_WITH_CLI=true \
       scripts/experiments/build_apple_arm64e_xcframework.sh --release
   ```

5. The script now skips the negative stable baseline repro by default.
   Re-enable it only when you explicitly want that proof:

   ```bash
   RUN_STABLE_BASELINES=1 \
   CARGO_NET_GIT_FETCH_WITH_CLI=true \
       scripts/experiments/build_apple_arm64e_xcframework.sh --release
   ```

6. After the XCFramework is recreated, run the macOS unit suite:

   ```bash
   xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
       -destination 'platform=macOS'
   ```
