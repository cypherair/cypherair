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
