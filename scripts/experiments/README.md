# Apple `arm64e` Historical And Diagnostic Notes

This directory contains historical investigation notes and diagnostic helpers
from CypherAir's Apple `arm64e` work. It is not the formal app build entrypoint.
Use the repo-root `./build-xcframework.sh --release` path for current mainline
packaging.

## Toolchain

The formal CypherAir build no longer uses a repo-wide `rust-toolchain.toml`
override. Ordinary Rust validation should be explicit:

```bash
cargo +stable test --manifest-path pgp-mobile/Cargo.toml
```

The local arm64e path can still use the locally linked Rust toolchain:

- `stage1-arm64e-patch`

That optional toolchain currently comes from the local Rust fork checkout at:

- `/Users/tianren/coding/rust`

`./build-xcframework.sh --release` uses that local `stage1-arm64e-patch`
toolchain when it is linked, so normal app-side or `pgp-mobile` changes can be
rebuilt locally without waiting for a GitHub Rust compiler build. GitHub Actions
release jobs set `ARM64E_STAGE1_FORCE_DOWNLOAD=1` and consume an attested
`cypherair/rust` `rust-arm64e-stage1-*` prerelease instead, so prerelease and
stable compliance artifacts are reproducible from remote provenance rather than
developer-machine state.

The active Rust integration branch is
`codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`, based on
`upstream/main@9836b06b55f5`. It is the union of the three upstream-ready Rust
PR branches, a small integration-only visionOS+ptrauth cross-check follow-up,
and a final CypherAir fork-only workflow commit, which should never be sent to
rust-lang/rust. The earlier stacked `prep/arm64e-*` rehearsal branches have
been deleted; use the `prep/upstream-ready-*` branches and the rust-lang/rust
PRs as the upstream references.

As of 2026-04-24, three clean upstream-ready Rust PRs are open:

- target: <https://github.com/rust-lang/rust/pull/155715>
- arm64e ptrauth/codegen: <https://github.com/rust-lang/rust/pull/155716>
- bootstrap shallow upstream detection: <https://github.com/rust-lang/rust/pull/155717>

The CypherAir integration PR
<https://github.com/cypherair/rust/pull/5> is now the local validation/reference
stack until those PRs land or are reshaped by upstream review. The older PR #4
is closed as superseded, but its branch/run remains useful as a green
historical reference.

## Carry Chain

The current mainline arm64e build intentionally uses a layered downstream carry
chain:

- `pgp-mobile` tracks the CypherAir `openssl-src-rs` fork branch
  `carry/apple-arm64e-openssl-fork`
- that `openssl-src-rs` fork branch points at a CypherAir `openssl` fork commit
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
- update `pgp-mobile/Cargo.toml`, `pgp-mobile/Cargo.lock`, and this status
  documentation together when the carry chain changes

## Script

- `build_apple_arm64e_xcframework.sh`
  Historical diagnostic predecessor to the official repo-root entrypoint. It
  still helps reproduce the original arm64e investigation path, but current
  mainline packaging should use `./build-xcframework.sh --release`.
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
`PgpMobile.xcframework` is missing or broken, use this recovery flow. You only
need to rebuild or republish stage1 after changing the Rust compiler fork
itself; ordinary CypherAir app or `pgp-mobile` changes can reuse the existing
local stage1 or the latest Rust fork prerelease.

1. Restore the local Rust stage1 toolchain from
   `/Users/tianren/coding/rust` on branch
   `codex/arm64e-upstream-ready-integration-2026-04-24-u9836b06`.
2. Create a local `bootstrap.toml` in the Rust fork if one is missing.
   Keep `build = "aarch64-apple-darwin"` and
   `host = ["aarch64-apple-darwin"]`, but include
   `target = ["aarch64-apple-darwin", "arm64e-apple-darwin"]`.
   Set `profile = "compiler"`, `llvm.download-ci-llvm = true`, and
   `rust.download-rustc = false`.
   This file is local bootstrap state and is typically ignored, not committed.
3. Rebuild the Rust stage1 compiler, host std/proc_macro, and arm64e Darwin
   std artifacts:

   ```bash
   cd /Users/tianren/coding/rust
   python3 x.py build compiler/rustc library/std library/proc_macro --stage 1 \
       --target aarch64-apple-darwin,arm64e-apple-darwin
   rustup toolchain link stage1-arm64e-patch \
       /Users/tianren/coding/rust/build/aarch64-apple-darwin/stage1
   rustc +stage1-arm64e-patch -vV
   ```

4. Recreate the app-side Apple arm64e artifacts:

   ```bash
   cd /Users/tianren/coding/cypherair-main
   CARGO_NET_GIT_FETCH_WITH_CLI=true \
       ./build-xcframework.sh --release
   ```

   This produces dual device slices (`arm64` + `arm64e`) for iOS, macOS, and
   visionOS, while simulator slices remain `arm64`, and writes
   `PgpMobile.arm64e-build-manifest.json`.

   The older `scripts/experiments/build_apple_arm64e_xcframework.sh` remains a
   diagnostic/reproduction script for historical investigations. The repo-root
   `./build-xcframework.sh --release` path is the formal release build
   entrypoint.

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
