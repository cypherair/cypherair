---
name: rust-sync
description: Decide whether a Rust change requires the slow pinned XCFramework rebuild before Swift validation, and run it correctly. Use when changes touch pgp-mobile/src/**, Cargo.toml/Cargo.lock, UniFFI interface definitions, or build-xcframework.sh and Swift-side tests are about to run. Do NOT use for Rust-only test changes (pgp-mobile/tests/**), comment/doc edits, or work validated by cargo test alone.
---

The XCFramework rebuild is slow (~3–5 min cold). Run it only when required.

**Rebuild required** before `xcodebuild test` when, since the artifact was last
built, anything changed in: `pgp-mobile/src/**`, `Cargo.toml`/`Cargo.lock`,
UniFFI interface definitions, or `build-xcframework.sh`. These alter the
compiled artifact or generated bindings that Xcode links.

**Rebuild NOT required** for: `pgp-mobile/tests/**`- or `examples/**`-only
changes, docs edits outside the crate, or turns where only `cargo +stable test`
runs and no Swift-side validation follows.

The artifact gate is content-hashed. Its inputs: every `*.rs` under
`pgp-mobile/src/**` EXCEPT `**/tests.rs` (the `#[cfg(test)]` modules — free to
edit), plus `Cargo.toml`, `Cargo.lock`, `build.rs`, `uniffi-bindgen.rs`,
`build-xcframework.sh`, `scripts/build_apple_arm64e_xcframework.sh`, and
`third_party/arm64e-stage1-toolchain.pin.json`; the fingerprint also binds the
built slices themselves. An edit to any input — comments in non-test `.rs`
files included — fails every Xcode build until the sync runs. Outside the
gate: `pgp-mobile/tests/**`, `examples/**`, non-`.rs` files under `src`.
Because the stage1 pin is an input, a `repin-arm64e` rotation also invalidates
the local artifact — plan the rebuild into any re-pin.

**Procedure:** run the pinned sync command exactly as written in CLAUDE.md
"Build Commands" (the pinned tag is owned by docs/ARM64E_STATUS.md — never
substitute `latest`). Then run the Swift validation lane. Troubleshooting for
stale artifacts: docs/TESTING.md Section 2.4.

**Verify:** the rebuild refreshed `PgpMobile.arm64e-build-manifest.json`, the
generated bindings, and `PgpMobileSourceInputs.xcfilelist` (commit the last two
when they change), `python3 scripts/xcframework_source_fingerprint.py --check`
passes, and the Swift test lane passes against the new artifact.
