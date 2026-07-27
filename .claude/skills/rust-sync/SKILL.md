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

The artifact gate is content-hashed, so *any* edit inside `pgp-mobile/src/**` —
comments included — makes the Xcode build fail until the sync runs. The hash
covers `pgp-mobile/src`, `Cargo.toml`, `Cargo.lock`, `build.rs`, and
`uniffi-bindgen.rs`; `pgp-mobile/tests` and `examples` are deliberately outside
it.

**Procedure:** run the pinned sync command exactly as written in CLAUDE.md
"Build Commands" (the pinned tag is owned by docs/ARM64E_STATUS.md — never
substitute `latest`). Then run the Swift validation lane. Troubleshooting for
stale artifacts: docs/TESTING.md Section 2.4.

**Verify:** the rebuild refreshed `PgpMobile.arm64e-build-manifest.json`, the
generated bindings, and `PgpMobileSourceInputs.xcfilelist` (commit the last two
when they change), `python3 scripts/xcframework_source_fingerprint.py --check`
passes, and the Swift test lane passes against the new artifact.
