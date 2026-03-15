# UniFFI Bindgen: iOS .a vs macOS dylib

> Status: Under investigation. Current build script works correctly.

## Removed CLAUDE.md Content

The following comment was previously in CLAUDE.md (Build Commands section):

```
# Generate Swift bindings (MUST use iOS .a, not host dylib — UniFFI 0.31+ generates
# different checksums per target, and host dylib checksums won't match the iOS static lib)
cargo run --release --manifest-path pgp-mobile/Cargo.toml \
    --bin uniffi-bindgen generate \
    --library target/aarch64-apple-ios/release/libpgp_mobile.a \
    --language swift --out-dir bindings/
```

## Why It Was Removed

The claim that "UniFFI 0.31+ generates different checksums per target" could not be verified. Investigation found:

1. **UniFFI maintainer statement:** In [issue #2507](https://github.com/mozilla/uniffi-rs/issues/2507), a maintainer stated "The metadata created by different platforms should be identical" and the issue was closed with a documentation update noting "uniffi metadata is portable."

2. **Community practice:** Multiple tutorials and production projects (Ferrostar, Bitwarden, etc.) use a macOS host dylib for bindgen, then link against iOS `.a` files. This is the mainstream approach.

3. **UniFFI 0.31 changelog:** The checksum change mentioned ("method checksums no longer include the self type") is a cross-version change (0.30 vs 0.31), not a cross-target change.

4. **Clean build test (2026-03-15):** `build-xcframework.sh` was run from a fully clean state (all artifacts deleted). The script compiled a macOS `.dylib`, used it for bindgen, then linked against iOS `.a` files. Xcode build succeeded with no checksum mismatch or runtime issues.

## Current Build Script Behavior

`build-xcframework.sh` Step 4 temporarily injects `cdylib` into `Cargo.toml` via `sed`, compiles a macOS host `.dylib`, restores `Cargo.toml`, and uses the `.dylib` for `uniffi-bindgen generate`. This works correctly.

The `sed` mutation approach is fragile (if the process is killed by `SIGKILL`, `Cargo.toml` may be left modified), but functionally correct. A cleaner alternative would be to permanently include `cdylib` in `Cargo.toml`'s crate-type, but this is a low-priority improvement.

## Open Question

Whether passing an iOS `.a` directly to `uniffi-bindgen generate --library` works reliably with UniFFI 0.31 has not been tested. There was a [reported issue (#2324)](https://github.com/mozilla/uniffi-rs/issues/2324) with `.a` file parsing in an earlier version, though the root cause was unrelated. If a future investigation confirms `.a` works reliably, the build script could be simplified by removing the host dylib step entirely.
