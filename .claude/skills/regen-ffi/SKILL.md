---
name: regen-ffi
description: Regenerate UniFFI Swift bindings from Rust crate
disable-model-invocation: true
---

Regenerate the UniFFI Swift bindings after changes to the `pgp-mobile` Rust crate public API.

## Steps

1. Build the HOST (macOS) dylib — this is NOT an iOS artifact, it's used only for bindgen:
   ```bash
   cargo build --release --manifest-path pgp-mobile/Cargo.toml
   ```

2. Generate Swift bindings from the dylib:
   ```bash
   cargo run --bin uniffi-bindgen generate --library target/release/libpgp_mobile.dylib \
       --language swift --out-dir bindings/
   ```

3. Cross-compile for both iOS targets to verify the static lib builds:
   ```bash
   cargo build --release --target aarch64-apple-ios --manifest-path pgp-mobile/Cargo.toml
   cargo build --release --target aarch64-apple-ios-sim --manifest-path pgp-mobile/Cargo.toml
   ```

4. Recreate the XCFramework:
   ```bash
   xcodebuild -create-xcframework \
       -library target/aarch64-apple-ios/release/libpgp_mobile.a -headers bindings/ \
       -library target/aarch64-apple-ios-sim/release/libpgp_mobile.a -headers bindings/ \
       -output PgpMobile.xcframework
   ```

5. Run tests to verify nothing broke:
   ```bash
   cargo test --manifest-path pgp-mobile/Cargo.toml
   xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
       -destination 'platform=iOS Simulator,name=iPhone 17'
   ```

## Notes

- Do NOT modify the generated `pgp_mobile.swift` directly — it will be overwritten on regeneration.
- If the generated bindings produce Swift 6.2 concurrency warnings, see CONVENTIONS.md §3 for the approved workarounds.
- The first build compiles vendored OpenSSL from source (~3-5 min). Subsequent builds are cached.
