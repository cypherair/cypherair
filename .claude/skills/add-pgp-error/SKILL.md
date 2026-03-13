---
name: add-pgp-error
description: Add a new PgpError variant across Rust FFI and Swift
disable-model-invocation: true
---

Add a new PgpError variant: $ARGUMENTS

## Steps

1. Add the new variant to `pgp-mobile/src/error.rs` in the `PgpError` enum.
2. Add the corresponding case to `Sources/Models/PGPError.swift` — the enum must stay 1:1 with Rust.
3. Add a user-facing error message for the new case in `Localizable.xcstrings` (both English and Simplified Chinese).
4. Regenerate FFI bindings if the error enum is exposed via UniFFI:
   ```bash
   cargo build --release --manifest-path pgp-mobile/Cargo.toml
   cargo run --bin uniffi-bindgen generate --library target/release/libpgp_mobile.dylib \
       --language swift --out-dir bindings/
   ```
5. Verify both sides compile and tests pass:
   ```bash
   cargo test --manifest-path pgp-mobile/Cargo.toml
   xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
       -destination 'platform=iOS Simulator,name=iPhone 17'
   ```
6. Add a test that triggers the new error variant and verifies it maps correctly to the Swift enum case.
