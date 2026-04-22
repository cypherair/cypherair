# arm64e macOS Unit Test Crash Investigation

## Summary

This note captures the current root-cause evidence for the `macOS` unit-test
crashes on the `codex/apple-arm64e-unified-experiment` branch after enabling
Xcode's Enhanced Security `Authenticate Pointers` setting.

The important conclusion is:

- the failing Xcode unit tests are **not** the smallest reproduction
- the issue reproduces in **pure Rust** on `arm64e-apple-darwin`
- the issue reproduces even in a standalone scratch Cargo binary outside this repo

That makes the current leading diagnosis:

- **this is primarily an `arm64e` Rust host-runtime / toolchain problem**
- not a Swift UI problem
- not an XCTest harness problem
- not currently a CypherAir business-logic bug

## Evidence Collected

### 1. Original Xcode macOS unit-test failures

Running:

```bash
xcodebuild test -scheme CypherAir -testPlan CypherAir-UnitTests \
    -destination 'platform=macOS'
```

showed repeated:

```text
Restarting after unexpected exit, crash, or test timeout
```

Crash reports were written under:

```text
~/Library/Logs/DiagnosticReports/CypherAir-2026-04-22-0403*.ips
```

Representative crash signatures:

- `CypherAir-2026-04-22-040331.ips`
  - `EXC_BAD_ACCESS / SIGSEGV`
  - stack includes
    - `PgpEngine.mergePublicCertificateUpdate`
    - `pgp_mobile::keys::merge_public_certificate_update`
    - `sequoia_openpgp::packet::signature::Signature::merge_internal`
- `CypherAir-2026-04-22-040304.ips`
  - `EXC_BAD_ACCESS / SIGSEGV`
  - stack includes
    - `PgpEngine.discoverCertificateSelectors`
    - `pgp_mobile::keys::discover_certificate_selectors`

Repeated crash reports also showed `_tlv_get_addr` and Rust std TLS-related
symbols such as `std::hash::RandomState::new::KEYS`.

### 2. Pure Rust control vs repro

Control cases on the default host architecture (`arm64`) passed:

```bash
cargo test --manifest-path pgp-mobile/Cargo.toml \
    --test certificate_merge_tests \
    test_merge_public_certificate_expiry_refresh_profile_a -- --exact

cargo test --manifest-path pgp-mobile/Cargo.toml \
    --test selector_discovery_tests \
    test_discover_certificate_selectors_profile_a_generated_cert_exposes_selectors -- --exact
```

Both passed on `arm64`.

The same cases on `arm64e-apple-darwin` crashed:

```bash
cargo +nightly test -Zbuild-std --target arm64e-apple-darwin \
    --manifest-path pgp-mobile/Cargo.toml \
    --test certificate_merge_tests \
    test_merge_public_certificate_expiry_refresh_profile_a -- --exact

cargo +nightly test -Zbuild-std --target arm64e-apple-darwin \
    --manifest-path pgp-mobile/Cargo.toml \
    --test selector_discovery_tests \
    test_discover_certificate_selectors_profile_a_generated_cert_exposes_selectors -- --exact
```

Observed result for both:

```text
signal: 11, SIGSEGV: invalid memory reference
```

This proves the crash is reproducible **without UniFFI and without Swift/XCTest**.

### 3. Standalone scratch Cargo binary

The strongest evidence came from a scratch binary outside the repo.

On the default host target (`arm64`), a trivial program:

```rust
fn main() {
    println!("hello");
}
```

ran successfully.

On `arm64e-apple-darwin`, the same trivial program crashed:

```bash
cargo +nightly run -Zbuild-std --target arm64e-apple-darwin
```

Observed exit:

```text
EXIT:139
```

Diagnostic report:

```text
~/Library/Logs/DiagnosticReports/arm64e-hashset-zzKjsb-2026-04-22-041533.ips
```

Key details:

- `EXC_BAD_ACCESS / SIGSEGV`
- crash occurs before any CypherAir or Sequoia code runs
- stack includes
  - `std::thread::current::id::get_or_init`
  - `_tlv_get_addr`
  - `std::rt::init`
  - `std::rt::lang_start_internal`

That points below CypherAir and below Sequoia, into Rust runtime / TLS startup on
the current `arm64e-apple-darwin` toolchain path.

## Current Conclusion

The present evidence supports this ordering of likelihood:

1. `arm64e-apple-darwin` Rust host binaries are currently not viable on this
   toolchain path for local execution.
2. The Xcode macOS unit-test crashes are a downstream symptom of that lower-level
   runtime issue.
3. `discover_certificate_selectors` and `merge_public_certificate_update` appear
   in crash stacks because those tests happen to exercise Rust code heavily, not
   because they are uniquely broken business paths.

## Practical Impact

For the current experiment branch:

- `iOS arm64e` build probing remains separately interesting
- `macOS unit tests under arm64e` should currently be treated as **blocked by
  Rust host-runtime instability**
- further Swift/XCTest debugging is unlikely to produce the primary root cause

## Reproduction Helper

Use:

```bash
./scripts/experiments/repro_arm64e_rust_host_crashes.sh
```

to rerun the minimal host-side control/repro matrix without launching the full
Xcode macOS unit-test host.
