# arm64e macOS Unit Test Crash Investigation

## Summary

This note captures the current root-cause evidence for the `macOS` unit-test
crashes on the `codex/apple-arm64e-unified-experiment` branch after enabling
Xcode's Enhanced Security `Authenticate Pointers` setting.

The important conclusion is:

- the failing Xcode unit tests are **not** the smallest reproduction
- the issue reproduces in **pure Rust** on `arm64e-apple-darwin`
- the issue reproduces even in a standalone scratch Cargo binary outside this repo
- the same host can run an `arm64e` binary built by `clang`

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

### 4. Platform sanity check: `clang` arm64e works

On the same machine, the following succeeds:

```bash
xcrun clang -arch arm64e hello.c -o hello-c
./hello-c
```

Observed output:

```text
hello-c
```

This matters because it makes the current issue look much less like
"the machine cannot run arm64e binaries at all" and much more like
"the current Rust host-runtime path is not viable on this environment."

### 5. Ad-hoc re-signing does not change the crash

The scratch Rust `arm64e` binary was inspected with `codesign -dv --verbose=4`.
It was already linker-signed / ad-hoc signed by default. Re-signing a copy with:

```bash
codesign --force --sign - <binary>
```

did not change behavior. The re-signed binary still exited `139`.

This reduces the likelihood that the current host crash is primarily a code
signing issue.

### 6. Toolchain time-sampling

I sampled four nightly toolchains on the same host:

| Toolchain | Rust version | Scratch build | Scratch run | `certificate_merge_tests` |
|---|---|---:|---:|---:|
| `nightly` | `1.97.0-nightly (e9e32aca5 2026-04-17)` | 0 | 139 | 101 |
| `nightly-2026-04-01` | `1.96.0-nightly (48cc71ee8 2026-03-31)` | 0 | 139 | 101 |
| `nightly-2026-03-15` | `1.96.0-nightly (03749d625 2026-03-14)` | 0 | 139 | 101 |
| `nightly-2026-02-15` | `1.95.0-nightly (a33907a7a 2026-02-14)` | 0 | 139 | 101 |

For the project test, the failure shape remained:

```text
signal: 11, SIGSEGV: invalid memory reference
```

For the scratch binary, the run log remained empty and the process exited `139`.

This sampled window does **not** look like a very recent regression confined to
the latest nightly.

### 7. clang vs Rust TLS codegen gap

Further investigation narrowed the most actionable difference to the TLS access
path under `arm64e`.

On the same host:

- a C/C++ `thread_local` sample compiled with `clang -arch arm64e` runs
  successfully
- an equivalent Rust `thread_local!` sample compiled for
  `arm64e-apple-darwin` crashes

The generated code differs in an important way:

- clang emits a TLS wrapper that uses an authenticated indirect call
  (`blraaz`)
- Rust currently emits a TLS wrapper that uses a plain indirect call (`blr`)

Representative Rust wrapper before patching IR:

```text
adrp x0, ...
ldr  x0, [x0]
ldr  x8, [x0]
blr  x8
```

Representative wrapper after manually patching the Rust-generated LLVM IR to
add clang-like `ptrauth-*` function attributes:

```text
adrp   x0, ...
ldr    x0, [x0]
ldr    x8, [x0]
blraaz x8
```

This matters because it means the current investigation now has a plausible
upstream repair direction:

- Rust's `arm64e-apple-darwin` codegen appears to be missing clang-like
  pointer-authentication semantics for TLS/indirect-call paths.

This is stronger evidence than the earlier "Rust crashes in `_tlv_get_addr`"
observation, because it provides a concrete codegen-level difference rather
than only a runtime symptom.

### 8. Source-level Rust patch spike

I then moved from manual LLVM IR patching to a source-level Rust compiler spike
in a temporary Rust checkout:

```text
/Users/tianren/coding/rust
branch: codex/arm64e-darwin-ptrauth-spike
```

The spike currently has two layers:

1. `rustc_codegen_llvm/src/attributes.rs`
   - default `arm64e-apple-darwin` function attributes:
     - `ptrauth-auth-traps`
     - `ptrauth-calls`
     - `ptrauth-indirect-gotos`
     - `ptrauth-returns`
   - plus `+pauth` in `target-features`
2. `rustc_codegen_llvm/src/context.rs`
   - add a clang-style `ptrauth.abi-version` module flag for
     `arm64e-apple-darwin`
3. `rustc_codegen_ssa/src/back/metadata.rs`
   - set Mach-O metadata objects to
     `CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI`
     (`CPU_SUBTYPE_LIB64` in Apple headers has the same bit pattern)

This split matters:

- function attributes fix the TLS wrapper call sequence
- the `ptrauth.abi-version` / metadata subtype work fixes the
  `arm64e.old` vs `arm64e` linker rejection

### 9. What the patched compiler now does

Using the patched stage1 compiler, the following now succeed for
`arm64e-apple-darwin`:

- scratch Rust `hello world`
- scratch Rust `thread_local!` sample
- scratch `std::thread::current().id()` sample

Representative results:

```text
hello-stage1
exit:0
```

```text
7
8
exit:0
```

```text
ThreadId(1)
```

That means the original "Rust arm64e host binaries crash immediately" problem
is no longer reproduced for these minimal host samples with the patched
compiler.

### 10. Remaining limitation

The direct host-runtime issue appears fixed for minimal programs, but downstream
validation through `cargo` is still imperfect when using the temporary stage1
toolchain as a rustup-linked toolchain:

- `cargo` itself falls back to the installed nightly cargo binary
- the ad-hoc stage1 sysroot layout still needs manual help for some host/target
  crates during downstream verification

This currently affects the convenience of validating `pgp-mobile` end-to-end
through normal cargo/test workflows, but it does **not** negate the stronger
result above:

- the patched compiler can now produce runnable `arm64e-apple-darwin` host
  binaries

So the investigation has moved from:

- "why does Rust arm64e crash at startup?"

to:

- "how do we turn this local patch spike into a clean upstreamable Rust/LLVM
  change and a smoother validation workflow?"

## Current Conclusion

The present evidence supports this ordering of likelihood:

1. `arm64e-apple-darwin` Rust host binaries are currently not viable on this
   local toolchain path for host execution.
2. The Xcode macOS unit-test crashes are a downstream symptom of that lower-level
   runtime issue.
3. `discover_certificate_selectors` and `merge_public_certificate_update` appear
   in crash stacks because those tests happen to exercise Rust code heavily, not
   because they are uniquely broken business paths.
4. Within the sampled nightly range (`2026-02-15` through current nightly), the
   problem looks target-wide rather than like an obvious recent regression.
5. The most actionable remaining hypothesis is now a codegen/ABI gap in
   `arm64e` TLS/indirect-call pointer authentication rather than a generic
   application-layer crash.
6. A source-level Rust patch spike now fixes the minimal host reproductions,
   which strongly suggests the core issue is in Rust's `arm64e` codegen / ABI
   glue rather than in CypherAir or Sequoia.

## Practical Impact

For the current experiment branch:

- `iOS arm64e` build probing remains separately interesting
- `macOS unit tests under arm64e` should currently be treated as **blocked by
  Rust host-runtime instability**
- further Swift/XCTest debugging is unlikely to produce the primary root cause
- the next-best escalation target is Rust/toolchain investigation or upstream
  reporting, not more app-layer debugging

## Reproduction Helper

Use:

```bash
./scripts/experiments/repro_arm64e_rust_host_crashes.sh
```

to rerun the minimal host-side control/repro matrix without launching the full
Xcode macOS unit-test host.

Use:

```bash
./scripts/experiments/probe_arm64e_tls_codegen_gap.sh
```

to reproduce the clang-vs-Rust TLS wrapper difference and the manual IR
attribute experiment that changes Rust's wrapper from `blr` to `blraaz`.
