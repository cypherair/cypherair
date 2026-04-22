# Draft Rust Issue: `arm64e-apple-darwin` host binaries crash on launch

## Summary

On a local Apple Silicon macOS host, `arm64e-apple-darwin` binaries built with
nightly Rust and `-Zbuild-std` crash immediately at runtime with
`EXC_BAD_ACCESS / SIGSEGV`, even for a standalone `hello world`.

This appears to conflict with the current Rust target documentation, which says
that `arm64e-apple-darwin` is Tier 3 (with Host Tools) and that the target
supports running binaries on macOS platforms with `arm64e` architecture:

- <https://doc.rust-lang.org/rustc/platform-support/arm64e-apple-darwin.html>

## Environment

- macOS `26.4.1` (`25E253`)
- Apple Silicon host
- Xcode `17E202`
- Apple clang `21.0.0 (clang-2100.0.123.102)`
- Stable Rust:
  - `rustc 1.95.0 (59807616e 2026-04-14)`
- Nightly sampled:
  - `nightly` -> `rustc 1.97.0-nightly (e9e32aca5 2026-04-17)`
  - `nightly-2026-04-01` -> `rustc 1.96.0-nightly (48cc71ee8 2026-03-31)`
  - `nightly-2026-03-15` -> `rustc 1.96.0-nightly (03749d625 2026-03-14)`
  - `nightly-2026-02-15` -> `rustc 1.95.0-nightly (a33907a7a 2026-02-14)`

## Minimal Reproduction

### Platform sanity check

The following works on the same machine:

```bash
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void) {
  puts("hello-c");
  return 0;
}
EOF
xcrun clang -arch arm64e hello.c -o hello-c
./hello-c
```

Observed result:

```text
hello-c
```

### Rust scratch binary

```bash
mkdir /tmp/arm64e-rust-hello && cd /tmp/arm64e-rust-hello
cargo init --bin --quiet
cat > src/main.rs <<'EOF'
fn main() {
    println!("hello");
}
EOF
rustup component add rust-src --toolchain nightly
cargo +nightly build -Zbuild-std --target arm64e-apple-darwin
./target/arm64e-apple-darwin/debug/arm64e-rust-hello
```

Observed result:

- process exits with `139`
- no stdout is printed
- crash report shows `EXC_BAD_ACCESS / SIGSEGV`

Representative crash report from local run:

- `~/Library/Logs/DiagnosticReports/arm64e-hashset-zzKjsb-2026-04-22-041533.ips`

Representative frames:

- `std::thread::current::id::get_or_init`
- `_tlv_get_addr`
- `std::rt::init`
- `std::rt::lang_start_internal`

## Additional Evidence

The same environment also crashes on a real project test binary for
`arm64e-apple-darwin`:

```bash
cargo +nightly test -Zbuild-std --target arm64e-apple-darwin \
  --manifest-path pgp-mobile/Cargo.toml \
  --test certificate_merge_tests \
  test_merge_public_certificate_expiry_refresh_profile_a -- --exact
```

Observed result:

```text
signal: 11, SIGSEGV: invalid memory reference
```

However, the corresponding `arm64` host test passes.

## Toolchain Sampling

I sampled four nightly toolchains on the same machine:

| Toolchain | Scratch build | Scratch run | Project test |
|---|---:|---:|---:|
| `nightly` | 0 | 139 | 101 |
| `nightly-2026-04-01` | 0 | 139 | 101 |
| `nightly-2026-03-15` | 0 | 139 | 101 |
| `nightly-2026-02-15` | 0 | 139 | 101 |

Interpretation:

- scratch `hello world` consistently builds but crashes at runtime
- the sampled window suggests this is **not obviously a regression from just the most recent nightly**

## Notes

- Re-signing the scratch binary with ad-hoc signing did not change the crash.
- The binary is already linker-signed / ad-hoc signed by default.
- A same-host `clang -arch arm64e` C binary runs successfully, so this does not
  currently look like a generic host inability to run all arm64e binaries.

## Question

Is the expectation that `arm64e-apple-darwin` host binaries should currently be
viable on local macOS, or is the current docs wording stronger than the target's
real runtime support level?
