#!/usr/bin/env bash
set -euo pipefail

# probe_arm64e_tls_codegen_gap.sh
#
# Demonstrates the current arm64e codegen gap between clang and Rust for a
# thread-local access path:
#   1. Build an arm64e C++ thread_local sample and dump the TLS wrapper.
#   2. Build an arm64e Rust thread_local sample and dump the analogous wrapper.
#   3. Patch the generated Rust LLVM IR with clang-like ptrauth function
#      attributes and show that the wrapper changes from `blr` to `blraaz`.

WORK_ROOT="$(mktemp -d /tmp/arm64e-tls-codegen-gap-XXXXXX)"
CPP_DIR="$WORK_ROOT/cpp"
RUST_DIR="$WORK_ROOT/rust"
PATCH_DIR="$WORK_ROOT/patched"
mkdir -p "$CPP_DIR" "$RUST_DIR" "$PATCH_DIR"

echo "work_root=$WORK_ROOT"

cat >"$CPP_DIR/tls.cpp" <<'EOF'
#include <iostream>
thread_local int value = 11;
int main() {
  std::cout << value << "\n";
  value += 1;
  std::cout << value << "\n";
  return 0;
}
EOF

xcrun clang++ -std=c++20 -S -emit-llvm -arch arm64e "$CPP_DIR/tls.cpp" -o "$CPP_DIR/tls.ll"
xcrun clang++ -std=c++20 -arch arm64e "$CPP_DIR/tls.cpp" -o "$CPP_DIR/tlspp"

cat >"$RUST_DIR/main.rs" <<'EOF'
use std::cell::Cell;
thread_local! { static VALUE: Cell<u32> = const { Cell::new(7) }; }
fn main() {
    VALUE.with(|v| {
        println!("{}", v.get());
        v.set(v.get() + 1);
        println!("{}", v.get());
    });
}
EOF

(
    cd "$RUST_DIR"
    cargo init --bin --quiet
    mkdir -p src
    cp main.rs src/main.rs
    cargo +nightly rustc -Zbuild-std --target arm64e-apple-darwin -- --emit=llvm-ir
)

RUST_LL="$(find "$RUST_DIR" -name '*.ll' | tail -n 1)"
cp "$RUST_LL" "$PATCH_DIR/original.ll"

python3 - <<'PY'
from pathlib import Path

src = Path("/tmp").glob("arm64e-tls-codegen-gap-*/patched/original.ll")
src = sorted(src)[-1]
text = src.read_text()
for n in [0, 1, 2, 3, 4, 7, 8, 9, 10]:
    text = text.replace(
        f'attributes #{n} = {{',
        f'attributes #{n} = {{ "ptrauth-auth-traps" "ptrauth-calls" "ptrauth-indirect-gotos" "ptrauth-returns" "target-features"="+pauth"',
    )
patched = src.with_name("attrs.ll")
patched.write_text(text)
print(patched)
PY

xcrun clang -arch arm64e -c "$PATCH_DIR/original.ll" -o "$PATCH_DIR/original.o"
xcrun clang -arch arm64e -c "$PATCH_DIR/attrs.ll" -o "$PATCH_DIR/attrs.o"

echo
echo "== clang tls wrapper =="
otool -tvV "$CPP_DIR/tlspp" | awk 'BEGIN{flag=0;count=0} /__ZTW5value:/{flag=1;count=0} flag{print;count++} count>12{exit}'

echo
echo "== rust tls wrapper before patch =="
otool -tvV "$PATCH_DIR/original.o" | awk 'BEGIN{flag=0;count=0} /VALUE0s_0B5_:/ {flag=1;count=0} flag{print;count++} count>14{exit}'

echo
echo "== rust tls wrapper after manual IR attrs =="
otool -tvV "$PATCH_DIR/attrs.o" | awk 'BEGIN{flag=0;count=0} /VALUE0s_0B5_:/ {flag=1;count=0} flag{print;count++} count>14{exit}'

echo
echo "== key IR markers =="
echo "-- clang --"
rg -n 'ptrauth|threadlocal.address' "$CPP_DIR/tls.ll" | sed -n '1,40p'
echo "-- rust original --"
rg -n 'ptrauth|threadlocal.address' "$PATCH_DIR/original.ll" | sed -n '1,40p'
echo "-- rust patched --"
rg -n 'ptrauth|threadlocal.address' "$PATCH_DIR/attrs.ll" | sed -n '1,40p'
