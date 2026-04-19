#!/bin/bash
# build-xcframework.sh — Automated build pipeline for pgp-mobile XCFramework.
#
# This script:
# 1. Cross-compiles pgp-mobile for iOS, visionOS, and macOS targets
# 2. Generates UniFFI Swift bindings
# 3. Creates the XCFramework
#
# Prerequisites:
# - Xcode (latest stable) with command-line tools
# - Rust stable with targets: aarch64-apple-ios, aarch64-apple-ios-sim,
#   aarch64-apple-darwin, aarch64-apple-visionos, aarch64-apple-visionos-sim
# - perl + make (for vendored OpenSSL compilation)
#
# Usage:
#   ./build-xcframework.sh [--release|--debug]
#
# First-time build compiles vendored OpenSSL from source (~3-5 minutes).
# Subsequent builds use cached artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/pgp-mobile/Cargo.toml"
BINDINGS_DIR="$SCRIPT_DIR/bindings"
XCFRAMEWORK_OUTPUT="$SCRIPT_DIR/PgpMobile.xcframework"

# Default to release build
BUILD_MODE="${1:---release}"
if [ "$BUILD_MODE" = "--debug" ]; then
    BUILD_DIR="debug"
    CARGO_FLAGS=""
else
    BUILD_DIR="release"
    CARGO_FLAGS="--release"
fi

echo "=== CypherAir: pgp-mobile XCFramework Build ==="
echo "Build mode: $BUILD_DIR"
echo ""

# Xcode consumes the packaged PgpMobile.xcframework. The target-specific
# archives below are intermediate inputs for that package. Any leftover
# target-specific `libpgp_mobile.dylib` is still treated as stale state because
# older direct-link settings or manual linker flags can pick it instead of the
# intended static archive. Only the host dylib used for UniFFI bindgen is
# allowed, and it is treated as a temporary file.
target_dylib_candidates=(
    "$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-ios/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-visionos/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/target/aarch64-apple-ios/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/target/aarch64-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/target/aarch64-apple-visionos/$BUILD_DIR/libpgp_mobile.dylib"
    "$SCRIPT_DIR/target/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.dylib"
)

cleanup_target_specific_dylibs() {
    for dylib in "${target_dylib_candidates[@]}"; do
        rm -f "$dylib"
    done
}

patch_generated_swift_bindings() {
    local swift_file="$1"

    if [ ! -f "$swift_file" ]; then
        return
    fi

    # Swift 6.2 treats shared raw pointers as non-Sendable. UniFFI 0.31.1
    # generates callback vtable pointers as plain static lets, so mark them
    # explicitly unsafe/nonisolated after generation instead of hand-editing
    # the checked-in generated file.
    perl -0pi -e 's/\n    static let vtablePtr: UnsafePointer<(UniffiVTableCallbackInterface[A-Za-z0-9_]+)> = \{/\n    nonisolated(unsafe) static let vtablePtr: UnsafePointer<$1> = {/g' "$swift_file"
}

assert_no_target_specific_dylibs() {
    local dylib
    local stale_found=0

    for dylib in "${target_dylib_candidates[@]}"; do
        if [ -f "$dylib" ]; then
            echo "  ✗ ERROR: Stale target-specific dylib found next to a Rust static archive:"
            echo "    $dylib"
            stale_found=1
        fi
    done

    if [ "$stale_found" -ne 0 ]; then
        exit 1
    fi
}

# ── Step 1: Verify Rust targets ──────────────────────────────────
echo "[1/11] Verifying Rust targets..."
if ! rustup target list --installed | grep -q "aarch64-apple-ios$"; then
    echo "  Installing aarch64-apple-ios target..."
    rustup target add aarch64-apple-ios
fi
if ! rustup target list --installed | grep -q "aarch64-apple-ios-sim"; then
    echo "  Installing aarch64-apple-ios-sim target..."
    rustup target add aarch64-apple-ios-sim
fi
if ! rustup target list --installed | grep -q "aarch64-apple-darwin"; then
    echo "  Installing aarch64-apple-darwin target..."
    rustup target add aarch64-apple-darwin
fi
if ! rustup target list --installed | grep -q "aarch64-apple-visionos$"; then
    echo "  Installing aarch64-apple-visionos target..."
    rustup target add aarch64-apple-visionos
fi
if ! rustup target list --installed | grep -q "aarch64-apple-visionos-sim$"; then
    echo "  Installing aarch64-apple-visionos-sim target..."
    rustup target add aarch64-apple-visionos-sim
fi
echo "  ✓ Targets ready"

# ── Step 2: Build for iOS device ─────────────────────────────────
echo ""
echo "[2/11] Building for aarch64-apple-ios (device)..."
echo "  Note: First build compiles vendored OpenSSL (~3-5 min)"
cargo build $CARGO_FLAGS --target aarch64-apple-ios --manifest-path "$MANIFEST"
DEVICE_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-ios/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$DEVICE_LIB" ]; then
    # Try parent target dir
    DEVICE_LIB="$SCRIPT_DIR/target/aarch64-apple-ios/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ Device library: $DEVICE_LIB"
ls -lh "$DEVICE_LIB"

# ── Step 3: Build for iOS simulator ──────────────────────────────
echo ""
echo "[3/11] Building for aarch64-apple-ios-sim (simulator)..."
cargo build $CARGO_FLAGS --target aarch64-apple-ios-sim --manifest-path "$MANIFEST"
SIM_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$SIM_LIB" ]; then
    SIM_LIB="$SCRIPT_DIR/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ Simulator library: $SIM_LIB"
ls -lh "$SIM_LIB"

# ── Step 4: Build for macOS (Apple Silicon) ──────────────────────
echo ""
echo "[4/11] Building for aarch64-apple-darwin (macOS)..."
cargo build $CARGO_FLAGS --target aarch64-apple-darwin --manifest-path "$MANIFEST"
MACOS_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-darwin/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$MACOS_LIB" ]; then
    MACOS_LIB="$SCRIPT_DIR/target/aarch64-apple-darwin/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ macOS library: $MACOS_LIB"
ls -lh "$MACOS_LIB"

# ── Step 5: Build for visionOS device ────────────────────────────
echo ""
echo "[5/11] Building for aarch64-apple-visionos (device)..."
cargo build $CARGO_FLAGS --target aarch64-apple-visionos --manifest-path "$MANIFEST"
VISIONOS_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-visionos/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$VISIONOS_LIB" ]; then
    VISIONOS_LIB="$SCRIPT_DIR/target/aarch64-apple-visionos/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ visionOS device library: $VISIONOS_LIB"
ls -lh "$VISIONOS_LIB"

# ── Step 6: Build for visionOS simulator ─────────────────────────
echo ""
echo "[6/11] Building for aarch64-apple-visionos-sim (simulator)..."
cargo build $CARGO_FLAGS --target aarch64-apple-visionos-sim --manifest-path "$MANIFEST"
VISIONOS_SIM_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$VISIONOS_SIM_LIB" ]; then
    VISIONOS_SIM_LIB="$SCRIPT_DIR/target/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ visionOS simulator library: $VISIONOS_SIM_LIB"
ls -lh "$VISIONOS_SIM_LIB"

# Clean target-specific output directories before bindgen creates any host dylib.
cleanup_target_specific_dylibs

# ── Step 7: Build host dylib for UniFFI bindgen ──────────────────
echo ""
echo "[7/11] Building host dylib for UniFFI bindgen..."
# Temporarily add cdylib to crate-type so cargo produces a .dylib for bindgen.
# The dylib is only needed on the macOS host for uniffi-bindgen — it is never
# shipped to iOS.  We restore the original Cargo.toml afterwards.
CARGO_TOML="$SCRIPT_DIR/pgp-mobile/Cargo.toml"

# Trap handler: restore Cargo.toml if the script is interrupted or fails
# while the backup exists (between cp and mv).
cleanup_cargo_toml() {
    if [ -f "$CARGO_TOML.bak" ]; then
        echo "  ⚠️  Restoring Cargo.toml from backup..."
        mv "$CARGO_TOML.bak" "$CARGO_TOML" 2>/dev/null || true
    fi
}
trap 'cleanup_cargo_toml' EXIT INT TERM

cp "$CARGO_TOML" "$CARGO_TOML.bak"
sed -i '' 's/crate-type = \["lib", "staticlib"\]/crate-type = ["lib", "staticlib", "cdylib"]/' "$CARGO_TOML"

cargo build $CARGO_FLAGS --manifest-path "$MANIFEST"

# Restore original Cargo.toml
mv "$CARGO_TOML.bak" "$CARGO_TOML"

# Clear the trap now that Cargo.toml is safely restored
trap - EXIT INT TERM

HOST_DYLIB="$SCRIPT_DIR/pgp-mobile/target/$BUILD_DIR/libpgp_mobile.dylib"
if [ ! -f "$HOST_DYLIB" ]; then
    HOST_DYLIB="$SCRIPT_DIR/target/$BUILD_DIR/libpgp_mobile.dylib"
fi
if [ ! -f "$HOST_DYLIB" ]; then
    echo "  ✗ ERROR: Host dylib not found. Cannot generate bindings."
    exit 1
fi
echo "  ✓ Host dylib: $HOST_DYLIB"

# ── Step 8: Generate Swift bindings ──────────────────────────────
echo ""
echo "[8/11] Generating UniFFI Swift bindings..."
rm -rf "$BINDINGS_DIR"
mkdir -p "$BINDINGS_DIR"
(cd "$SCRIPT_DIR/pgp-mobile" && cargo run $CARGO_FLAGS --bin uniffi-bindgen \
    generate --library "$HOST_DYLIB" --language swift --out-dir "$BINDINGS_DIR")
rm -f "$HOST_DYLIB"
patch_generated_swift_bindings "$BINDINGS_DIR/pgp_mobile.swift"

# Create module.modulemap alias expected by Xcode project build settings
# (UniFFI generates pgp_mobileFFI.modulemap, but project.pbxproj references module.modulemap)
if [ -f "$BINDINGS_DIR/pgp_mobileFFI.modulemap" ]; then
    cp "$BINDINGS_DIR/pgp_mobileFFI.modulemap" "$BINDINGS_DIR/module.modulemap"
fi

echo "  ✓ Bindings generated in $BINDINGS_DIR"
ls -la "$BINDINGS_DIR"

# ── Step 9: Create XCFramework ───────────────────────────────────
echo ""
echo "[9/11] Creating XCFramework..."
rm -rf "$XCFRAMEWORK_OUTPUT"
assert_no_target_specific_dylibs

# Move the modulemap and header to a headers directory
HEADERS_DIR="$BINDINGS_DIR/headers"
mkdir -p "$HEADERS_DIR"
if [ -f "$BINDINGS_DIR/pgp_mobileFFI.h" ]; then
    cp "$BINDINGS_DIR/pgp_mobileFFI.h" "$HEADERS_DIR/"
fi
if [ -f "$BINDINGS_DIR/pgp_mobileFFI.modulemap" ]; then
    cp "$BINDINGS_DIR/pgp_mobileFFI.modulemap" "$HEADERS_DIR/module.modulemap"
fi

xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HEADERS_DIR" \
    -library "$SIM_LIB" -headers "$HEADERS_DIR" \
    -library "$MACOS_LIB" -headers "$HEADERS_DIR" \
    -library "$VISIONOS_LIB" -headers "$HEADERS_DIR" \
    -library "$VISIONOS_SIM_LIB" -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK_OUTPUT"

echo "  ✓ XCFramework created: $XCFRAMEWORK_OUTPUT"

# ── Step 10: Report binary size ──────────────────────────────────
echo ""
echo "[10/11] Binary size report..."
DEVICE_SIZE=$(stat -f%z "$DEVICE_LIB" 2>/dev/null || stat --printf="%s" "$DEVICE_LIB" 2>/dev/null || echo "unknown")
SIM_SIZE=$(stat -f%z "$SIM_LIB" 2>/dev/null || stat --printf="%s" "$SIM_LIB" 2>/dev/null || echo "unknown")
MACOS_SIZE=$(stat -f%z "$MACOS_LIB" 2>/dev/null || stat --printf="%s" "$MACOS_LIB" 2>/dev/null || echo "unknown")
VISIONOS_SIZE=$(stat -f%z "$VISIONOS_LIB" 2>/dev/null || stat --printf="%s" "$VISIONOS_LIB" 2>/dev/null || echo "unknown")
VISIONOS_SIM_SIZE=$(stat -f%z "$VISIONOS_SIM_LIB" 2>/dev/null || stat --printf="%s" "$VISIONOS_SIM_LIB" 2>/dev/null || echo "unknown")
echo "  Device library: $DEVICE_SIZE bytes"
echo "  Simulator library: $SIM_SIZE bytes"
echo "  macOS library: $MACOS_SIZE bytes"
echo "  visionOS device library: $VISIONOS_SIZE bytes"
echo "  visionOS simulator library: $VISIONOS_SIM_SIZE bytes"

# ── Step 11: Sync Swift bindings to Xcode source tree ────────────
echo ""
echo "[11/11] Syncing generated bindings to Sources/PgpMobile/..."
SWIFT_BINDING_SRC="$BINDINGS_DIR/pgp_mobile.swift"
SWIFT_BINDING_DST="$SCRIPT_DIR/Sources/PgpMobile/pgp_mobile.swift"
if [ -f "$SWIFT_BINDING_SRC" ]; then
    cp "$SWIFT_BINDING_SRC" "$SWIFT_BINDING_DST"
    echo "  ✓ pgp_mobile.swift synced"
else
    echo "  ⚠️ WARNING: pgp_mobile.swift not found in bindings — skipped"
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Next steps:"
echo "  1. Xcode links $XCFRAMEWORK_OUTPUT."
echo "  2. pgp-mobile/target/... contains Cargo build intermediates only."
echo "  3. After a successful build, you may run:"
echo "     cargo clean --manifest-path pgp-mobile/Cargo.toml"
echo "     to reclaim Cargo target space without breaking Xcode linkage."
echo "  4. If Swift 6.2 concurrency warnings occur:"
echo "     - Use @preconcurrency import PgpMobile"
echo "     - Or add @unchecked Sendable conformances in an extension file"
