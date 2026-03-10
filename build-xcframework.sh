#!/bin/bash
# build-xcframework.sh — Automated build pipeline for pgp-mobile XCFramework.
#
# This script:
# 1. Cross-compiles pgp-mobile for iOS device and simulator targets
# 2. Generates UniFFI Swift bindings
# 3. Creates the XCFramework
#
# Prerequisites:
# - Xcode (latest stable) with command-line tools
# - Rust stable with targets: aarch64-apple-ios, aarch64-apple-ios-sim
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

echo "=== Cypher Air: pgp-mobile XCFramework Build ==="
echo "Build mode: $BUILD_DIR"
echo ""

# ── Step 1: Verify Rust targets ──────────────────────────────────
echo "[1/7] Verifying Rust targets..."
if ! rustup target list --installed | grep -q "aarch64-apple-ios$"; then
    echo "  Installing aarch64-apple-ios target..."
    rustup target add aarch64-apple-ios
fi
if ! rustup target list --installed | grep -q "aarch64-apple-ios-sim"; then
    echo "  Installing aarch64-apple-ios-sim target..."
    rustup target add aarch64-apple-ios-sim
fi
echo "  ✓ Targets ready"

# ── Step 2: Build for iOS device ─────────────────────────────────
echo ""
echo "[2/7] Building for aarch64-apple-ios (device)..."
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
echo "[3/7] Building for aarch64-apple-ios-sim (simulator)..."
cargo build $CARGO_FLAGS --target aarch64-apple-ios-sim --manifest-path "$MANIFEST"
SIM_LIB="$SCRIPT_DIR/pgp-mobile/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.a"
if [ ! -f "$SIM_LIB" ]; then
    SIM_LIB="$SCRIPT_DIR/target/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.a"
fi
echo "  ✓ Simulator library: $SIM_LIB"
ls -lh "$SIM_LIB"

# ── Step 4: Build host dylib for UniFFI bindgen ──────────────────
echo ""
echo "[4/7] Building host dylib for UniFFI bindgen..."
cargo build $CARGO_FLAGS --manifest-path "$MANIFEST"
HOST_DYLIB="$SCRIPT_DIR/pgp-mobile/target/$BUILD_DIR/libpgp_mobile.dylib"
if [ ! -f "$HOST_DYLIB" ]; then
    HOST_DYLIB="$SCRIPT_DIR/target/$BUILD_DIR/libpgp_mobile.dylib"
fi
echo "  ✓ Host dylib: $HOST_DYLIB"

# ── Step 5: Generate Swift bindings ──────────────────────────────
echo ""
echo "[5/7] Generating UniFFI Swift bindings..."
rm -rf "$BINDINGS_DIR"
mkdir -p "$BINDINGS_DIR"
cargo run $CARGO_FLAGS --manifest-path "$MANIFEST" --bin uniffi-bindgen \
    generate --library "$HOST_DYLIB" --language swift --out-dir "$BINDINGS_DIR"
echo "  ✓ Bindings generated in $BINDINGS_DIR"
ls -la "$BINDINGS_DIR"

# ── Step 6: Create XCFramework ───────────────────────────────────
echo ""
echo "[6/7] Creating XCFramework..."
rm -rf "$XCFRAMEWORK_OUTPUT"

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
    -output "$XCFRAMEWORK_OUTPUT"

echo "  ✓ XCFramework created: $XCFRAMEWORK_OUTPUT"

# ── Step 7: Check binary size ────────────────────────────────────
echo ""
echo "[7/7] Binary size check..."
DEVICE_SIZE=$(stat -f%z "$DEVICE_LIB" 2>/dev/null || stat --printf="%s" "$DEVICE_LIB" 2>/dev/null || echo "unknown")
SIM_SIZE=$(stat -f%z "$SIM_LIB" 2>/dev/null || stat --printf="%s" "$SIM_LIB" 2>/dev/null || echo "unknown")
echo "  Device library: $DEVICE_SIZE bytes"
echo "  Simulator library: $SIM_SIZE bytes"

# Check if under 10 MB threshold (C1.6)
if [ "$DEVICE_SIZE" != "unknown" ] && [ "$DEVICE_SIZE" -gt 10485760 ]; then
    echo "  ⚠️ WARNING: Device library exceeds 10 MB threshold (C1.6)"
else
    echo "  ✓ Device library within 10 MB threshold"
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy $BINDINGS_DIR/pgp_mobile.swift to your Xcode project"
echo "  2. Add $XCFRAMEWORK_OUTPUT to your Xcode project"
echo "  3. If Swift 6.2 concurrency warnings occur:"
echo "     - Use @preconcurrency import PgpMobile"
echo "     - Or add @unchecked Sendable conformances in an extension file"
