#!/bin/bash
# build_apple_arm64e_xcframework.sh — branch-local Apple arm64e experiment.
#
# This script:
# 1. Reproduces the stable arm64e baseline failures for iOS and Darwin.
# 2. Builds Apple arm64e device artifacts using the locally linked patched Rust
#    toolchain while keeping simulator slices on stable arm64.
# 3. Generates Swift bindings using an arm64e-apple-darwin host dylib built by
#    that same patched toolchain.
# 4. Packages PgpMobile.xcframework and runs generic iOS/macOS build probes
#    using ARCHS=arm64e without modifying the tracked Xcode project.
#
# Dependency note:
# This script intentionally relies on a layered downstream carry chain:
# pgp-mobile -> CypherAir openssl-src-rs fork branch
#               `carry/apple-arm64e-openssl-fork`
#            -> CypherAir OpenSSL fork branch
#               `carry/apple-arm64e-targets`
# Keep that layering explicit so the openssl-src-rs branch is not mistaken for
# a standalone upstreamable change before the underlying OpenSSL target
# definitions land upstream.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$REPO_ROOT/pgp-mobile/Cargo.toml"
XCFRAMEWORK_OUTPUT="$REPO_ROOT/PgpMobile.xcframework"
BINDINGS_DIR="$REPO_ROOT/bindings"
SOURCES_BINDING="$REPO_ROOT/Sources/PgpMobile/pgp_mobile.swift"
EXPERIMENT_ROOT="$REPO_ROOT/pgp-mobile/target/apple-arm64e-experiment"
EXPERIMENT_CARGO_HOME="$EXPERIMENT_ROOT/cargo-home"
EXPERIMENT_TARGET_DIR="$EXPERIMENT_ROOT/build"
GENERATED_BINDINGS_DIR="$EXPERIMENT_ROOT/generated-bindings"
ARM64E_TOOLCHAIN="stage1-arm64e-patch"
STABLE_TOOLCHAIN="stable"
NIGHTLY_TOOLCHAIN="nightly"

BUILD_MODE="${1:---release}"
if [ "$BUILD_MODE" = "--debug" ]; then
    BUILD_DIR="debug"
    CARGO_FLAGS=""
else
    BUILD_DIR="release"
    CARGO_FLAGS="--release"
fi

baseline_root=""

log_step() {
    echo
    echo "[$1] $2"
}

cleanup() {
    if [ -n "$baseline_root" ] && [ -d "$baseline_root" ]; then
        rm -rf "$baseline_root"
    fi

    if [ -f "$MANIFEST.bak.apple-arm64e-experiment" ]; then
        mv "$MANIFEST.bak.apple-arm64e-experiment" "$MANIFEST" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

require_toolchain() {
    local toolchain="$1"
    if ! rustup toolchain list | sed 's/ .*//' | grep -Eq "^${toolchain}(-.*)?$"; then
        echo "error: missing Rust toolchain '${toolchain}'." >&2
        exit 1
    fi
}

ensure_component() {
    local toolchain="$1"
    local component="$2"
    if ! rustup component list --toolchain "${toolchain}" | grep -q "^${component} .*installed"; then
        echo "  Installing ${component} for ${toolchain}..."
        rustup component add "${component}" --toolchain "${toolchain}"
    fi
}

run_expected_failure() {
    local label="$1"
    local expected_substring="$2"
    local log_file="$3"
    shift 3

    set +e
    "$@" >"$log_file" 2>&1
    local status=$?
    set -e

    if [ "$status" -eq 0 ]; then
        echo "error: ${label} unexpectedly succeeded." >&2
        cat "$log_file" >&2
        exit 1
    fi

    if ! grep -Fq "$expected_substring" "$log_file"; then
        echo "error: ${label} failed, but not with the expected message." >&2
        cat "$log_file" >&2
        exit 1
    fi

    echo "  ✓ ${label}"
    grep -F "$expected_substring" "$log_file" | head -n 1
}

seed_experiment_cache() {
    log_step "seed" "Fetching dependencies into the experiment Cargo cache..."
    mkdir -p "$EXPERIMENT_CARGO_HOME" "$EXPERIMENT_TARGET_DIR"
    env \
        CARGO_HOME="$EXPERIMENT_CARGO_HOME" \
        CARGO_TARGET_DIR="$EXPERIMENT_TARGET_DIR" \
        cargo +"$NIGHTLY_TOOLCHAIN" fetch --manifest-path "$MANIFEST"
}

reset_experiment_build_state() {
    log_step "clean" "Resetting experiment build artifacts..."
    rm -rf "$EXPERIMENT_TARGET_DIR" "$GENERATED_BINDINGS_DIR"
    mkdir -p "$EXPERIMENT_TARGET_DIR"
}

patch_generated_swift_bindings() {
    local swift_file="$1"

    if [ ! -f "$swift_file" ]; then
        return
    fi

    perl -0pi -e 's/\n    static let vtablePtr: UnsafePointer<(UniffiVTableCallbackInterface[A-Za-z0-9_]+)> = \{/\n    nonisolated(unsafe) static let vtablePtr: UnsafePointer<$1> = {/g' "$swift_file"
}

sync_file_if_changed() {
    local src="$1"
    local dst="$2"

    if [ ! -f "$src" ]; then
        echo "error: generated file missing: $src" >&2
        exit 1
    fi

    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        echo "  ✓ $(basename "$dst") unchanged"
        return
    fi

    cp "$src" "$dst"
    echo "  ✓ synced $(basename "$dst")"
}

build_rust_artifact() {
    local label="$1"
    local toolchain="$2"
    local target="$3"
    shift 3

    log_step "$label" "Building ${target}..."
    env \
        CARGO_HOME="$EXPERIMENT_CARGO_HOME" \
        CARGO_TARGET_DIR="$EXPERIMENT_TARGET_DIR" \
        cargo +"$toolchain" build $CARGO_FLAGS "$@" --target "$target" --manifest-path "$MANIFEST"
}

resolve_library_path() {
    local target="$1"
    local path="$EXPERIMENT_TARGET_DIR/$target/$BUILD_DIR/libpgp_mobile.a"

    if [ ! -f "$path" ]; then
        echo "error: expected static library not found: $path" >&2
        exit 1
    fi

    printf '%s\n' "$path"
}

cleanup_target_specific_dylibs() {
    local dylib_candidates=(
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-ios/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-visionos/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.dylib"
    )

    for dylib in "${dylib_candidates[@]}"; do
        rm -f "$dylib"
    done
}

assert_no_target_specific_dylibs() {
    local dylib_candidates=(
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-ios/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/aarch64-apple-ios-sim/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/arm64e-apple-visionos/$BUILD_DIR/libpgp_mobile.dylib"
        "$EXPERIMENT_TARGET_DIR/aarch64-apple-visionos-sim/$BUILD_DIR/libpgp_mobile.dylib"
    )
    local stale_found=0

    for dylib in "${dylib_candidates[@]}"; do
        if [ -f "$dylib" ]; then
            echo "error: stale target-specific dylib found: $dylib" >&2
            stale_found=1
        fi
    done

    if [ "$stale_found" -ne 0 ]; then
        exit 1
    fi
}

generate_bindings() {
    log_step "bindgen" "Generating UniFFI Swift bindings with the arm64e Darwin host dylib..."

    rm -rf "$GENERATED_BINDINGS_DIR"
    mkdir -p "$GENERATED_BINDINGS_DIR"

    cp "$MANIFEST" "$MANIFEST.bak.apple-arm64e-experiment"
    sed -i '' 's/crate-type = \["lib", "staticlib"\]/crate-type = ["lib", "staticlib", "cdylib"]/' "$MANIFEST"

    env \
        CARGO_HOME="$EXPERIMENT_CARGO_HOME" \
        CARGO_TARGET_DIR="$EXPERIMENT_TARGET_DIR" \
        cargo +"$ARM64E_TOOLCHAIN" build -Zbuild-std $CARGO_FLAGS --target arm64e-apple-darwin --manifest-path "$MANIFEST"

    mv "$MANIFEST.bak.apple-arm64e-experiment" "$MANIFEST"

    local host_dylib="$EXPERIMENT_TARGET_DIR/arm64e-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
    if [ ! -f "$host_dylib" ]; then
        echo "error: host dylib not found: $host_dylib" >&2
        exit 1
    fi

    (
        cd "$REPO_ROOT/pgp-mobile"
        env \
            CARGO_HOME="$EXPERIMENT_CARGO_HOME" \
            CARGO_TARGET_DIR="$EXPERIMENT_TARGET_DIR" \
            cargo run $CARGO_FLAGS --bin uniffi-bindgen generate \
                --library "$host_dylib" \
                --language swift \
                --out-dir "$GENERATED_BINDINGS_DIR"
    )

    rm -f "$host_dylib"
    patch_generated_swift_bindings "$GENERATED_BINDINGS_DIR/pgp_mobile.swift"

    if [ -f "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" ]; then
        cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" "$GENERATED_BINDINGS_DIR/module.modulemap"
    fi

    sync_file_if_changed "$GENERATED_BINDINGS_DIR/module.modulemap" "$BINDINGS_DIR/module.modulemap"
    sync_file_if_changed "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" "$BINDINGS_DIR/pgp_mobileFFI.modulemap"
    sync_file_if_changed "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.h" "$BINDINGS_DIR/pgp_mobileFFI.h"
    sync_file_if_changed "$GENERATED_BINDINGS_DIR/pgp_mobile.swift" "$BINDINGS_DIR/pgp_mobile.swift"
    sync_file_if_changed "$GENERATED_BINDINGS_DIR/pgp_mobile.swift" "$SOURCES_BINDING"
}

create_xcframework() {
    local ios_device_lib="$1"
    local ios_sim_lib="$2"
    local macos_lib="$3"
    local visionos_device_lib="$4"
    local visionos_sim_lib="$5"
    local headers_dir="$GENERATED_BINDINGS_DIR/headers"

    log_step "xcframework" "Creating PgpMobile.xcframework..."
    cleanup_target_specific_dylibs
    assert_no_target_specific_dylibs

    rm -rf "$XCFRAMEWORK_OUTPUT"
    rm -rf "$headers_dir"
    mkdir -p "$headers_dir"

    cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.h" "$headers_dir/"
    cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" "$headers_dir/module.modulemap"

    xcodebuild -create-xcframework \
        -library "$ios_device_lib" -headers "$headers_dir" \
        -library "$ios_sim_lib" -headers "$headers_dir" \
        -library "$macos_lib" -headers "$headers_dir" \
        -library "$visionos_device_lib" -headers "$headers_dir" \
        -library "$visionos_sim_lib" -headers "$headers_dir" \
        -output "$XCFRAMEWORK_OUTPUT"
}

verify_xcframework() {
    log_step "verify" "Verifying XCFramework slices..."

    plutil -p "$XCFRAMEWORK_OUTPUT/Info.plist"

    python3 - "$XCFRAMEWORK_OUTPUT/Info.plist" <<'PY'
import plistlib
import sys

info = plistlib.load(open(sys.argv[1], "rb"))
libs = info["AvailableLibraries"]

def require_arch(platform, variant, expected_arch):
    for lib in libs:
        if lib.get("SupportedPlatform") != platform:
            continue
        if lib.get("SupportedPlatformVariant") != variant:
            continue
        arches = lib.get("SupportedArchitectures", [])
        if arches != [expected_arch]:
            raise SystemExit(
                f"{platform}/{variant or 'device'} expected [{expected_arch}] but saw {arches}"
            )
        return
    raise SystemExit(f"missing XCFramework library for {platform}/{variant or 'device'}")

require_arch("ios", None, "arm64e")
require_arch("ios", "simulator", "arm64")
require_arch("macos", None, "arm64e")
require_arch("xros", None, "arm64e")
require_arch("xros", "simulator", "arm64")
PY

    while IFS= read -r lib_path; do
        echo "=== $lib_path ==="
        lipo -info "$lib_path"
        file "$lib_path"
    done < <(find "$XCFRAMEWORK_OUTPUT" -type f -name 'libpgp_mobile.a' | sort)
}

verify_effective_archs() {
    local platform_label="$1"
    shift

    log_step "xcode-settings" "Checking effective CypherAir ${platform_label} ARCHS override..."

    local settings_output
    settings_output="$(
        xcodebuild \
            -project "$REPO_ROOT/CypherAir.xcodeproj" \
            -target CypherAir \
            -showBuildSettings \
            "$@" \
            2>/dev/null \
            | rg '^    ARCHS = '
    )"

    echo "$settings_output"

    if ! printf '%s\n' "$settings_output" | grep -q 'ARCHS = arm64e'; then
        echo "warning: effective ${platform_label} ARCHS override did not resolve to arm64e before the build probe." >&2
    fi
}

run_ios_probe() {
    log_step "probe-ios" "Running generic iOS build probe with ARCHS=arm64e..."
    xcodebuild build \
        -scheme CypherAir \
        -project "$REPO_ROOT/CypherAir.xcodeproj" \
        -destination 'generic/platform=iOS' \
        ARCHS=arm64e \
        CODE_SIGNING_ALLOWED=NO
}

run_macos_probe() {
    log_step "probe-macos" "Running generic macOS build probe with ARCHS=arm64e..."
    xcodebuild build \
        -scheme CypherAir \
        -project "$REPO_ROOT/CypherAir.xcodeproj" \
        -destination 'generic/platform=macOS' \
        ARCHS=arm64e \
        CODE_SIGNING_ALLOWED=NO
}

echo "=== CypherAir: Apple arm64e XCFramework Experiment ==="
echo "Build mode: $BUILD_DIR"
echo "Repo root: $REPO_ROOT"

require_toolchain "$STABLE_TOOLCHAIN"
require_toolchain "$NIGHTLY_TOOLCHAIN"
require_toolchain "$ARM64E_TOOLCHAIN"
ensure_component "$NIGHTLY_TOOLCHAIN" "rust-src"

mkdir -p "$EXPERIMENT_ROOT"
baseline_root="$(mktemp -d "$EXPERIMENT_ROOT/baseline.XXXXXX")"

log_step "baseline" "Reproducing the known stable arm64e failure baselines..."
run_expected_failure \
    "stable cargo arm64e iOS baseline" \
    "can't find crate for \`core\`" \
    "$baseline_root/stable-ios.log" \
    env \
        CARGO_HOME="$baseline_root/stable-ios-cargo-home" \
        CARGO_TARGET_DIR="$baseline_root/stable-ios-target" \
        cargo build --manifest-path "$MANIFEST" --target arm64e-apple-ios

run_expected_failure \
    "stable cargo arm64e Darwin baseline" \
    "can't find crate for \`core\`" \
    "$baseline_root/stable-darwin.log" \
    env \
        CARGO_HOME="$baseline_root/stable-darwin-cargo-home" \
        CARGO_TARGET_DIR="$baseline_root/stable-darwin-target" \
        cargo build --manifest-path "$MANIFEST" --target arm64e-apple-darwin

seed_experiment_cache
reset_experiment_build_state

build_rust_artifact "ios-device-arm64e" "$ARM64E_TOOLCHAIN" "arm64e-apple-ios" -Zbuild-std
build_rust_artifact "ios-sim-arm64" "$STABLE_TOOLCHAIN" "aarch64-apple-ios-sim"
build_rust_artifact "macos-arm64e" "$ARM64E_TOOLCHAIN" "arm64e-apple-darwin" -Zbuild-std
build_rust_artifact "visionos-device-arm64e" "$ARM64E_TOOLCHAIN" "arm64e-apple-visionos" -Zbuild-std
build_rust_artifact "visionos-sim-arm64" "$STABLE_TOOLCHAIN" "aarch64-apple-visionos-sim"

IOS_DEVICE_LIB="$(resolve_library_path "arm64e-apple-ios")"
IOS_SIM_LIB="$(resolve_library_path "aarch64-apple-ios-sim")"
MACOS_LIB="$(resolve_library_path "arm64e-apple-darwin")"
VISIONOS_DEVICE_LIB="$(resolve_library_path "arm64e-apple-visionos")"
VISIONOS_SIM_LIB="$(resolve_library_path "aarch64-apple-visionos-sim")"

generate_bindings
create_xcframework "$IOS_DEVICE_LIB" "$IOS_SIM_LIB" "$MACOS_LIB" "$VISIONOS_DEVICE_LIB" "$VISIONOS_SIM_LIB"
verify_xcframework
verify_effective_archs "iOS" ARCHS=arm64e
verify_effective_archs "macOS" ARCHS=arm64e
run_ios_probe
run_macos_probe

echo
echo "=== Experiment Complete ==="
echo "Produced: $XCFRAMEWORK_OUTPUT"
echo "Experiment Cargo cache: $EXPERIMENT_CARGO_HOME"
echo "Experiment target dir: $EXPERIMENT_TARGET_DIR"
