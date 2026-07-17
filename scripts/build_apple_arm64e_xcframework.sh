#!/bin/bash
# Official CypherAir Apple arm64e XCFramework build.

set -euo pipefail

# Keep release secrets out of every build subprocess (cargo, rustup, curl,
# codesign helpers). The Xcode Cloud hooks scrub these before calling us;
# this is the belt for local developer shells.
unset GH_TOKEN GITHUB_TOKEN GITHUB_PAT ASC_ISSUER_ID ASC_KEY_ID ASC_PRIVATE_KEY ASC_PRIVATE_KEY_PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/pgp-mobile/Cargo.toml"
BINDINGS_DIR="$REPO_ROOT/bindings"
SOURCES_BINDING="$REPO_ROOT/Sources/PgpMobile/pgp_mobile.swift"
XCFRAMEWORK_OUTPUT="$REPO_ROOT/PgpMobile.xcframework"
ARM64E_MANIFEST_OUTPUT="$REPO_ROOT/PgpMobile.arm64e-build-manifest.json"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/pgp-mobile/target}"
UNIVERSAL_LIB_DIR="$CARGO_TARGET_DIR/apple-arm64e-universal-libs"
GENERATED_BINDINGS_DIR="$CARGO_TARGET_DIR/apple-arm64e-generated-bindings"
STAGE1_CACHE_DIR="$CARGO_TARGET_DIR/apple-arm64e-stage1"

STABLE_TOOLCHAIN="${STABLE_TOOLCHAIN:-stable}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOCAL_ARM64E_TOOLCHAIN="${LOCAL_ARM64E_TOOLCHAIN:-}"
ARM64E_RUST_REPOSITORY="${ARM64E_RUST_REPOSITORY:-cypherair/rust}"
ARM64E_STAGE1_PIN_FILE="${ARM64E_STAGE1_PIN_FILE:-$REPO_ROOT/third_party/arm64e-stage1-toolchain.pin.json}"
DEFAULT_ARM64E_STAGE1_RELEASE_TAG="rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1"
ARM64E_STAGE1_RELEASE_TAG="${ARM64E_STAGE1_RELEASE_TAG:-$DEFAULT_ARM64E_STAGE1_RELEASE_TAG}"
ARM64E_STAGE1_RELEASE_PREFIX="${ARM64E_STAGE1_RELEASE_PREFIX:-rust-arm64e-stage1-stable197}"
ARM64E_STAGE1_FORCE_DOWNLOAD="${ARM64E_STAGE1_FORCE_DOWNLOAD:-0}"
ARM64E_STAGE1_DIR="${ARM64E_STAGE1_DIR:-}"
ARM64E_RUSTC="${ARM64E_RUSTC:-}"
ARM64E_RUST_STAGE1_MANIFEST="${ARM64E_RUST_STAGE1_MANIFEST:-}"
ARM64E_DEPENDENCY_FRESHNESS_LEVEL="${ARM64E_DEPENDENCY_FRESHNESS_LEVEL:-warn}"
MANIFEST_BACKUP="$MANIFEST.bak.apple-arm64e-build"
MANIFEST_BACKUP_CREATED=0
ARM64E_PREBUILT_STD_TARGETS=(
    arm64e-apple-darwin
    arm64e-apple-ios
    arm64e-apple-visionos
)

BUILD_MODE="${1:---release}"
if [ "$BUILD_MODE" = "--debug" ]; then
    BUILD_DIR="debug"
    CARGO_FLAGS=()
else
    BUILD_DIR="release"
    CARGO_FLAGS=(--release)
fi

cleanup_manifest_backup() {
    if [ "$MANIFEST_BACKUP_CREATED" = "1" ] && [ -f "$MANIFEST_BACKUP" ]; then
        mv "$MANIFEST_BACKUP" "$MANIFEST" 2>/dev/null || true
    fi
}
trap cleanup_manifest_backup EXIT INT TERM

if [ -f "$MANIFEST_BACKUP" ]; then
    echo "warning: stale manifest backup exists and will not be restored unless this run recreates it: $MANIFEST_BACKUP" >&2
fi

log_step() {
    echo
    echo "[$1] $2"
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: missing required command '$1'" >&2
        exit 1
    fi
}

download_stage1_release_assets() {
    env -u GH_TOKEN -u GITHUB_TOKEN \
        ARM64E_RUST_REPOSITORY="$ARM64E_RUST_REPOSITORY" \
        ARM64E_STAGE1_PIN_FILE="$ARM64E_STAGE1_PIN_FILE" \
        ARM64E_STAGE1_RELEASE_TAG="$ARM64E_STAGE1_RELEASE_TAG" \
        ARM64E_STAGE1_RELEASE_PREFIX="$ARM64E_STAGE1_RELEASE_PREFIX" \
        "$SCRIPT_DIR/download_arm64e_stage1_toolchain.sh" "$STAGE1_CACHE_DIR"
}

ensure_toolchain() {
    local toolchain="$1"
    if ! rustup toolchain list | sed 's/ .*//' | grep -Eq "^${toolchain}(-.*)?$"; then
        echo "Installing Rust toolchain ${toolchain}..."
        rustup toolchain install "$toolchain" --profile minimal
    fi
}

ensure_component() {
    local toolchain="$1"
    local component="$2"
    if ! rustup component list --toolchain "$toolchain" | grep -q "^${component} .*installed"; then
        rustup component add "$component" --toolchain "$toolchain"
    fi
}

ensure_rustup_target() {
    local toolchain="$1"
    local target="$2"
    if ! rustup target list --toolchain "$toolchain" --installed | grep -q "^${target}$"; then
        rustup target add "$target" --toolchain "$toolchain"
    fi
}

download_stage1_toolchain() {
    require_command zstd

    local tag="$ARM64E_STAGE1_RELEASE_TAG"
    if [ -z "$tag" ] || [ "$tag" = "latest" ] || [ "$tag" = "null" ]; then
        echo "error: ARM64E_STAGE1_RELEASE_TAG must be an explicit ${ARM64E_STAGE1_RELEASE_PREFIX}-* tag; 'latest' is not allowed" >&2
        echo "       current default: $DEFAULT_ARM64E_STAGE1_RELEASE_TAG" >&2
        exit 1
    fi

    log_step "stage1" "Downloading Rust arm64e stage1 prerelease ${tag}..."
    ARM64E_STAGE1_RELEASE_TAG="$tag" download_stage1_release_assets

    ARM64E_STAGE1_DIR="$STAGE1_CACHE_DIR/toolchain/stage1-arm64e-patch"
    ARM64E_RUST_STAGE1_MANIFEST="$(find "$STAGE1_CACHE_DIR/download" -maxdepth 1 -name 'rust-stage1-for-arm64e-*.json' -print -quit)"
    if [ -z "$ARM64E_RUST_STAGE1_MANIFEST" ]; then
        echo "error: downloaded arm64e stage1 manifest is missing from $STAGE1_CACHE_DIR/download" >&2
        exit 1
    fi
    export ARM64E_RUST_STAGE1_RELEASE_TAG="$tag"
}

validate_stage1_manifest() {
    if [ -z "$ARM64E_RUST_STAGE1_MANIFEST" ]; then
        echo "error: ARM64E_RUST_STAGE1_MANIFEST is required for official XCFramework packaging" >&2
        echo "       use ARM64E_STAGE1_FORCE_DOWNLOAD=1 with the pinned prerelease" >&2
        exit 1
    fi
    if [ ! -f "$ARM64E_RUST_STAGE1_MANIFEST" ]; then
        echo "error: arm64e stage1 manifest is missing: $ARM64E_RUST_STAGE1_MANIFEST" >&2
        exit 1
    fi

    local validation_args=(
        --manifest "$ARM64E_RUST_STAGE1_MANIFEST"
        --rustc "$ARM64E_RUSTC"
        --pin-file "$ARM64E_STAGE1_PIN_FILE"
        --release-tag "$ARM64E_STAGE1_RELEASE_TAG"
    )
    local target
    for target in "${ARM64E_PREBUILT_STD_TARGETS[@]}"; do
        validation_args+=(--required-target "$target")
    done

    env -u GH_TOKEN -u GITHUB_TOKEN \
        "$PYTHON_BIN" "$SCRIPT_DIR/validate_arm64e_stage1_toolchain.py" \
        "${validation_args[@]}"
}

resolve_arm64e_rustc() {
    if [ "$ARM64E_STAGE1_FORCE_DOWNLOAD" = "1" ]; then
        download_stage1_toolchain
    fi

    if [ -z "$ARM64E_RUSTC" ] && [ -n "$ARM64E_STAGE1_DIR" ]; then
        ARM64E_RUSTC="$ARM64E_STAGE1_DIR/bin/rustc"
    fi

    if [ -z "$ARM64E_RUSTC" ] && [ -n "$LOCAL_ARM64E_TOOLCHAIN" ] && \
        rustup which --toolchain "$LOCAL_ARM64E_TOOLCHAIN" rustc >/dev/null 2>&1; then
        ARM64E_RUSTC="$(rustup which --toolchain "$LOCAL_ARM64E_TOOLCHAIN" rustc)"
    fi

    if [ -z "$ARM64E_RUSTC" ]; then
        download_stage1_toolchain
        ARM64E_RUSTC="$ARM64E_STAGE1_DIR/bin/rustc"
    fi

    if [ ! -x "$ARM64E_RUSTC" ]; then
        echo "error: arm64e rustc is missing or not executable: $ARM64E_RUSTC" >&2
        exit 1
    fi

    export ARM64E_RUSTC
    export ARM64E_RUST_STAGE1_MANIFEST
    validate_stage1_manifest
    echo "arm64e rustc: $ARM64E_RUSTC"
    "$ARM64E_RUSTC" -vV
}

ensure_arm64e_stage1_payload() {
    local host_triple
    local host_libdir
    local target
    local target_libdir

    host_triple="$("$ARM64E_RUSTC" -vV | sed -n 's/^host: //p')"
    if [ -z "$host_triple" ]; then
        echo "error: unable to determine arm64e stage1 host triple from $ARM64E_RUSTC" >&2
        exit 1
    fi

    host_libdir="$("$ARM64E_RUSTC" --print target-libdir --target "$host_triple")"
    if ! compgen -G "$host_libdir/libstd-*.rlib" >/dev/null || ! compgen -G "$host_libdir/libproc_macro-*.rlib" >/dev/null; then
        cat >&2 <<EOF
error: arm64e stage1 toolchain is missing host std/proc_macro for ${host_triple}.

Cargo compiles build scripts and proc macros for the host even when the final
crate target is arm64e. Rebuild or republish the Rust fork stage1 with:

    python3 x.py build compiler/rustc library/std library/proc_macro --stage 1 --target ${host_triple},arm64e-apple-darwin,arm64e-apple-ios,arm64e-apple-visionos

Then relink the rebuilt stage1 directory or use ARM64E_STAGE1_FORCE_DOWNLOAD=1
with a prerelease that includes host std.
EOF
        exit 1
    fi

    for target in "${ARM64E_PREBUILT_STD_TARGETS[@]}"; do
        target_libdir="$("$ARM64E_RUSTC" --print target-libdir --target "$target")"
        if ! compgen -G "$target_libdir/libstd-*.rlib" >/dev/null; then
            echo "error: arm64e stage1 toolchain is missing prebuilt std for ${target} at ${target_libdir}" >&2
            echo "       republish the stable197 Rust fork stage1 with prebuilt std payloads." >&2
            exit 1
        fi
    done

}

normalize_generated_text_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return
    fi
    perl -0pi -e 's/[ \t]+$//mg; s/\n+\z/\n/' "$file"
}

patch_generated_swift_bindings() {
    local swift_file="$1"
    if [ ! -f "$swift_file" ]; then
        return
    fi
    perl -0pi -e 's/\n    static let vtablePtr: UnsafePointer<(UniffiVTableCallbackInterface[A-Za-z0-9_]+)> = \{/\n    nonisolated(unsafe) static let vtablePtr: UnsafePointer<$1> = {/g' "$swift_file"
    normalize_generated_text_file "$swift_file"
}

normalize_generated_bindings() {
    normalize_generated_text_file "$GENERATED_BINDINGS_DIR/module.modulemap"
    normalize_generated_text_file "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap"
    normalize_generated_text_file "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.h"
    normalize_generated_text_file "$GENERATED_BINDINGS_DIR/pgp_mobile.swift"
}

sync_file_if_changed() {
    local src="$1"
    local dst="$2"
    if [ ! -f "$src" ]; then
        echo "error: generated file missing: $src" >&2
        exit 1
    fi
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        echo "unchanged: $dst"
        return
    fi
    cp "$src" "$dst"
    echo "synced: $dst"
}

# sequoia-openpgp >= 2.4.0 pulls in ossl, which enables openssl-sys's
# `bindgen` feature. bindgen (libclang) does not infer Apple cross-target
# sysroots the way cc/openssl-src do, so without an explicit sysroot it
# parses macOS SDK headers for every target; visionOS availability
# attributes then hard-fail the build. Map each Rust target to its SDK.
bindgen_clang_args_for_target() {
    local target="$1"
    local sdk="" clang_target=""
    case "$target" in
        aarch64-apple-ios)          sdk=iphoneos;        clang_target=arm64-apple-ios ;;
        arm64e-apple-ios)           sdk=iphoneos;        clang_target=arm64e-apple-ios ;;
        aarch64-apple-ios-sim)      sdk=iphonesimulator; clang_target=arm64-apple-ios-simulator ;;
        aarch64-apple-darwin)       sdk=macosx;          clang_target=arm64-apple-macosx ;;
        arm64e-apple-darwin)        sdk=macosx;          clang_target=arm64e-apple-macosx ;;
        aarch64-apple-visionos)     sdk=xros;            clang_target=arm64-apple-xros ;;
        arm64e-apple-visionos)      sdk=xros;            clang_target=arm64e-apple-xros ;;
        aarch64-apple-visionos-sim) sdk=xrsimulator;     clang_target=arm64-apple-xros-simulator ;;
        *) return 0 ;;
    esac
    printf -- '--target=%s -isysroot %s' "$clang_target" "$(xcrun --sdk "$sdk" --show-sdk-path)"
}

build_rust_artifact() {
    local label="$1"
    local target="$2"
    shift 2

    local bindgen_env_name="BINDGEN_EXTRA_CLANG_ARGS_${target//-/_}"
    local bindgen_args
    bindgen_args="$(bindgen_clang_args_for_target "$target")"

    log_step "$label" "Building ${target}..."
    if [[ "$target" == arm64e-* ]]; then
        env -u GH_TOKEN -u GITHUB_TOKEN \
            CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            "$bindgen_env_name=$bindgen_args" \
            RUSTC="$ARM64E_RUSTC" \
            cargo +"$STABLE_TOOLCHAIN" build --locked "${CARGO_FLAGS[@]}" "$@" --target "$target" --manifest-path "$MANIFEST"
    else
        env -u GH_TOKEN -u GITHUB_TOKEN \
            CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            "$bindgen_env_name=$bindgen_args" \
            cargo +"$STABLE_TOOLCHAIN" build --locked "${CARGO_FLAGS[@]}" "$@" --target "$target" --manifest-path "$MANIFEST"
    fi
}

resolve_library_path() {
    local target="$1"
    local path="$CARGO_TARGET_DIR/$target/$BUILD_DIR/libpgp_mobile.a"
    if [ ! -f "$path" ]; then
        echo "error: expected static library not found: $path" >&2
        exit 1
    fi
    printf '%s\n' "$path"
}

combine_archives() {
    local label="$1"
    local output="$2"
    local first_lib="$3"
    local second_lib="$4"

    log_step "$label" "Creating universal archive..."
    mkdir -p "$(dirname "$output")"
    lipo -create "$first_lib" "$second_lib" -output "$output"
    lipo -info "$output"
}

cleanup_target_specific_dylibs() {
    find "$CARGO_TARGET_DIR" -type f -name "libpgp_mobile.dylib" -delete 2>/dev/null || true
}

assert_no_target_specific_dylibs() {
    local stale
    stale="$(find "$CARGO_TARGET_DIR" -type f -name "libpgp_mobile.dylib" -print 2>/dev/null || true)"
    if [ -n "$stale" ]; then
        echo "error: stale target-specific dylibs found:" >&2
        printf '%s\n' "$stale" >&2
        exit 1
    fi
}

generate_bindings() {
    log_step "bindgen" "Generating UniFFI Swift bindings with an arm64e Darwin host dylib..."
    rm -rf "$GENERATED_BINDINGS_DIR"
    mkdir -p "$GENERATED_BINDINGS_DIR"

    cp "$MANIFEST" "$MANIFEST_BACKUP"
    MANIFEST_BACKUP_CREATED=1
    perl -0pi -e 's/crate-type = \["lib", "staticlib"\]/crate-type = ["lib", "staticlib", "cdylib"]/g' "$MANIFEST"

    env -u GH_TOKEN -u GITHUB_TOKEN \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        RUSTC="$ARM64E_RUSTC" \
        cargo +"$STABLE_TOOLCHAIN" build --locked "${CARGO_FLAGS[@]}" --target arm64e-apple-darwin --manifest-path "$MANIFEST"

    mv "$MANIFEST_BACKUP" "$MANIFEST"
    MANIFEST_BACKUP_CREATED=0

    local host_dylib="$CARGO_TARGET_DIR/arm64e-apple-darwin/$BUILD_DIR/libpgp_mobile.dylib"
    if [ ! -f "$host_dylib" ]; then
        echo "error: host dylib not found: $host_dylib" >&2
        exit 1
    fi

    (
        cd "$REPO_ROOT/pgp-mobile"
        env -u GH_TOKEN -u GITHUB_TOKEN \
            CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            cargo +"$STABLE_TOOLCHAIN" run --locked "${CARGO_FLAGS[@]}" --bin uniffi-bindgen generate \
                --library "$host_dylib" \
                --language swift \
                --out-dir "$GENERATED_BINDINGS_DIR"
    )

    rm -f "$host_dylib"
    patch_generated_swift_bindings "$GENERATED_BINDINGS_DIR/pgp_mobile.swift"

    if [ -f "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" ]; then
        cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" "$GENERATED_BINDINGS_DIR/module.modulemap"
    fi
    normalize_generated_bindings

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

    rm -rf "$XCFRAMEWORK_OUTPUT" "$headers_dir"
    mkdir -p "$headers_dir"
    cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.h" "$headers_dir/"
    cp "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.modulemap" "$headers_dir/module.modulemap"

    env -u GH_TOKEN -u GITHUB_TOKEN \
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
    local metadata_args=(
        --cargo-lock "$REPO_ROOT/pgp-mobile/Cargo.lock"
        --xcframework "$XCFRAMEWORK_OUTPUT"
        --output "$ARM64E_MANIFEST_OUTPUT"
        --freshness-level "$ARM64E_DEPENDENCY_FRESHNESS_LEVEL"
    )
    if [ -n "$ARM64E_RUST_STAGE1_MANIFEST" ]; then
        metadata_args+=(--rust-stage1-manifest "$ARM64E_RUST_STAGE1_MANIFEST")
    fi
    env -u GH_TOKEN -u GITHUB_TOKEN \
        "$PYTHON_BIN" "$SCRIPT_DIR/arm64e_release_metadata.py" "${metadata_args[@]}"

    while IFS= read -r lib_path; do
        echo "=== $lib_path ==="
        lipo -info "$lib_path"
    done < <(find "$XCFRAMEWORK_OUTPUT" -type f -name 'libpgp_mobile.a' | sort)
}

echo "=== CypherAir: Apple arm64e XCFramework Build ==="
echo "Build mode: $BUILD_DIR"
echo "Cargo target dir: $CARGO_TARGET_DIR"
df -h "$REPO_ROOT" || true

require_command cargo
require_command rustup
require_command curl
require_command lipo
require_command xcodebuild
require_command bsdtar
require_command "$PYTHON_BIN"

ensure_toolchain "$STABLE_TOOLCHAIN"
resolve_arm64e_rustc
ensure_arm64e_stage1_payload

ensure_rustup_target "$STABLE_TOOLCHAIN" aarch64-apple-ios
ensure_rustup_target "$STABLE_TOOLCHAIN" aarch64-apple-ios-sim
ensure_rustup_target "$STABLE_TOOLCHAIN" aarch64-apple-darwin
ensure_rustup_target "$STABLE_TOOLCHAIN" aarch64-apple-visionos
ensure_rustup_target "$STABLE_TOOLCHAIN" aarch64-apple-visionos-sim

mkdir -p "$CARGO_TARGET_DIR" "$UNIVERSAL_LIB_DIR"

build_rust_artifact "ios-device-arm64" aarch64-apple-ios
build_rust_artifact "ios-device-arm64e" arm64e-apple-ios
build_rust_artifact "ios-sim-arm64" aarch64-apple-ios-sim
build_rust_artifact "macos-arm64" aarch64-apple-darwin
build_rust_artifact "macos-arm64e" arm64e-apple-darwin
build_rust_artifact "visionos-device-arm64" aarch64-apple-visionos
build_rust_artifact "visionos-device-arm64e" arm64e-apple-visionos
build_rust_artifact "visionos-sim-arm64" aarch64-apple-visionos-sim

IOS_DEVICE_ARM64_LIB="$(resolve_library_path aarch64-apple-ios)"
IOS_DEVICE_ARM64E_LIB="$(resolve_library_path arm64e-apple-ios)"
IOS_SIM_LIB="$(resolve_library_path aarch64-apple-ios-sim)"
MACOS_ARM64_LIB="$(resolve_library_path aarch64-apple-darwin)"
MACOS_ARM64E_LIB="$(resolve_library_path arm64e-apple-darwin)"
VISIONOS_DEVICE_ARM64_LIB="$(resolve_library_path aarch64-apple-visionos)"
VISIONOS_DEVICE_ARM64E_LIB="$(resolve_library_path arm64e-apple-visionos)"
VISIONOS_SIM_LIB="$(resolve_library_path aarch64-apple-visionos-sim)"

IOS_DEVICE_LIB="$UNIVERSAL_LIB_DIR/ios-device/$BUILD_DIR/libpgp_mobile.a"
MACOS_LIB="$UNIVERSAL_LIB_DIR/macos-device/$BUILD_DIR/libpgp_mobile.a"
VISIONOS_DEVICE_LIB="$UNIVERSAL_LIB_DIR/visionos-device/$BUILD_DIR/libpgp_mobile.a"

combine_archives "ios-device-universal" "$IOS_DEVICE_LIB" "$IOS_DEVICE_ARM64_LIB" "$IOS_DEVICE_ARM64E_LIB"
combine_archives "macos-device-universal" "$MACOS_LIB" "$MACOS_ARM64_LIB" "$MACOS_ARM64E_LIB"
combine_archives "visionos-device-universal" "$VISIONOS_DEVICE_LIB" "$VISIONOS_DEVICE_ARM64_LIB" "$VISIONOS_DEVICE_ARM64E_LIB"

generate_bindings
create_xcframework "$IOS_DEVICE_LIB" "$IOS_SIM_LIB" "$MACOS_LIB" "$VISIONOS_DEVICE_LIB" "$VISIONOS_SIM_LIB"
verify_xcframework

echo
echo "=== Build Complete ==="
echo "Produced: $XCFRAMEWORK_OUTPUT"
echo "arm64e manifest: $ARM64E_MANIFEST_OUTPUT"
