#!/bin/bash
# Builds the engine library for Apple platforms, and writes it with its Swift
# bindings into Packages/CypherEngine.
#
#   scripts/build-engine.sh             all eight targets
#   scripts/build-engine.sh TARGET...   only these, for a quick loop
#   scripts/build-engine.sh --check     fail unless the built library comes
#                                       from this checkout's sources
#
# Stock Rust builds the arm64 slices. The arm64e slices are built by stable
# Cargo with RUSTC pointed at the pinned stage1 compiler
# (third_party/arm64e-stage1-toolchain.pin.json; docs/BUILD.md section 3),
# which this script downloads and checks against the pin.

set -euo pipefail

# Keep credentials out of every build subprocess.
unset GH_TOKEN GITHUB_TOKEN GITHUB_PAT ASC_ISSUER_ID ASC_KEY_ID ASC_PRIVATE_KEY ASC_PRIVATE_KEY_PATH
# Each target is built for the app's own deployment target, never an inherited one.
unset MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$REPO_ROOT/engine"
PACKAGE="$REPO_ROOT/Packages/CypherEngine"
XCFRAMEWORK="$PACKAGE/CypherEngineFFI.xcframework"
BINDINGS="$PACKAGE/Sources/CypherEngine/cypher_engine.swift"
SOURCE_HASH_FILE="$XCFRAMEWORK/source-hash"
PIN="$REPO_ROOT/third_party/arm64e-stage1-toolchain.pin.json"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ENGINE/target}"
OUT="$CARGO_TARGET_DIR/apple"

ALL_TARGETS=(
    aarch64-apple-ios arm64e-apple-ios aarch64-apple-ios-sim
    aarch64-apple-darwin arm64e-apple-darwin
    aarch64-apple-visionos arm64e-apple-visionos aarch64-apple-visionos-sim
)

# Everything the library is built from: the engine's sources, its lock file,
# the package manifest that states the deployment targets, the compiler pin and
# this script. Paths are relative to the repository.
inputs() {
    (
        cd "$REPO_ROOT"
        {
            find engine/src engine/uniffi-bindgen -type f
            echo engine/Cargo.toml
            echo engine/Cargo.lock
            echo Packages/CypherEngine/Package.swift
            echo third_party/arm64e-stage1-toolchain.pin.json
            echo scripts/build-engine.sh
        } | LC_ALL=C sort
    )
}

source_hash() {
    (cd "$REPO_ROOT" && inputs | while read -r file; do shasum -a 256 "$file"; done) \
        | shasum -a 256 | cut -d ' ' -f 1
}

# The app's "Check engine library" phase runs this, sandboxed: it may read only
# the files that engine/inputs.xcfilelist declares, which this script writes.
if [ "${1:-}" = "--check" ]; then
    if [ ! -f "$SOURCE_HASH_FILE" ] || [ ! -f "$BINDINGS" ]; then
        echo "error: the engine library is missing. Run scripts/build-engine.sh" >&2
        exit 1
    fi
    if ! (cd "$REPO_ROOT" && inputs | xargs shasum -a 256 >/dev/null); then
        echo "error: engine/inputs.xcfilelist does not list every engine source. Run scripts/build-engine.sh and commit the list" >&2
        exit 1
    fi
    if [ "$(cat "$SOURCE_HASH_FILE")" != "$(source_hash)" ]; then
        echo "error: the engine library was built from other sources. Run scripts/build-engine.sh" >&2
        exit 1
    fi
    exit 0
fi

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=("${ALL_TARGETS[@]}")
fi
for target in "${TARGETS[@]}"; do
    case " ${ALL_TARGETS[*]} " in
        *" $target "*) ;;
        *) echo "error: unknown target $target; the targets are: ${ALL_TARGETS[*]}" >&2; exit 1 ;;
    esac
done

step() { echo; echo "== $*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: missing required command '$1'" >&2; exit 1; }
}
for command in cargo rustup xcodebuild xcrun lipo curl shasum zstd bsdtar python3; do require "$command"; done

pin() {
    python3 - "$PIN" "$@" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2:]:
    value = value[key]
print(value)
PY
}

# Download the pinned stage1 compiler for this host into the target directory,
# once per pinned release, check every asset against the pin, and set
# ARM64E_RUSTC. Called as a plain command, never inside $(...), so that a failed
# check stops the script: bash 3.2 does not carry `set -e` into a substitution.
use_stage1_rustc() {
    local tag repository host base root download asset url
    tag="$(pin release tag)"
    repository="$(pin repository)"
    host="$(rustc +stable -vV | sed -n 's/^host: //p')"
    base="rust-stage1-for-arm64e-$host"
    root="$CARGO_TARGET_DIR/arm64e-stage1/$tag"
    download="$root/download"
    if [ ! -x "$root/toolchain/stage1-arm64e-patch/bin/rustc" ]; then
        mkdir -p "$download"
        for asset in "$base.tar.zst" "$base.sha256" "$base.json"; do
            if ! verify_asset "$download/$asset" "$asset" 2>/dev/null; then
                url="https://github.com/$repository/releases/download/$tag/$asset"
                echo "Downloading $url"
                curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
                    --output "$download/$asset" "$url"
                verify_asset "$download/$asset" "$asset"
            fi
        done
        rm -rf "$root/toolchain"
        mkdir -p "$root/toolchain"
        (cd "$download" && shasum -a 256 -c "$base.sha256")
        zstd -d -c "$download/$base.tar.zst" | bsdtar -xf - -C "$root/toolchain"
    fi
    ARM64E_RUSTC="$root/toolchain/stage1-arm64e-patch/bin/rustc"
    [ -x "$ARM64E_RUSTC" ] || { echo "error: the stage1 compiler is missing: $ARM64E_RUSTC" >&2; exit 1; }
}

verify_asset() {
    local file="$1" asset="$2"
    [ -f "$file" ] || { echo "error: $asset is missing" >&2; return 1; }
    if [ "$(stat -f %z "$file")" != "$(pin assets "$asset" size)" ] \
        || [ "$(shasum -a 256 "$file" | cut -d ' ' -f 1)" != "$(pin assets "$asset" sha256)" ]; then
        echo "error: $asset does not match third_party/arm64e-stage1-toolchain.pin.json" >&2
        return 1
    fi
}

# The deployment targets, from the engine package's manifest, which states the
# app's exact versions (docs/BUILD.md section 7). Not from the project: Xcode
# cannot resolve it while the library is missing.
read_deployment_targets() {
    platform() { sed -n "s/.*\.$1(\"\([0-9.]*\)\").*/\1/p" "$PACKAGE/Package.swift" | head -n 1; }
    MACOS_VERSION="$(platform macOS)"
    IOS_VERSION="$(platform iOS)"
    XROS_VERSION="$(platform visionOS)"
    for version in "$MACOS_VERSION" "$IOS_VERSION" "$XROS_VERSION"; do
        [[ "$version" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo "error: cannot read the deployment targets from $PACKAGE/Package.swift" >&2; exit 1; }
    done
    echo "Deployment targets: macOS $MACOS_VERSION, iOS $IOS_VERSION, visionOS $XROS_VERSION"
}

# The environment for one target: its deployment target, and the SDK that
# bindgen (through openssl-sys) must parse, which it does not infer itself.
target_env() {
    local target="$1" sdk clang_target variable version
    case "$target" in
        aarch64-apple-ios)          sdk=iphoneos;        clang_target=arm64-apple-ios ;;
        arm64e-apple-ios)           sdk=iphoneos;        clang_target=arm64e-apple-ios ;;
        aarch64-apple-ios-sim)      sdk=iphonesimulator; clang_target=arm64-apple-ios-simulator ;;
        aarch64-apple-darwin)       sdk=macosx;          clang_target=arm64-apple-macosx ;;
        arm64e-apple-darwin)        sdk=macosx;          clang_target=arm64e-apple-macosx ;;
        aarch64-apple-visionos)     sdk=xros;            clang_target=arm64-apple-xros ;;
        arm64e-apple-visionos)      sdk=xros;            clang_target=arm64e-apple-xros ;;
        aarch64-apple-visionos-sim) sdk=xrsimulator;     clang_target=arm64-apple-xros-simulator ;;
    esac
    case "$target" in
        *-darwin) variable=MACOSX_DEPLOYMENT_TARGET; version="$MACOS_VERSION" ;;
        *-ios*) variable=IPHONEOS_DEPLOYMENT_TARGET; version="$IOS_VERSION" ;;
        *-visionos*) variable=XROS_DEPLOYMENT_TARGET; version="$XROS_VERSION" ;;
    esac
    printf '%s\n' "$variable=$version"
    # bindgen splits this value with shell quoting; %q keeps an SDK path with spaces whole.
    printf 'BINDGEN_EXTRA_CLANG_ARGS_%s=--target=%s -isysroot %q\n' \
        "${target//-/_}" "$clang_target" "$(xcrun --sdk "$sdk" --show-sdk-path)"
    if [[ "$target" == arm64e-* ]]; then
        printf 'RUSTC=%s\n' "$ARM64E_RUSTC"
    fi
}

build_target() {
    local target="$1" environment=()
    step "Building $target"
    while IFS= read -r line; do environment+=("$line"); done < <(target_env "$target")
    env "${environment[@]}" cargo +stable build --locked --release --lib \
        --manifest-path "$ENGINE/Cargo.toml" --target "$target"
}

library() { echo "$CARGO_TARGET_DIR/$1/release/libcypher_engine.a"; }

# One library per XCFramework slice: device slices join arm64 and arm64e.
slice() {
    local name="$1"; shift
    local libraries=() target
    for target in "$@"; do
        if [[ " ${TARGETS[*]} " == *" $target "* ]]; then
            libraries+=("$(library "$target")")
        fi
    done
    [ ${#libraries[@]} -gt 0 ] || return 0
    mkdir -p "$OUT/$name"
    lipo -create "${libraries[@]}" -output "$OUT/$name/libcypher_engine.a"
    XCFRAMEWORK_ARGS+=(-library "$OUT/$name/libcypher_engine.a" -headers "$OUT/headers")
}

for target in "${TARGETS[@]}"; do
    if [[ "$target" == aarch64-* ]]; then
        rustup target add --toolchain stable "$target" >/dev/null
    fi
done
if [[ " ${TARGETS[*]} " == *" arm64e-"* ]]; then
    use_stage1_rustc
    echo "arm64e compiler: $ARM64E_RUSTC"
    "$ARM64E_RUSTC" -vV
fi
read_deployment_targets

for target in "${TARGETS[@]}"; do build_target "$target"; done

step "Generating the Swift bindings"
rm -rf "$OUT"
mkdir -p "$OUT/bindings" "$OUT/headers"
(cd "$ENGINE" && cargo +stable run --locked --release --quiet -p uniffi-bindgen -- generate \
    --library "$(library "${TARGETS[0]}")" --language swift --out-dir "$OUT/bindings")
cp "$OUT/bindings/cypher_engineFFI.h" "$OUT/headers/"
cp "$OUT/bindings/cypher_engineFFI.modulemap" "$OUT/headers/module.modulemap"

step "Creating the XCFramework"
XCFRAMEWORK_ARGS=()
slice ios aarch64-apple-ios arm64e-apple-ios
slice ios-simulator aarch64-apple-ios-sim
slice macos aarch64-apple-darwin arm64e-apple-darwin
slice xros aarch64-apple-visionos arm64e-apple-visionos
slice xros-simulator aarch64-apple-visionos-sim
rm -rf "$XCFRAMEWORK" "$BINDINGS"
xcodebuild -create-xcframework "${XCFRAMEWORK_ARGS[@]}" -output "$XCFRAMEWORK"
cp "$OUT/bindings/cypher_engine.swift" "$BINDINGS"
inputs | sed 's|^|$(SRCROOT)/|' >"$ENGINE/inputs.xcfilelist"
# Written last: a run that fails earlier leaves no hash that claims the library is current.
source_hash >"$SOURCE_HASH_FILE"

step "Done"
find "$XCFRAMEWORK" -name libcypher_engine.a | sort | while read -r built; do lipo -info "$built"; done
