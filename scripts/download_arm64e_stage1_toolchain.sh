#!/bin/bash
# Download the CypherAir Rust arm64e stage1 toolchain for CI before builds run.
#
# Integrity contract: the release tag, repository, and per-asset SHA-256
# digests must match the committed consumer pin in
# third_party/arm64e-stage1-toolchain.pin.json. The digest check needs no
# GitHub token, so it is enforced unconditionally on every path, including
# token-scrubbed CI fetches. Release-level immutability, tag→commit binding,
# and build-provenance attestation checks (which need gh auth) live in
# scripts/verify_arm64e_stage1_release.sh and run in CI after this download.

set -euo pipefail

unset GH_TOKEN GITHUB_TOKEN

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_ROOT="${1:?usage: download_arm64e_stage1_toolchain.sh <output-root>}"
PIN_FILE="${ARM64E_STAGE1_PIN_FILE:-$REPO_ROOT/third_party/arm64e-stage1-toolchain.pin.json}"
ARM64E_RUST_REPOSITORY="${ARM64E_RUST_REPOSITORY:-cypherair/rust}"
DEFAULT_ARM64E_STAGE1_RELEASE_TAG="rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1"
ARM64E_STAGE1_RELEASE_TAG="${ARM64E_STAGE1_RELEASE_TAG:-$DEFAULT_ARM64E_STAGE1_RELEASE_TAG}"
ARM64E_STAGE1_RELEASE_PREFIX="${ARM64E_STAGE1_RELEASE_PREFIX:-rust-arm64e-stage1-stable197}"
STAGE1_ASSET_PREFIX="${STAGE1_ASSET_PREFIX:-rust-stage1-for-arm64e}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: missing required command '$1'" >&2
        exit 1
    fi
}

pin_value() {
    python3 - "$PIN_FILE" "$1" <<'PY'
import json
import sys

pin_path, dotted_path = sys.argv[1:3]
with open(pin_path, encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted_path.split("."):
    value = value[part]
print("" if value is None else str(value))
PY
}

pin_asset_hash() {
    python3 - "$PIN_FILE" "$1" <<'PY'
import json
import sys

pin_path, asset_name = sys.argv[1:3]
with open(pin_path, encoding="utf-8") as handle:
    payload = json.load(handle)
asset = payload["assets"].get(asset_name)
if asset is None:
    print(f"error: asset {asset_name!r} is not in the stage1 pin file", file=sys.stderr)
    sys.exit(1)
print(asset["sha256"])
PY
}

download_stage1_release() {
    local release_base_url asset_name
    release_base_url="https://github.com/${ARM64E_RUST_REPOSITORY}/releases/download/${tag}"
    for asset_name in "${EXPECTED_STAGE1_ASSETS[@]}"; do
        curl --fail --silent --show-error --location \
            --proto '=https' --tlsv1.2 \
            --output "$download_dir/$asset_name" \
            "$release_base_url/$asset_name"
    done
}

verify_assets_against_pin() {
    local asset_name expected actual
    for asset_name in "${EXPECTED_STAGE1_ASSETS[@]}"; do
        expected="$(pin_asset_hash "$asset_name")"
        actual="$(shasum -a 256 "$download_dir/$asset_name" | awk '{print $1}')"
        if [ "$actual" != "$expected" ]; then
            echo "error: $asset_name sha256 $actual != pinned $expected" >&2
            echo "       the downloaded stage1 asset does not match third_party/arm64e-stage1-toolchain.pin.json" >&2
            exit 1
        fi
    done
}

require_command curl
require_command shasum
require_command zstd
require_command bsdtar
require_command rustc
require_command python3

if [ ! -f "$PIN_FILE" ]; then
    echo "error: stage1 consumer pin file is missing: $PIN_FILE" >&2
    exit 1
fi

tag="$ARM64E_STAGE1_RELEASE_TAG"
if [ -z "$tag" ] || [ "$tag" = "latest" ] || [ "$tag" = "null" ]; then
    echo "error: ARM64E_STAGE1_RELEASE_TAG must be an explicit ${ARM64E_STAGE1_RELEASE_PREFIX}-* tag; 'latest' is not allowed" >&2
    echo "       current default: $DEFAULT_ARM64E_STAGE1_RELEASE_TAG" >&2
    exit 1
fi
case "$tag" in
    "${ARM64E_STAGE1_RELEASE_PREFIX}"-*) ;;
    *)
        echo "error: ARM64E_STAGE1_RELEASE_TAG must start with ${ARM64E_STAGE1_RELEASE_PREFIX}-" >&2
        exit 1
        ;;
esac

PINNED_REPOSITORY="$(pin_value repository)"
PINNED_TAG="$(pin_value release.tag)"
if [ "$ARM64E_RUST_REPOSITORY" != "$PINNED_REPOSITORY" ]; then
    echo "error: ARM64E_RUST_REPOSITORY '$ARM64E_RUST_REPOSITORY' != pinned repository '$PINNED_REPOSITORY'" >&2
    echo "       update third_party/arm64e-stage1-toolchain.pin.json via the re-pin rule (docs/ARM64E_STATUS.md)" >&2
    exit 1
fi
if [ "$tag" != "$PINNED_TAG" ]; then
    echo "error: ARM64E_STAGE1_RELEASE_TAG '$tag' != pinned tag '$PINNED_TAG'" >&2
    echo "       update third_party/arm64e-stage1-toolchain.pin.json via the re-pin rule (docs/ARM64E_STATUS.md)" >&2
    exit 1
fi

download_dir="$OUTPUT_ROOT/download"
toolchain_root="$OUTPUT_ROOT/toolchain"
stage1_dir="$toolchain_root/stage1-arm64e-patch"
host_triple="$(rustc -vV | sed -n 's/^host: //p')"
if [ -z "$host_triple" ]; then
    echo "error: unable to determine host triple from rustc -vV" >&2
    exit 1
fi
stage1_asset_base="${STAGE1_ASSET_PREFIX}-${host_triple}"
EXPECTED_STAGE1_ASSETS=(
    "${stage1_asset_base}.tar.zst"
    "${stage1_asset_base}.sha256"
    "${stage1_asset_base}.json"
)
stage1_manifest="$download_dir/${stage1_asset_base}.json"

echo "Downloading Rust arm64e stage1 prerelease ${tag} for host ${host_triple}..."
rm -rf "$OUTPUT_ROOT"
mkdir -p "$download_dir" "$toolchain_root"

download_stage1_release

echo "Verifying downloaded assets against third_party/arm64e-stage1-toolchain.pin.json..."
verify_assets_against_pin

(
    cd "$download_dir"
    shasum -a 256 -c "${stage1_asset_base}.sha256"
    zstd -d -c "${stage1_asset_base}.tar.zst" | bsdtar -xf - -C "$toolchain_root"
)

if [ ! -x "$stage1_dir/bin/rustc" ]; then
    echo "error: downloaded arm64e rustc is missing or not executable: $stage1_dir/bin/rustc" >&2
    exit 1
fi
if [ ! -f "$stage1_manifest" ]; then
    echo "error: downloaded arm64e stage1 manifest is missing: $stage1_manifest" >&2
    exit 1
fi

if [ -n "${GITHUB_ENV:-}" ]; then
    {
        echo "ARM64E_STAGE1_FORCE_DOWNLOAD=0"
        echo "ARM64E_STAGE1_DIR=$stage1_dir"
        echo "ARM64E_RUST_STAGE1_MANIFEST=$stage1_manifest"
        echo "ARM64E_RUST_STAGE1_RELEASE_TAG=$tag"
    } >> "$GITHUB_ENV"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "stage1_dir=$stage1_dir"
        echo "stage1_manifest=$stage1_manifest"
        echo "stage1_release_tag=$tag"
    } >> "$GITHUB_OUTPUT"
fi

echo "arm64e stage1 toolchain: $stage1_dir"
echo "arm64e stage1 manifest: $stage1_manifest"
