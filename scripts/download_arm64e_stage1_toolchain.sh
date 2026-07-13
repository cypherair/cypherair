#!/bin/bash
# Download the CypherAir Rust arm64e stage1 toolchain for CI before builds run.

set -euo pipefail

unset GH_TOKEN GITHUB_TOKEN

OUTPUT_ROOT="${1:?usage: download_arm64e_stage1_toolchain.sh <output-root>}"
ARM64E_RUST_REPOSITORY="${ARM64E_RUST_REPOSITORY:-cypherair/rust}"
DEFAULT_ARM64E_STAGE1_RELEASE_TAG="rust-arm64e-stage1-stable197-20260713T191930Z-027700f-r29277996466-a1"
ARM64E_STAGE1_RELEASE_TAG="${ARM64E_STAGE1_RELEASE_TAG:-$DEFAULT_ARM64E_STAGE1_RELEASE_TAG}"
ARM64E_STAGE1_RELEASE_PREFIX="${ARM64E_STAGE1_RELEASE_PREFIX:-rust-arm64e-stage1-stable197}"
STAGE1_ASSET_PREFIX="${STAGE1_ASSET_PREFIX:-rust-stage1-for-arm64e}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: missing required command '$1'" >&2
        exit 1
    fi
}

download_stage1_release() {
    local release_base_url asset_name
    release_base_url="https://github.com/${ARM64E_RUST_REPOSITORY}/releases/download/${tag}"
    for asset_name in "${EXPECTED_STAGE1_ASSETS[@]}"; do
        curl --fail --silent --show-error --location \
            --output "$download_dir/$asset_name" \
            "$release_base_url/$asset_name"
    done
}

require_command curl
require_command shasum
require_command zstd
require_command bsdtar
require_command rustc

tag="$ARM64E_STAGE1_RELEASE_TAG"
if [ -z "$tag" ] || [ "$tag" = "latest" ] || [ "$tag" = "null" ]; then
    echo "error: ARM64E_STAGE1_RELEASE_TAG must be an explicit ${ARM64E_STAGE1_RELEASE_PREFIX}-* tag; 'latest' is not allowed" >&2
    echo "       current default: $DEFAULT_ARM64E_STAGE1_RELEASE_TAG" >&2
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
