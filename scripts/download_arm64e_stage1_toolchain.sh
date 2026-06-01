#!/bin/bash
# Download the CypherAir Rust arm64e stage1 toolchain for CI before builds run.

set -euo pipefail

unset GH_TOKEN GITHUB_TOKEN

OUTPUT_ROOT="${1:?usage: download_arm64e_stage1_toolchain.sh <output-root>}"
ARM64E_RUST_REPOSITORY="${ARM64E_RUST_REPOSITORY:-cypherair/rust}"
ARM64E_STAGE1_RELEASE_TAG="${ARM64E_STAGE1_RELEASE_TAG:-latest}"
ARM64E_STAGE1_RELEASE_PREFIX="${ARM64E_STAGE1_RELEASE_PREFIX:-rust-arm64e-stage1-stable196}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: missing required command '$1'" >&2
        exit 1
    fi
}

github_api_url() {
    printf 'https://api.github.com/repos/%s/%s' "$ARM64E_RUST_REPOSITORY" "$1"
}

curl_github_api() {
    curl --fail --silent --show-error --location \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$1"
}

latest_stage1_release_tag() {
    local prefix="$ARM64E_STAGE1_RELEASE_PREFIX"
    local releases_json
    releases_json="$(mktemp)"
    curl_github_api "$(github_api_url 'releases?per_page=100')" > "$releases_json"
    python3 - "$releases_json" "$prefix" <<'PY'
import json
import sys

path, prefix = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    releases = json.load(handle)
matches = [
    release
    for release in releases
    if release.get("prerelease") and release.get("tag_name", "").startswith(prefix)
]
matches.sort(key=lambda release: release.get("published_at") or "")
print(matches[-1]["tag_name"] if matches else "")
PY
    rm -f "$releases_json"
}

download_stage1_release() {
    local release_json assets_tsv
    release_json="$(mktemp)"
    assets_tsv="$(mktemp)"
    curl_github_api "$(github_api_url "releases/tags/${tag}")" > "$release_json"
    python3 - "$release_json" <<'PY' > "$assets_tsv"
import json
import sys

expected = [
    "rust-stage1-arm64e-apple-darwin.tar.zst",
    "rust-stage1-arm64e-apple-darwin.sha256",
    "rust-stage1-arm64e-apple-darwin.json",
]
with open(sys.argv[1], encoding="utf-8") as handle:
    release = json.load(handle)
assets = {
    asset.get("name"): asset.get("browser_download_url")
    for asset in release.get("assets", [])
}
missing = [name for name in expected if not assets.get(name)]
if missing:
    print(f"missing release assets: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)
for name in expected:
    print(f"{name}\t{assets[name]}")
PY
    while IFS=$'\t' read -r asset_name asset_url; do
        curl --fail --silent --show-error --location \
            --output "$download_dir/$asset_name" \
            "$asset_url"
    done < "$assets_tsv"
    rm -f "$release_json" "$assets_tsv"
}

require_command curl
require_command python3
require_command shasum
require_command zstd
require_command bsdtar

tag="$ARM64E_STAGE1_RELEASE_TAG"
if [ "$tag" = "latest" ] || [ -z "$tag" ]; then
    tag="$(latest_stage1_release_tag)"
fi
if [ -z "$tag" ] || [ "$tag" = "null" ]; then
    echo "error: unable to discover a ${ARM64E_STAGE1_RELEASE_PREFIX} prerelease in $ARM64E_RUST_REPOSITORY" >&2
    exit 1
fi

download_dir="$OUTPUT_ROOT/download"
toolchain_root="$OUTPUT_ROOT/toolchain"
stage1_dir="$toolchain_root/stage1-arm64e-patch"
stage1_manifest="$download_dir/rust-stage1-arm64e-apple-darwin.json"

echo "Downloading Rust arm64e stage1 prerelease ${tag}..."
rm -rf "$OUTPUT_ROOT"
mkdir -p "$download_dir" "$toolchain_root"

download_stage1_release

(
    cd "$download_dir"
    shasum -a 256 -c rust-stage1-arm64e-apple-darwin.sha256
    zstd -d -c rust-stage1-arm64e-apple-darwin.tar.zst | bsdtar -xf - -C "$toolchain_root"
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
