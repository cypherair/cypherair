#!/usr/bin/env bash
# Verify the pinned arm64e stage1 release contract with GitHub-authenticated
# checks, complementing the token-free digest and byte-size pin that
# scripts/download_arm64e_stage1_toolchain.sh enforces on every download:
#
#   1. Release integrity: the pinned tag resolves to a non-draft, immutable
#      release whose target commit matches the pinned fork commit
#      (tag→commit binding). The stage1 channel is a prerelease by design,
#      so the prerelease flag is asserted against the pin instead of being
#      rejected outright.
#   2. GitHub release attestation (`gh release verify`).
#   3. Per downloaded asset: `gh release verify-asset` plus a SLSA
#      build-provenance check (`gh attestation verify`) bound to the fork's
#      publishing workflow, source ref, and source commit, on GitHub-hosted
#      runners only.
#
# Requires an authenticated gh. Run after download_arm64e_stage1_toolchain.sh
# and before the stage1 compiler executes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${ARM64E_STAGE1_PIN_FILE:-$REPO_ROOT/third_party/arm64e-stage1-toolchain.pin.json}"
DOWNLOAD_DIR="${1:?usage: verify_arm64e_stage1_release.sh <download-dir>}"

log() { echo "[verify_arm64e_stage1_release] $*"; }

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

pin_asset_names() {
    python3 - "$PIN_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
for name in payload["assets"]:
    print(name)
PY
}

pin_asset_hash() {
    python3 - "$PIN_FILE" "$1" <<'PY'
import json
import sys

pin_path, asset_name = sys.argv[1:3]
with open(pin_path, encoding="utf-8") as handle:
    payload = json.load(handle)
print(payload["assets"][asset_name]["sha256"])
PY
}

pin_asset_size() {
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
size = asset.get("size")
if type(size) is not int or size <= 0:
    print(
        f"error: pinned size for asset {asset_name!r} must be a positive integer",
        file=sys.stderr,
    )
    sys.exit(1)
print(size)
PY
}

file_size_bytes() {
    python3 - "$1" <<'PY'
import os
import sys

print(os.path.getsize(sys.argv[1]))
PY
}

require_command gh
require_command python3
require_command shasum

[ -f "$PIN_FILE" ] || {
    echo "error: stage1 consumer pin file is missing: $PIN_FILE" >&2
    exit 1
}
[ -d "$DOWNLOAD_DIR" ] || {
    echo "error: stage1 download directory is missing: $DOWNLOAD_DIR" >&2
    exit 1
}

RELEASE_REPOSITORY="$(pin_value repository)"
RELEASE_TAG="$(pin_value release.tag)"
RELEASE_COMMIT="$(pin_value release.commitSha)"
RELEASE_SOURCE_REF="$(pin_value release.sourceRef)"
RELEASE_SIGNER_WORKFLOW="$(pin_value release.signerWorkflow)"
RELEASE_IS_PRERELEASE="$(pin_value release.isPrerelease)"

verify_release_integrity() {
    local release_json
    release_json="$(mktemp)"
    gh release view "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" \
        --json tagName,isDraft,isPrerelease,isImmutable,targetCommitish,url \
        > "$release_json"
    python3 - "$release_json" "$RELEASE_TAG" "$RELEASE_COMMIT" "$RELEASE_IS_PRERELEASE" <<'PY'
import json
import sys

path, expected_tag, expected_commit, expected_prerelease = sys.argv[1:5]
with open(path, encoding="utf-8") as handle:
    release = json.load(handle)

errors = []
if release.get("tagName") != expected_tag:
    errors.append(f"release tag {release.get('tagName')!r} != {expected_tag!r}")
if release.get("targetCommitish") != expected_commit:
    errors.append(f"release target {release.get('targetCommitish')!r} != {expected_commit!r}")
if release.get("isDraft") is not False:
    errors.append("release must not be draft")
if release.get("isPrerelease") is not (expected_prerelease == "True"):
    errors.append(f"release prerelease flag {release.get('isPrerelease')!r} != pinned {expected_prerelease!r}")
if release.get("isImmutable") is not True:
    errors.append("release must be immutable")
if errors:
    raise SystemExit("error: " + "; ".join(errors))
PY
    rm -f "$release_json"
    gh release verify "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" >/dev/null
}

verify_asset() {
    local asset="$1"
    local expected_size actual_size expected_hash actual_hash
    expected_size="$(pin_asset_size "$asset")"
    actual_size="$(file_size_bytes "$DOWNLOAD_DIR/$asset")"
    if [ "$actual_size" != "$expected_size" ]; then
        echo "error: $asset size $actual_size != pinned $expected_size" >&2
        exit 1
    fi
    expected_hash="$(pin_asset_hash "$asset")"
    actual_hash="$(shasum -a 256 "$DOWNLOAD_DIR/$asset" | awk '{print $1}')"
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "error: $asset sha256 $actual_hash != pinned $expected_hash" >&2
        exit 1
    fi
    (
        cd "$DOWNLOAD_DIR"
        gh release verify-asset "$RELEASE_TAG" "$asset" -R "$RELEASE_REPOSITORY" >/dev/null
    )
    gh attestation verify "$DOWNLOAD_DIR/$asset" \
        -R "$RELEASE_REPOSITORY" \
        --signer-workflow "$RELEASE_SIGNER_WORKFLOW" \
        --source-ref "$RELEASE_SOURCE_REF" \
        --source-digest "$RELEASE_COMMIT" \
        --deny-self-hosted-runners >/dev/null
}

log "verifying pinned release ${RELEASE_TAG} on ${RELEASE_REPOSITORY}"
verify_release_integrity

# Every downloaded stage1 file must be a pinned asset, and every pinned asset
# that was downloaded must carry a valid release + build-provenance
# attestation. The host-triple subset varies per builder, so only the assets
# actually present are checked — but at least one pinned asset must be there.
PINNED_ASSET_NAMES=()
while IFS= read -r asset; do
    PINNED_ASSET_NAMES+=("$asset")
done < <(pin_asset_names)

is_pinned_asset() {
    local candidate="$1" name
    for name in "${PINNED_ASSET_NAMES[@]}"; do
        if [ "$name" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

verified_count=0
while IFS= read -r -d '' path; do
    asset="$(basename "$path")"
    if ! is_pinned_asset "$asset"; then
        echo "error: unexpected entry in stage1 download directory: $asset" >&2
        exit 1
    fi
    log "verifying asset attestations: $asset"
    verify_asset "$asset"
    verified_count=$((verified_count + 1))
done < <(find "$DOWNLOAD_DIR" -mindepth 1 -maxdepth 1 -print0)

if [ "$verified_count" -eq 0 ]; then
    echo "error: no pinned stage1 assets found in $DOWNLOAD_DIR" >&2
    exit 1
fi

log "verified release integrity and $verified_count asset attestation(s)"
