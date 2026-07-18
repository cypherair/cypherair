#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${SQLCIPHER_PIN_FILE:-$REPO_ROOT/third_party/sqlcipher-xcframework.pin.json}"

WORK_DIR="${SQLCIPHER_RESTORE_WORK_DIR:-${REPO_ROOT}/build/sqlcipher-xcframework/release}"
LOCAL_BUILD_DIR=""
REQUIRE_ATTESTATION=0

usage() {
    cat <<USAGE
Usage: scripts/restore_sqlcipher_xcframework.sh [--from-local-build PATH] [--require-attestation]

Restores the pinned SQLCipher.xcframework release into the repository root for
Xcode linking. Downloaded assets and the extracted XCFramework are ignored by git.
The pinned release contract is read from third_party/sqlcipher-xcframework.pin.json.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --from-local-build)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            LOCAL_BUILD_DIR="$2"
            shift 2
            ;;
        --require-attestation)
            REQUIRE_ATTESTATION=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

log() { echo "[restore_sqlcipher_xcframework] $*"; }

# Retry a network-dependent command. Transient GitHub API resets (connection
# reset by peer) have killed a release archive action mid-verification, and
# parallel CI machines make such flakes routine. Deterministic failures (bad
# pin, failed attestation) still fail — just after the final attempt.
NET_RETRY_ATTEMPTS="${SQLCIPHER_RESTORE_NET_ATTEMPTS:-3}"
retry_net() {
    local label="$1"; shift
    local attempt=1
    while true; do
        if "$@"; then return 0; fi
        if [ "$attempt" -ge "$NET_RETRY_ATTEMPTS" ]; then
            echo "error: $label failed after $NET_RETRY_ATTEMPTS attempts" >&2
            exit 1
        fi
        log "$label failed (attempt $attempt/$NET_RETRY_ATTEMPTS); retrying in $((attempt * 10))s"
        sleep $((attempt * 10))
        attempt=$((attempt + 1))
    done
}

pin_value() {
    local path="$1"
    python3 - "$PIN_FILE" "$path" <<'PY'
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
    local asset="$1"
    python3 - "$PIN_FILE" "$asset" <<'PY'
import json
import sys

pin_path, asset_name = sys.argv[1:3]
with open(pin_path, encoding="utf-8") as handle:
    payload = json.load(handle)
print(payload["assets"][asset_name]["sha256"])
PY
}

pin_asset_size() {
    local asset="$1"
    python3 - "$PIN_FILE" "$asset" <<'PY'
import json
import sys

pin_path, asset_name = sys.argv[1:3]
with open(pin_path, encoding="utf-8") as handle:
    payload = json.load(handle)
asset = payload["assets"].get(asset_name)
if asset is None:
    print(f"error: asset {asset_name!r} is not in the SQLCipher pin file", file=sys.stderr)
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

[ -f "$PIN_FILE" ] || {
    echo "error: SQLCipher pin file is missing: $PIN_FILE" >&2
    exit 1
}

RELEASE_REPOSITORY="$(pin_value repository)"
RELEASE_TAG="$(pin_value release.tag)"
RELEASE_COMMIT="$(pin_value release.commitSha)"
RELEASE_SOURCE_REF="$(pin_value release.sourceRef)"
RELEASE_SIGNER_WORKFLOW="$(pin_value release.signerWorkflow)"
RELEASE_CHANNEL="$(pin_value release.channel)"
RELEASE_BASE_URL="https://github.com/${RELEASE_REPOSITORY}/releases/download/${RELEASE_TAG}"
EXPECTED_ASSET_NAMES=()
while IFS= read -r asset; do
    EXPECTED_ASSET_NAMES+=("$asset")
done < <(pin_asset_names)

if [ "$RELEASE_TAG" = "latest" ] || [ -z "$RELEASE_TAG" ]; then
    echo "error: SQLCipher restore must pin an exact release tag, not latest" >&2
    exit 1
fi
if [ "$RELEASE_CHANNEL" != "stable" ]; then
    echo "error: SQLCipher restore requires a stable release pin, got: $RELEASE_CHANNEL" >&2
    exit 1
fi
if [ "${#EXPECTED_ASSET_NAMES[@]}" -eq 0 ]; then
    echo "error: SQLCipher pin file contains no assets" >&2
    exit 1
fi
if [ "$REQUIRE_ATTESTATION" -eq 1 ] && [ -n "$LOCAL_BUILD_DIR" ]; then
    echo "error: --require-attestation cannot be used with --from-local-build" >&2
    exit 1
fi

copy_or_download_asset() {
    local asset="$1"
    if [ -n "$LOCAL_BUILD_DIR" ]; then
        local source_path="${LOCAL_BUILD_DIR%/}/$asset"
        [ -f "$source_path" ] || {
            echo "error: local SQLCipher build asset missing: $source_path" >&2
            exit 1
        }
        cp "$source_path" "$WORK_DIR/$asset"
    else
        retry_net "download of $asset" \
            curl -fL --proto '=https' --tlsv1.2 \
            -o "$WORK_DIR/$asset" \
            "$RELEASE_BASE_URL/$asset"
    fi
}

verify_asset_hash() {
    local asset="$1"
    local expected="$2"
    local actual
    actual="$(shasum -a 256 "$WORK_DIR/$asset" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "error: $asset sha256 $actual != expected $expected" >&2
        exit 1
    fi
}

verify_asset_size() {
    local asset="$1"
    local expected="$2"
    local actual
    actual="$(file_size_bytes "$WORK_DIR/$asset")"
    if [ "$actual" != "$expected" ]; then
        echo "error: $asset size $actual != expected $expected" >&2
        exit 1
    fi
}

fetch_release_metadata() {
    gh release view "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" \
        --json tagName,isDraft,isPrerelease,isImmutable,targetCommitish,url \
        > "$1"
}

gh_release_verify() {
    gh release verify "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" >/dev/null
}

verify_release_integrity() {
    local release_json
    release_json="$(mktemp)"
    retry_net "SQLCipher release metadata fetch" fetch_release_metadata "$release_json"
    python3 - "$release_json" "$RELEASE_TAG" "$RELEASE_COMMIT" <<'PY'
import json
import sys

path, expected_tag, expected_commit = sys.argv[1:4]
with open(path, encoding="utf-8") as handle:
    release = json.load(handle)

errors = []
if release.get("tagName") != expected_tag:
    errors.append(f"release tag {release.get('tagName')!r} != {expected_tag!r}")
if release.get("targetCommitish") != expected_commit:
    errors.append(f"release target {release.get('targetCommitish')!r} != {expected_commit!r}")
if release.get("isDraft") is not False:
    errors.append("release must not be draft")
if release.get("isPrerelease") is not False:
    errors.append("release must not be prerelease")
if release.get("isImmutable") is not True:
    errors.append("release must be immutable")
if errors:
    raise SystemExit("error: " + "; ".join(errors))
PY
    rm -f "$release_json"
    retry_net "SQLCipher release tag verification" gh_release_verify
}

gh_verify_release_asset() {
    (
        cd "$WORK_DIR"
        gh release verify-asset "$RELEASE_TAG" "$1" -R "$RELEASE_REPOSITORY" >/dev/null
    )
}

gh_verify_asset_attestation() {
    gh attestation verify "$WORK_DIR/$1" \
        -R "$RELEASE_REPOSITORY" \
        --signer-workflow "$RELEASE_SIGNER_WORKFLOW" \
        --source-ref "$RELEASE_SOURCE_REF" \
        --source-digest "$RELEASE_COMMIT" \
        --deny-self-hosted-runners >/dev/null
}

verify_attestation() {
    local asset="$1"
    retry_net "SQLCipher release asset verification of $asset" gh_verify_release_asset "$asset"
    retry_net "SQLCipher attestation verification of $asset" gh_verify_asset_attestation "$asset"
}

# The zip's sha256 is pinned, but extraction still runs with full filesystem
# privileges: reject archives whose entry names could write outside the
# staging directory (absolute paths, .. components) or outside the single
# expected SQLCipher.xcframework/ root before extracting anything.
validate_zip_entries() {
    local zip_path="$1"
    python3 - "$zip_path" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    names = archive.namelist()

errors = []
if not names:
    errors.append("archive has no entries")
for name in names:
    if name.startswith("/"):
        errors.append(f"absolute path entry: {name!r}")
    elif ".." in name.split("/"):
        errors.append(f"parent-directory entry: {name!r}")
    elif name.rstrip("/") != "SQLCipher.xcframework" and not name.startswith("SQLCipher.xcframework/"):
        errors.append(f"entry outside SQLCipher.xcframework/: {name!r}")
if errors:
    raise SystemExit("error: rejecting SQLCipher zip: " + "; ".join(errors[:10]))
PY
}

# Symlinks are legitimate inside an xcframework (macOS framework bundles use
# versioned-layout links); reject only links whose resolved target escapes
# the extracted tree.
validate_extracted_symlinks() {
    local tree="$1"
    python3 - "$tree" <<'PY'
import os
import sys

root = os.path.realpath(sys.argv[1])
errors = []
for dirpath, dirnames, filenames in os.walk(root):
    for entry in dirnames + filenames:
        path = os.path.join(dirpath, entry)
        if not os.path.islink(path):
            continue
        resolved = os.path.realpath(path)
        if resolved != root and not resolved.startswith(root + os.sep):
            errors.append(
                f"symlink escapes the xcframework: {os.path.relpath(path, root)} -> {os.readlink(path)}"
            )
if errors:
    raise SystemExit("error: rejecting SQLCipher zip: " + "; ".join(errors[:10]))
PY
}

STAGING_DIR=""
cleanup_staging_dir() {
    if [ -n "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
        STAGING_DIR=""
    fi
}
trap cleanup_staging_dir EXIT

mkdir -p "$WORK_DIR"
rm -rf "$WORK_DIR"/*

if [ -n "$LOCAL_BUILD_DIR" ]; then
    log "copying pinned assets from local build: $LOCAL_BUILD_DIR"
else
    log "downloading pinned release: $RELEASE_TAG"
fi

for asset in "${EXPECTED_ASSET_NAMES[@]}"; do
    copy_or_download_asset "$asset"
    verify_asset_size "$asset" "$(pin_asset_size "$asset")"
    verify_asset_hash "$asset" "$(pin_asset_hash "$asset")"
done

(
    cd "$WORK_DIR"
    shasum -a 256 -c SQLCipher.xcframework.sha256
)
if [ "$REQUIRE_ATTESTATION" -eq 1 ]; then
    command -v gh >/dev/null 2>&1 || {
        echo "error: gh is required for SQLCipher attestation verification" >&2
        exit 1
    }
    log "verifying immutable release and file attestations"
    verify_release_integrity
    for asset in "${EXPECTED_ASSET_NAMES[@]}"; do
        verify_attestation "$asset"
    done
fi

log "extracting SQLCipher.xcframework"
validate_zip_entries "$WORK_DIR/SQLCipher.xcframework.zip"
# Extract into a staging directory on the same volume and move the framework
# into place only after every check passes, so a bad archive can neither
# write into the repository root nor destroy the previously restored copy.
STAGING_DIR="$(mktemp -d "$WORK_DIR/extract.XXXXXX")"
ditto -x -k "$WORK_DIR/SQLCipher.xcframework.zip" "$STAGING_DIR"
[ -d "$STAGING_DIR/SQLCipher.xcframework" ] || {
    echo "error: archive did not produce SQLCipher.xcframework" >&2
    exit 1
}
validate_extracted_symlinks "$STAGING_DIR/SQLCipher.xcframework"

rm -rf "$REPO_ROOT/SQLCipher.xcframework"
mv "$STAGING_DIR/SQLCipher.xcframework" "$REPO_ROOT/SQLCipher.xcframework"

cp "$WORK_DIR/SQLCipher.arm64e-build-manifest.json" "$REPO_ROOT/SQLCipher.arm64e-build-manifest.json"
cp "$WORK_DIR/SQLCipher-PrivacyInfo.xcprivacy" "$REPO_ROOT/SQLCipher-PrivacyInfo.xcprivacy"
cp "$WORK_DIR/SQLCipher.xcframework.release.json" "$REPO_ROOT/SQLCipher.xcframework.release.json"
cp "$WORK_DIR/SQLCipher.xcframework.sha256" "$REPO_ROOT/SQLCipher.xcframework.sha256"

python3 "$REPO_ROOT/scripts/validate_sqlcipher_xcframework.py" \
    --root "$REPO_ROOT" \
    --release-assets "$WORK_DIR"

log "SQLCipher.xcframework restored and validated"
