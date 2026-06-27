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
EXPECTED_ZIP_SHA="$(pin_asset_hash "SQLCipher.xcframework.zip")"
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

verify_release_integrity() {
    local release_json
    release_json="$(mktemp)"
    gh release view "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" \
        --json tagName,isDraft,isPrerelease,isImmutable,targetCommitish,url \
        > "$release_json"
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
    gh release verify "$RELEASE_TAG" -R "$RELEASE_REPOSITORY" >/dev/null
}

verify_attestation() {
    local asset="$1"
    (
        cd "$WORK_DIR"
        gh release verify-asset "$RELEASE_TAG" "$asset" -R "$RELEASE_REPOSITORY" >/dev/null
    )
    gh attestation verify "$WORK_DIR/$asset" \
        -R "$RELEASE_REPOSITORY" \
        --signer-workflow "$RELEASE_SIGNER_WORKFLOW" \
        --source-ref "$RELEASE_SOURCE_REF" \
        --source-digest "$RELEASE_COMMIT" \
        --deny-self-hosted-runners >/dev/null
}

mkdir -p "$WORK_DIR"
rm -f "$WORK_DIR"/*

if [ -n "$LOCAL_BUILD_DIR" ]; then
    log "copying pinned assets from local build: $LOCAL_BUILD_DIR"
else
    log "downloading pinned release: $RELEASE_TAG"
fi

for asset in "${EXPECTED_ASSET_NAMES[@]}"; do
    copy_or_download_asset "$asset"
done

(
    cd "$WORK_DIR"
    shasum -a 256 -c SQLCipher.xcframework.sha256
)
verify_asset_hash "SQLCipher.xcframework.zip" "$EXPECTED_ZIP_SHA"

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
rm -rf "$REPO_ROOT/SQLCipher.xcframework"
ditto -x -k "$WORK_DIR/SQLCipher.xcframework.zip" "$REPO_ROOT"

cp "$WORK_DIR/SQLCipher.arm64e-build-manifest.json" "$REPO_ROOT/SQLCipher.arm64e-build-manifest.json"
cp "$WORK_DIR/SQLCipher-PrivacyInfo.xcprivacy" "$REPO_ROOT/SQLCipher-PrivacyInfo.xcprivacy"
cp "$WORK_DIR/SQLCipher.xcframework.release.json" "$REPO_ROOT/SQLCipher.xcframework.release.json"
cp "$WORK_DIR/SQLCipher.xcframework.sha256" "$REPO_ROOT/SQLCipher.xcframework.sha256"

python3 "$REPO_ROOT/scripts/validate_sqlcipher_xcframework.py" \
    --root "$REPO_ROOT" \
    --release-assets "$WORK_DIR"

log "SQLCipher.xcframework restored and validated"
