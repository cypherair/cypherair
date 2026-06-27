#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_TAG="sqlcipher-xcframework-experiment-20260626T224724Z-61d7f56-r28269517779-a1"
RELEASE_COMMIT="61d7f56baa687a19270c93f85b3663adc22fa9f2"
RELEASE_REPOSITORY="cypherair/sqlcipher-xcframework"
RELEASE_BASE_URL="https://github.com/${RELEASE_REPOSITORY}/releases/download/${RELEASE_TAG}"
EXPECTED_ZIP_SHA="22bd894ded5bdde119c87f81809b9b99a19dcd7afdf9410858a7fc34555ee20d"
EXPECTED_ASSET_NAMES=(
    "SQLCipher.xcframework.zip"
    "SQLCipher.xcframework.sha256"
    "SQLCipher.arm64e-build-manifest.json"
    "SQLCipher-PrivacyInfo.xcprivacy"
    "sqlcipher-xcframework-experiment.json"
)

WORK_DIR="${SQLCIPHER_RESTORE_WORK_DIR:-${REPO_ROOT}/build/sqlcipher-xcframework/release}"
LOCAL_BUILD_DIR=""
REQUIRE_ATTESTATION=0

usage() {
    cat <<USAGE
Usage: scripts/restore_sqlcipher_xcframework.sh [--from-local-build PATH] [--require-attestation]

Restores the pinned SQLCipher.xcframework release into the repository root for
Xcode linking. Downloaded assets and the extracted XCFramework are ignored by git.
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

if [ "$RELEASE_TAG" = "latest" ]; then
    echo "error: SQLCipher restore must pin an exact release tag, not latest" >&2
    exit 1
fi

log() { echo "[restore_sqlcipher_xcframework] $*"; }

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

verify_attestation() {
    local asset="$1"
    gh attestation verify "$WORK_DIR/$asset" \
        -R "$RELEASE_REPOSITORY" \
        --signer-workflow "${RELEASE_REPOSITORY}/.github/workflows/experimental-release.yml" \
        --source-ref refs/heads/main \
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
    log "verifying file attestations"
    for asset in "${EXPECTED_ASSET_NAMES[@]}"; do
        verify_attestation "$asset"
    done
fi

log "extracting SQLCipher.xcframework"
rm -rf "$REPO_ROOT/SQLCipher.xcframework"
ditto -x -k "$WORK_DIR/SQLCipher.xcframework.zip" "$REPO_ROOT"

cp "$WORK_DIR/SQLCipher.arm64e-build-manifest.json" "$REPO_ROOT/SQLCipher.arm64e-build-manifest.json"
cp "$WORK_DIR/SQLCipher-PrivacyInfo.xcprivacy" "$REPO_ROOT/SQLCipher-PrivacyInfo.xcprivacy"
cp "$WORK_DIR/sqlcipher-xcframework-experiment.json" "$REPO_ROOT/sqlcipher-xcframework-experiment.json"
cp "$WORK_DIR/SQLCipher.xcframework.sha256" "$REPO_ROOT/SQLCipher.xcframework.sha256"

python3 "$REPO_ROOT/scripts/validate_sqlcipher_xcframework.py" \
    --root "$REPO_ROOT" \
    --release-assets "$WORK_DIR"

log "SQLCipher.xcframework restored and validated"
