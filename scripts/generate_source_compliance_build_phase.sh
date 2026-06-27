#!/usr/bin/env bash

set -euo pipefail

: "${SRCROOT:?SRCROOT is required}"
: "${TARGET_BUILD_DIR:?TARGET_BUILD_DIR is required}"
: "${TARGET_TEMP_DIR:?TARGET_TEMP_DIR is required}"
: "${UNLOCALIZED_RESOURCES_FOLDER_PATH:?UNLOCALIZED_RESOURCES_FOLDER_PATH is required}"
: "${MARKETING_VERSION:?MARKETING_VERSION is required}"
: "${CURRENT_PROJECT_VERSION:?CURRENT_PROJECT_VERSION is required}"

OUTPUT_PATH="${OUTPUT_PATH:-${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/SourceComplianceInfo.json}"
METADATA_FILE="${METADATA_FILE:-${TARGET_TEMP_DIR}/SourceComplianceOverrides.json}"
COMMIT_SHA="${SOURCE_COMPLIANCE_COMMIT_SHA:-}"
REQUIRE_STABLE_RELEASE="${SOURCE_COMPLIANCE_REQUIRE_STABLE_RELEASE:-NO}"
REPOSITORY_URL="https://github.com/cypherair/cypherair"
STABLE_RELEASE_TAG="${SOURCE_COMPLIANCE_STABLE_RELEASE_TAG:-}"
STABLE_RELEASE_URL="${SOURCE_COMPLIANCE_STABLE_RELEASE_URL:-}"
SQLCIPHER_PIN_FILE="${SOURCE_COMPLIANCE_SQLCIPHER_PIN_FILE:-${SRCROOT}/third_party/sqlcipher-xcframework.pin.json}"

is_commit_sha() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-fA-F]{40}$'
}

metadata_commit_sha() {
    if [ ! -f "$METADATA_FILE" ]; then
        return
    fi
    python3 - "$METADATA_FILE" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        payload = json.load(handle)
except Exception:
    print("")
    raise SystemExit

if isinstance(payload, dict):
    print(str(payload.get("commit_sha", "")).strip())
else:
    print("")
PY
}

fallback_git_commit_sha() {
    local git_head_file="${SRCROOT}/.git/HEAD"
    local git_head_log_file="${SRCROOT}/.git/logs/HEAD"
    local head_value

    if [ -f "$git_head_file" ]; then
        head_value="$(sed -n '1p' "$git_head_file")"
        if is_commit_sha "$head_value"; then
            printf '%s\n' "$head_value"
            return
        fi
    fi

    if [ -f "$git_head_log_file" ]; then
        awk 'NF >= 2 { sha=$2 } END { print sha }' "$git_head_log_file"
    fi
}

mkdir -p "$(dirname "$OUTPUT_PATH")"

# Xcode Cloud checks out a detached HEAD at the triggering tag and does not run
# the local scheme pre-action that writes SourceComplianceOverrides.json. When
# building in Xcode Cloud, derive the exact commit/tag/release URL from the
# Xcode Cloud environment so the in-app Source & Compliance page binds to the
# stable release. Explicit SOURCE_COMPLIANCE_* values still win, and
# non-Xcode-Cloud builds are unaffected.
case "${CI_XCODE_CLOUD:-}" in
    TRUE|true|1|YES|yes)
        if ! is_commit_sha "$COMMIT_SHA" && is_commit_sha "${CI_COMMIT:-}"; then
            COMMIT_SHA="${CI_COMMIT}"
        fi
        if [ -z "$STABLE_RELEASE_TAG" ] && [ -n "${CI_TAG:-}" ]; then
            STABLE_RELEASE_TAG="${CI_TAG}"
        fi
        if [ -z "$STABLE_RELEASE_URL" ] && [ -n "$STABLE_RELEASE_TAG" ]; then
            STABLE_RELEASE_URL="${REPOSITORY_URL}/releases/tag/${STABLE_RELEASE_TAG}"
        fi
        ;;
esac

case "$REQUIRE_STABLE_RELEASE" in
    YES|yes|TRUE|true|1)
        if ! is_commit_sha "$COMMIT_SHA"; then
            COMMIT_SHA="$(metadata_commit_sha)"
        fi
        if ! is_commit_sha "$COMMIT_SHA"; then
            COMMIT_SHA="$(fallback_git_commit_sha)"
        fi
        if ! is_commit_sha "$COMMIT_SHA"; then
            echo "error: stable-required build must resolve an exact git commit SHA from SOURCE_COMPLIANCE_COMMIT_SHA, source-compliance metadata, or sandbox-declared git metadata." >&2
            exit 1
        fi
        ;;
esac

set -- \
    --cargo-lock "${SRCROOT}/pgp-mobile/Cargo.lock" \
    --marketing-version "${MARKETING_VERSION}" \
    --build-number "${CURRENT_PROJECT_VERSION}" \
    --commit-sha "${COMMIT_SHA}" \
    --repository-url "${REPOSITORY_URL}" \
    --stable-release-tag "${STABLE_RELEASE_TAG}" \
    --stable-release-url "${STABLE_RELEASE_URL}" \
    --require-stable-release "${REQUIRE_STABLE_RELEASE}" \
    --output "$OUTPUT_PATH"

if [ -f "$METADATA_FILE" ]; then
    set -- "$@" --metadata-file "$METADATA_FILE"
fi
if [ -f "$SQLCIPHER_PIN_FILE" ]; then
    set -- "$@" --external-binary-dependency "$SQLCIPHER_PIN_FILE"
fi

python3 "${SRCROOT}/scripts/generate_source_compliance_info.py" "$@"
