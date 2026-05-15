#!/usr/bin/env bash

set -euo pipefail

: "${SRCROOT:?SRCROOT is required}"
: "${TARGET_BUILD_DIR:?TARGET_BUILD_DIR is required}"
: "${UNLOCALIZED_RESOURCES_FOLDER_PATH:?UNLOCALIZED_RESOURCES_FOLDER_PATH is required}"

SNAPSHOT_LIST="${SNAPSHOT_LIST:-${SRCROOT}/Tests/RepositoryAuditInputs.xcfilelist}"
SNAPSHOT_DST="${SNAPSHOT_DST:-${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/RepositoryAudit}"
SNAPSHOT_OUTPUT_LIST="${SNAPSHOT_OUTPUT_LIST:-${SRCROOT}/Tests/RepositoryAuditOutputs.xcfilelist}"

manifest_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/repository-audit-manifest.XXXXXX")"
trap 'rm -rf "$manifest_tmp_dir"' EXIT

realpath_for() {
    python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

manifest_input_relative_path() {
    case "$1" in
        "\$(SRCROOT)"/Sources/*.swift)
            printf '%s\n' "${1#\$(SRCROOT)/}"
            ;;
        "$SRCROOT"/Sources/*.swift)
            printf '%s\n' "${1#"$SRCROOT"/}"
            ;;
    esac
}

manifest_output_relative_path() {
    local output_prefix

    output_prefix="\$(TARGET_BUILD_DIR)/\$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/RepositoryAudit/"
    case "$1" in
        "$output_prefix"Sources/*.swift)
            printf '%s\n' "${1#"$output_prefix"}"
            ;;
    esac
}

list_repository_swift_sources() {
    if [ -e "$SRCROOT/.git" ]; then
        if [ -n "${SCRIPT_INPUT_FILE_COUNT:-}" ]; then
            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
                git -C "$SRCROOT" ls-files -- 'Sources/*.swift'
        else
            GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
                git -C "$SRCROOT" ls-files --cached --others --exclude-standard -- 'Sources/*.swift'
        fi
    else
        find "$SRCROOT/Sources" -type f -name '*.swift' -print | while IFS= read -r source_path; do
            printf '%s\n' "${source_path#"$SRCROOT"/}"
        done
    fi | LC_ALL=C sort -u
}

list_snapshot_input_swift_sources() {
    while IFS= read -r input_path; do
        case "$input_path" in
            ""|\#*)
                ;;
            *)
                manifest_input_relative_path "$input_path"
                ;;
        esac
    done < "$SNAPSHOT_LIST" | LC_ALL=C sort
}

list_snapshot_output_swift_sources() {
    while IFS= read -r output_path; do
        case "$output_path" in
            ""|\#*)
                ;;
            *)
                manifest_output_relative_path "$output_path"
                ;;
        esac
    done < "$SNAPSHOT_OUTPUT_LIST" | LC_ALL=C sort
}

print_manifest_paths() {
    sed 's/^/       /' "$1" >&2
}

validate_swift_manifest_completeness() {
    local actual_swift_sources
    local input_swift_sources
    local output_swift_sources
    local missing_inputs
    local stale_inputs
    local missing_outputs
    local stale_outputs
    local failed

    actual_swift_sources="$manifest_tmp_dir/actual-swift-sources"
    input_swift_sources="$manifest_tmp_dir/input-swift-sources"
    output_swift_sources="$manifest_tmp_dir/output-swift-sources"
    missing_inputs="$manifest_tmp_dir/missing-inputs"
    stale_inputs="$manifest_tmp_dir/stale-inputs"
    missing_outputs="$manifest_tmp_dir/missing-outputs"
    stale_outputs="$manifest_tmp_dir/stale-outputs"

    list_repository_swift_sources > "$actual_swift_sources"
    list_snapshot_input_swift_sources > "$input_swift_sources"
    list_snapshot_output_swift_sources > "$output_swift_sources"

    comm -23 "$actual_swift_sources" "$input_swift_sources" > "$missing_inputs"
    comm -13 "$actual_swift_sources" "$input_swift_sources" > "$stale_inputs"
    comm -23 "$input_swift_sources" "$output_swift_sources" > "$missing_outputs"
    comm -13 "$input_swift_sources" "$output_swift_sources" > "$stale_outputs"

    failed=0
    if [ -s "$missing_inputs" ]; then
        echo "error: RepositoryAudit input filelist is missing Swift sources:" >&2
        print_manifest_paths "$missing_inputs"
        failed=1
    fi
    if [ -s "$stale_inputs" ]; then
        echo "error: RepositoryAudit input filelist contains stale Swift sources:" >&2
        print_manifest_paths "$stale_inputs"
        failed=1
    fi
    if [ -s "$missing_outputs" ]; then
        echo "error: RepositoryAudit output filelist is missing Swift outputs for inputs:" >&2
        print_manifest_paths "$missing_outputs"
        failed=1
    fi
    if [ -s "$stale_outputs" ]; then
        echo "error: RepositoryAudit output filelist contains stale Swift outputs:" >&2
        print_manifest_paths "$stale_outputs"
        failed=1
    fi

    if [ "$failed" -ne 0 ]; then
        echo "error: Update Tests/RepositoryAuditInputs.xcfilelist and Tests/RepositoryAuditOutputs.xcfilelist." >&2
        exit 1
    fi
}

target_build_dir_real="$(realpath_for "$TARGET_BUILD_DIR")"
snapshot_dst_real="$(realpath_for "$SNAPSHOT_DST")"
case "$snapshot_dst_real" in
    "$target_build_dir_real"/*)
        ;;
    *)
        echo "error: RepositoryAudit snapshot destination must stay inside TARGET_BUILD_DIR." >&2
        echo "       TARGET_BUILD_DIR: $target_build_dir_real" >&2
        echo "       SNAPSHOT_DST: $snapshot_dst_real" >&2
        exit 1
        ;;
esac

validate_swift_manifest_completeness

mkdir -p "$SNAPSHOT_DST/Sources"
if [ -d "$SNAPSHOT_DST" ]; then
    find "$SNAPSHOT_DST" \( -type f -o -type l \) -delete
fi

resolve_snapshot_path() {
    case "$1" in
        "\$(SRCROOT)"/*)
            printf '%s/%s\n' "$SRCROOT" "${1#\$(SRCROOT)/}"
            ;;
        *)
            printf '%s\n' "$1"
            ;;
    esac
}

copied=0
copy_snapshot_input() {
    local input_path
    local relative_path
    local output_path

    input_path="$(resolve_snapshot_path "$1")"
    case "$input_path" in
        "$SRCROOT"/Sources/*)
            relative_path="${input_path#"$SRCROOT"/}"
            output_path="$SNAPSHOT_DST/$relative_path"
            mkdir -p "$(dirname "$output_path")"
            cp "$input_path" "$output_path"
            copied=$((copied + 1))
            ;;
    esac
}

index=0
while [ "$index" -lt "${SCRIPT_INPUT_FILE_COUNT:-0}" ]; do
    input_variable="SCRIPT_INPUT_FILE_$index"
    copy_snapshot_input "${!input_variable}"
    index=$((index + 1))
done

if [ "$copied" -eq 0 ]; then
    while IFS= read -r input_path; do
        [ -n "$input_path" ] && copy_snapshot_input "$input_path"
    done < "$SNAPSHOT_LIST"
fi

[ -f "$SNAPSHOT_DST/Sources/App/Encrypt/EncryptView.swift" ]
[ -f "$SNAPSHOT_DST/Sources/Resources/Localizable.xcstrings" ]
[ -f "$SNAPSHOT_DST/Sources/Resources/InfoPlist.xcstrings" ]
