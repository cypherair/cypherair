#!/usr/bin/env bash

set -euo pipefail

: "${SRCROOT:?SRCROOT is required}"
: "${TARGET_BUILD_DIR:?TARGET_BUILD_DIR is required}"
: "${UNLOCALIZED_RESOURCES_FOLDER_PATH:?UNLOCALIZED_RESOURCES_FOLDER_PATH is required}"

SNAPSHOT_LIST="${SNAPSHOT_LIST:-${SRCROOT}/Tests/RepositoryAuditInputs.xcfilelist}"
SNAPSHOT_DST="${SNAPSHOT_DST:-${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/RepositoryAudit}"

realpath_for() {
    python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"
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
