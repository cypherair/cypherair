#!/bin/bash
# Place the UniFFI outputs carried inside PgpMobile.xcframework where the Xcode
# project reads them: the Swift binding it compiles as app source, and the C
# interop header plus module map its per-configuration flags point at.
#
# Nothing generated is committed, so the bundle is the only place a checkout can
# get these from without rebuilding the crate. ./build-xcframework.sh runs this
# at the end of a successful sync; every consumer that restores a packaged
# artifact instead -- the CI platform probes, Xcode Cloud WF2 -- runs it right
# after the restore.
#
# The carry layout mirrors the checkout, so every destination is the carried
# path itself and this script names no file. Completeness is the fingerprint
# gate's job: scripts/xcframework_source_fingerprint.py --check re-hashes both
# ends of every recorded binding on every Xcode build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARRIED_DIR="$REPO_ROOT/PgpMobile.xcframework/cypherair-generated-bindings"

carries_nothing() {
    echo "error: PgpMobile.xcframework carries no generated bindings." >&2
    echo "       Where the crate is built, run the XCFramework sync:" >&2
    echo "           ./build-xcframework.sh --release" >&2
    echo "       Where the artifact is restored rather than built, obtain a current" >&2
    echo "       PgpMobile.xcframework and restore it again." >&2
    exit 1
}

[ -d "$CARRIED_DIR" ] || carries_nothing

placed=0
while IFS= read -r relative; do
    source="$CARRIED_DIR/$relative"
    destination="$REPO_ROOT/$relative"
    placed=$((placed + 1))

    # Rewrite only on a real change: an identical file with a fresh timestamp
    # costs the next Xcode build a full recompile of everything downstream.
    if [ -f "$destination" ] && cmp -s "$source" "$destination"; then
        echo "unchanged: $relative"
        continue
    fi

    mkdir -p "$(dirname "$destination")"
    cp "$source" "$destination"
    echo "placed: $relative"
done < <(cd "$CARRIED_DIR" && find . -type f -print | sed 's|^\./||' | sort)

[ "$placed" -gt 0 ] || carries_nothing
