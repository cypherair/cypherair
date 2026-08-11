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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARRIED_DIR="$REPO_ROOT/PgpMobile.xcframework/cypherair-generated-bindings"

place() {
    local name="$1"
    local destination="$2"
    local source="$CARRIED_DIR/$name"

    if [ ! -f "$source" ]; then
        echo "error: PgpMobile.xcframework carries no $name." >&2
        echo "       Run the XCFramework sync: ./build-xcframework.sh --release" >&2
        exit 1
    fi

    # Rewrite only on a real change: an identical file with a fresh timestamp
    # costs the next Xcode build a full recompile of everything downstream.
    if [ -f "$destination" ] && cmp -s "$source" "$destination"; then
        echo "unchanged: $destination"
        return
    fi

    mkdir -p "$(dirname "$destination")"
    cp "$source" "$destination"
    echo "placed: $destination"
}

place pgp_mobile.swift "$REPO_ROOT/Sources/PgpMobile/pgp_mobile.swift"
place module.modulemap "$REPO_ROOT/bindings/module.modulemap"
place pgp_mobileFFI.h "$REPO_ROOT/bindings/pgp_mobileFFI.h"
