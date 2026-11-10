#!/bin/sh
# Fails if an import crosses the layers of docs/ARCHITECTURE.md section 1:
# the core imports no UI framework and no LocalAuthentication, and imports the
# vault and the engine only with `internal import`; the app imports neither
# the vault nor the engine. A clean build refuses some of these, an
# incremental build may not.
set -eu
cd "$(dirname "$0")/.."

import='^[[:space:]]*(@[[:alnum:]_]+[[:space:]]+)*((public|package|internal|fileprivate|private)[[:space:]]+)?import[[:space:]]+((typealias|struct|class|enum|protocol|let|var|func)[[:space:]]+)?'
end='([.[:space:]]|$)'
lower='(Vault|Stores|Sealing|VaultTestSupport|CypherEngine[[:alnum:]_]*|cypher_engine[[:alnum:]_]*)'
failed=0

report() {
    if [ -n "$2" ]; then
        printf '%s\n%s\n' "$1" "$2" >&2
        failed=1
    fi
}

report "The core imports a UI framework or LocalAuthentication:" \
    "$(grep -rEn "${import}(SwiftUI|UIKit|AppKit|Cocoa|WatchKit|RealityKit|LocalAuthentication)${end}" Packages/CypherCore/Sources || true)"
report "The core imports the vault or the engine without \`internal import\`:" \
    "$(grep -rEn "${import}${lower}${end}" Packages/CypherCore/Sources | grep -vE ':[0-9]+:[[:space:]]*(internal|fileprivate|private)[[:space:]]+import[[:space:]]' || true)"
report "The app imports the vault or the engine:" \
    "$(grep -rEn "${import}${lower}${end}" App || true)"

exit "$failed"
