#!/bin/bash
# Official CypherAir Rust/UniFFI XCFramework entrypoint.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/scripts/build_apple_arm64e_xcframework.sh" "$@"
