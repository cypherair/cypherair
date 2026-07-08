#!/bin/bash
# Print the pass/fail summary and every test failure from an .xcresult bundle.
#
# Usage: scripts/xcresult_failures.sh [path/to/bundle.xcresult]
# Without an argument, uses the newest CypherAir test bundle under Xcode
# DerivedData. Exits 0 when the bundle's tests all passed, 1 otherwise, 2 when
# no bundle is found.
set -uo pipefail

XCR="${1:-}"
if [ -z "$XCR" ]; then
  XCR=$(ls -td "$HOME"/Library/Developer/Xcode/DerivedData/CypherAir-*/Logs/Test/*.xcresult 2>/dev/null | head -1 || true)
fi
if [ -z "$XCR" ] || [ ! -e "$XCR" ]; then
  echo "no .xcresult found — pass a path or run a test lane first" >&2
  exit 2
fi
echo "bundle: $XCR"

SUMMARY=$(xcrun xcresulttool get test-results summary --path "$XCR")
echo "$SUMMARY" | jq -r '"result: \(.result)  passed: \(.passedTests)  failed: \(.failedTests)  skipped: \(.skippedTests)  expected-failures: \(.expectedFailures)"'

FAILED=$(echo "$SUMMARY" | jq -r '.failedTests')
if [ "$FAILED" = "0" ]; then
  exit 0
fi

echo
echo "=== failures (summary) ==="
echo "$SUMMARY" | jq -r '.testFailures[]? | "\(.targetName // "?")/\(.testName // .testIdentifierString // "?")\n  \(.failureText // tojson)"'

# Fall back to the full test tree when the summary carries no failure details.
if [ "$(echo "$SUMMARY" | jq -r '.testFailures | length')" = "0" ]; then
  echo "=== failures (test tree) ==="
  xcrun xcresulttool get test-results tests --path "$XCR" | jq -r '
    [.. | objects | select(.nodeType? == "Test Case" and .result? == "Failed")][]
    | .nodeIdentifier // .name,
      ([.. | objects | select(.nodeType? == "Failure Message") | "  " + .name] | join("\n"))'
fi
exit 1
