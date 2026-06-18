#!/bin/bash
# Xcode Cloud pre-xcodebuild hook for CypherAir.
#
# Intentionally minimal. The App Store candidate gate runs in ci_post_clone.sh
# (after the xcframework is in place), and the in-app Source & Compliance values
# are derived directly from CI_TAG/CI_COMMIT by the project's source-compliance
# build phase (scripts/generate_source_compliance_build_phase.sh), which already
# sees the Xcode Cloud environment. This hook is reserved for future per-action
# adjustments keyed on CI_PRODUCT_PLATFORM / CI_XCODEBUILD_ACTION.

set -euo pipefail

echo "[ci_pre_xcodebuild] workflow=${CI_WORKFLOW:-<unset>} platform=${CI_PRODUCT_PLATFORM:-<none>} action=${CI_XCODEBUILD_ACTION:-<none>}"
exit 0
