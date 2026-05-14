#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/ci_xcode_platform_preflight.sh select
  scripts/ci_xcode_platform_preflight.sh preflight [--strict]

select writes DEVELOPER_DIR using the same Xcode candidate order as the
GitHub Actions workflows. preflight also checks whether the selected Xcode is
ready to run the iOS and visionOS generic app build probes.
EOF
}

mode="${1:-}"
strict="false"

if [ "$mode" != "select" ] && [ "$mode" != "preflight" ]; then
  usage
  exit 2
fi

if [ "$mode" = "preflight" ]; then
  if [ $# -eq 2 ] && [ "${2:-}" = "--strict" ]; then
    strict="true"
  elif [ $# -ne 1 ]; then
    usage
    exit 2
  fi
elif [ $# -ne 1 ]; then
  usage
  exit 2
fi

required_version="${XCODE_PLATFORM_REQUIRED_VERSION:-26.5}"
required_xcode_path="/Applications/Xcode_${required_version}.app/Contents/Developer"

github_env_set() {
  local name="$1"
  local value="$2"

  export "$name=$value"
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_ENV"
  fi
}

github_output_set() {
  local name="$1"
  local value="$2"

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  fi
}

summary_line() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

begin_group() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    printf '::group::%s\n' "$1"
  else
    printf '== %s ==\n' "$1"
  fi
}

end_group() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    printf '::endgroup::\n'
  fi
}

select_xcode() {
  local selected_developer_dir=""

  if [ -n "${XCODE_26_DEVELOPER_DIR:-}" ] && [ -d "${XCODE_26_DEVELOPER_DIR}" ]; then
    selected_developer_dir="${XCODE_26_DEVELOPER_DIR}"
  elif [ -d "$required_xcode_path" ]; then
    selected_developer_dir="$required_xcode_path"
  else
    printf '::error::Xcode %s was not found on this runner.\n' "$required_version"
    exit 1
  fi

  github_env_set DEVELOPER_DIR "$selected_developer_dir"
  printf 'Using DEVELOPER_DIR=%s\n' "$DEVELOPER_DIR"
  xcode-select -p
  xcodebuild -version
}

record_failure() {
  local failures_name="$1"
  local message="$2"

  printf -v "$failures_name" '%s\n- %s' "${!failures_name}" "$message"
}

runtime_available() {
  local platform_label="$1"
  local version="$2"

  DEVELOPER_DIR="$DEVELOPER_DIR" xcrun simctl list runtimes available -j 2>/dev/null \
    | python3 -c '
import json
import sys

platform = sys.argv[1].lower()
version = sys.argv[2]

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)

for runtime in data.get("runtimes", []):
    if not runtime.get("isAvailable", False):
        continue
    name = str(runtime.get("name", "")).lower()
    identifier = str(runtime.get("identifier", "")).lower()
    runtime_version = str(runtime.get("version", ""))
    if runtime_version == version and (platform in name or platform in identifier):
        sys.exit(0)

sys.exit(1)
' "$platform_label" "$version"
}

sdk_version() {
  local sdk="$1"

  DEVELOPER_DIR="$DEVELOPER_DIR" xcrun --sdk "$sdk" --show-sdk-version 2>/dev/null || true
}

show_destinations() {
  local output_file="$1"

  DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -showdestinations \
    -scheme CypherAir \
    -project CypherAir.xcodeproj \
    > "$output_file" 2>&1
}

check_platform_readiness() {
  local failures=""
  local xcode_version iphoneos_version xros_version destinations_file

  xcode_version="$(DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' | head -n1)"
  case "$xcode_version" in
    "$required_version"|"$required_version".*) ;;
    *)
      record_failure failures "selected Xcode is ${xcode_version:-unknown}, not $required_version"
      ;;
  esac

  iphoneos_version="$(sdk_version iphoneos)"
  if [ "$iphoneos_version" != "$required_version" ]; then
    record_failure failures "iphoneos SDK is ${iphoneos_version:-missing}, not $required_version"
  fi

  xros_version="$(sdk_version xros)"
  if [ "$xros_version" != "$required_version" ]; then
    record_failure failures "xros SDK is ${xros_version:-missing}, not $required_version"
  fi

  if ! runtime_available "iOS" "$required_version"; then
    record_failure failures "iOS $required_version simulator runtime is not available"
  fi

  if ! runtime_available "visionOS" "$required_version"; then
    record_failure failures "visionOS $required_version simulator runtime is not available"
  fi

  destinations_file="$(mktemp "${TMPDIR:-/tmp}/cypherair-destinations.XXXXXX")"
  if ! show_destinations "$destinations_file"; then
    record_failure failures "xcodebuild -showdestinations failed"
  fi

  if grep -q "iOS $required_version is not installed" "$destinations_file"; then
    record_failure failures "generic iOS destination reports iOS $required_version is not installed"
  elif ! grep -Eq "platform:iOS.*name:Any iOS Device" "$destinations_file"; then
    record_failure failures "generic iOS destination is not eligible"
  fi

  if grep -q "visionOS $required_version is not installed" "$destinations_file"; then
    record_failure failures "generic visionOS destination reports visionOS $required_version is not installed"
  elif ! grep -Eq "platform:visionOS.*name:Any visionOS Device" "$destinations_file"; then
    record_failure failures "generic visionOS destination is not eligible"
  fi

  rm -f "$destinations_file"

  if [ -n "$failures" ]; then
    printf '%s\n' "$failures"
    return 1
  fi

  return 0
}

select_xcode

if [ "$mode" = "select" ]; then
  exit 0
fi

begin_group "Runner and Xcode diagnostics"
printf 'Runner OS: %s\n' "${RUNNER_OS:-unknown}"
printf 'Runner arch: %s\n' "${RUNNER_ARCH:-unknown}"
printf 'Runner image OS: %s\n' "${ImageOS:-unknown}"
printf 'Runner image version: %s\n' "${ImageVersion:-unknown}"
printf 'DEVELOPER_DIR: %s\n' "$DEVELOPER_DIR"
DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version || true
end_group

begin_group "Available SDKs"
DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -showsdks || true
end_group

begin_group "Available simulator runtimes"
DEVELOPER_DIR="$DEVELOPER_DIR" xcrun simctl list runtimes available || true
end_group

if readiness_failures="$(check_platform_readiness)"; then
  github_output_set ready "true"
  github_output_set skip_reason ""
  summary_line "### Xcode $required_version Platform Probe Readiness"
  summary_line ""
  summary_line "- Status: ready"
  summary_line "- Xcode: $DEVELOPER_DIR"
  echo "Xcode $required_version platform probes are ready."
  exit 0
fi

skip_reason="$(printf '%s\n' "$readiness_failures" | awk 'NF { sub(/^- /, ""); printf "%s%s", sep, $0; sep="; " }')"
github_output_set ready "false"
github_output_set skip_reason "$skip_reason"
summary_line "### Xcode $required_version Platform Probe Readiness"
summary_line ""
summary_line "- Status: not ready"
summary_line "- Reason: $skip_reason"

if [ "$strict" = "true" ]; then
  printf '::error::Xcode %s platform probes are required but this runner is not ready: %s\n' "$required_version" "$skip_reason"
  printf '%s\n' "$readiness_failures"
  exit 1
fi

printf '::warning::Skipping Xcode %s platform probes because this runner is not ready: %s\n' "$required_version" "$skip_reason"
printf '%s\n' "$readiness_failures"
