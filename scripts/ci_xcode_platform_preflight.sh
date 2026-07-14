#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/ci_xcode_platform_preflight.sh select
  scripts/ci_xcode_platform_preflight.sh preflight [--strict]
  scripts/ci_xcode_platform_preflight.sh macos-unit-test-preflight [--strict]

select writes DEVELOPER_DIR using the same Xcode candidate order as the
GitHub Actions workflows. preflight also checks whether the selected Xcode is
ready to run the iOS and visionOS generic app build probes.
macos-unit-test-preflight checks whether the hosted runner is ready to run the
macOS Swift unit-test preview.
EOF
}

mode="${1:-}"
strict="false"

if [ "$mode" != "select" ] && [ "$mode" != "preflight" ] && [ "$mode" != "macos-unit-test-preflight" ]; then
  usage
  exit 2
fi

if [ "$mode" = "preflight" ] || [ "$mode" = "macos-unit-test-preflight" ]; then
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

required_version="${XCODE_PLATFORM_REQUIRED_VERSION:-26.6}"
required_xcode_path="/Applications/Xcode_${required_version}.app/Contents/Developer"
# Xcode 26.6 is an IDE-only update: it ships the 26.5 SDKs and simulator
# runtimes, so the SDK/runtime expectation is pinned independently of the
# Xcode release that hosts it.
required_sdk_version="${XCODE_PLATFORM_REQUIRED_SDK_VERSION:-26.5}"

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

version_at_least() {
  local actual="$1"
  local minimum="$2"

  python3 -c '
import re
import sys

def parts(version):
    values = []
    for part in version.split("."):
        match = re.match(r"^([0-9]+)", part)
        if not match:
            raise ValueError(version)
        values.append(int(match.group(1)))
    return values

try:
    actual = parts(sys.argv[1])
    minimum = parts(sys.argv[2])
except Exception:
    sys.exit(1)

width = max(len(actual), len(minimum))
actual.extend([0] * (width - len(actual)))
minimum.extend([0] * (width - len(minimum)))
sys.exit(0 if actual >= minimum else 1)
' "$actual" "$minimum"
}

project_build_setting() {
  local setting="$1"
  local output_file

  output_file="$(mktemp "${TMPDIR:-/tmp}/cypherair-build-settings.XXXXXX")"
  if ! DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -showBuildSettings \
      -scheme CypherAir \
      -project CypherAir.xcodeproj \
      > "$output_file" 2>&1; then
    rm -f "$output_file"
    return 1
  fi

  sed -n "s/^[[:space:]]*${setting} = //p" "$output_file" | head -n1
  rm -f "$output_file"
}

show_destinations() {
  local output_file="$1"

  DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -showdestinations \
    -scheme CypherAir \
    -project CypherAir.xcodeproj \
    > "$output_file" 2>&1
}

showdestinations_failure_is_runtime_missing_only() {
  local output_file="$1"

  awk -v version="$required_sdk_version" '
    BEGIN {
      version_regex = version
      gsub(/\./, "\\.", version_regex)
      saw_runtime_missing = 0
      invalid = 0
    }

    /^[[:space:]]*$/ { next }
    /^Command line invocation:$/ { next }
    /^[[:space:]]+.*xcodebuild.*-showdestinations/ { next }
    /^User defaults from command line:$/ { next }
    /^[[:space:]]+[A-Za-z_][A-Za-z0-9_]* = / { next }
    /^Ineligible destinations for the "CypherAir" scheme:$/ { next }
    /^Available destinations for the "CypherAir" scheme:$/ { next }

    $0 ~ "^[[:space:]]*\\{ platform:iOS,.*name:Any iOS Device,.*error:iOS " version_regex " is not installed[^}]*\\}[[:space:]]*$" {
      saw_runtime_missing = 1
      next
    }

    $0 ~ "^[[:space:]]*\\{ platform:visionOS,.*name:Any visionOS Device,.*error:visionOS " version_regex " is not installed[^}]*\\}[[:space:]]*$" {
      saw_runtime_missing = 1
      next
    }

    {
      invalid = 1
      exit
    }

    END {
      if (invalid || !saw_runtime_missing) {
        exit 1
      }
    }
  ' "$output_file"
}

check_platform_readiness() {
  local blocking_failures="" skippable_failures=""
  local xcode_version iphoneos_version xros_version destinations_file
  local destinations_status ios_runtime_missing_reported="false" visionos_runtime_missing_reported="false"

  xcode_version="$(DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' | head -n1)"
  case "$xcode_version" in
    "$required_version"|"$required_version".*) ;;
    *)
      record_failure skippable_failures "selected Xcode is ${xcode_version:-unknown}, not $required_version"
      ;;
  esac

  iphoneos_version="$(sdk_version iphoneos)"
  if [ "$iphoneos_version" != "$required_sdk_version" ]; then
    record_failure skippable_failures "iphoneos SDK is ${iphoneos_version:-missing}, not $required_sdk_version"
  fi

  xros_version="$(sdk_version xros)"
  if [ "$xros_version" != "$required_sdk_version" ]; then
    record_failure skippable_failures "xros SDK is ${xros_version:-missing}, not $required_sdk_version"
  fi

  if ! runtime_available "iOS" "$required_sdk_version"; then
    record_failure skippable_failures "iOS $required_sdk_version simulator runtime is not available"
  fi

  if ! runtime_available "visionOS" "$required_sdk_version"; then
    record_failure skippable_failures "visionOS $required_sdk_version simulator runtime is not available"
  fi

  destinations_file="$(mktemp "${TMPDIR:-/tmp}/cypherair-destinations.XXXXXX")"
  if show_destinations "$destinations_file"; then
    destinations_status=0
  else
    destinations_status=$?
  fi

  if grep -q "iOS $required_sdk_version is not installed" "$destinations_file"; then
    ios_runtime_missing_reported="true"
    record_failure skippable_failures "generic iOS destination reports iOS $required_sdk_version is not installed"
  fi

  if grep -q "visionOS $required_sdk_version is not installed" "$destinations_file"; then
    visionos_runtime_missing_reported="true"
    record_failure skippable_failures "generic visionOS destination reports visionOS $required_sdk_version is not installed"
  fi

  if [ "$destinations_status" -ne 0 ]; then
    if ! showdestinations_failure_is_runtime_missing_only "$destinations_file"; then
      record_failure blocking_failures "xcodebuild -showdestinations failed"
    fi
  else
    if [ "$ios_runtime_missing_reported" != "true" ] && ! grep -Eq "platform:iOS.*name:Any iOS Device" "$destinations_file"; then
      record_failure blocking_failures "generic iOS destination is not eligible"
    fi

    if [ "$visionos_runtime_missing_reported" != "true" ] && ! grep -Eq "platform:visionOS.*name:Any visionOS Device" "$destinations_file"; then
      record_failure blocking_failures "generic visionOS destination is not eligible"
    fi
  fi

  rm -f "$destinations_file"

  if [ -n "$blocking_failures" ]; then
    printf '%s\n' "$blocking_failures"
    if [ -n "$skippable_failures" ]; then
      printf '%s\n' "$skippable_failures"
    fi
    return 2
  fi

  if [ -n "$skippable_failures" ]; then
    printf '%s\n' "$skippable_failures"
    return 1
  fi

  return 0
}

check_macos_unit_test_readiness() {
  local blocking_failures="" skippable_failures=""
  local xcode_version macosx_version host_macos_version project_macos_target destinations_file
  local destinations_status

  xcode_version="$(DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p' | head -n1)"
  case "$xcode_version" in
    "$required_version"|"$required_version".*) ;;
    *)
      record_failure skippable_failures "selected Xcode is ${xcode_version:-unknown}, not $required_version"
      ;;
  esac

  macosx_version="$(sdk_version macosx)"
  if [ "$macosx_version" != "$required_sdk_version" ]; then
    record_failure skippable_failures "macosx SDK is ${macosx_version:-missing}, not $required_sdk_version"
  fi

  host_macos_version="$(sw_vers -productVersion 2>/dev/null || true)"
  if ! project_macos_target="$(project_build_setting MACOSX_DEPLOYMENT_TARGET)"; then
    record_failure blocking_failures "xcodebuild -showBuildSettings failed"
  elif [ -z "$project_macos_target" ]; then
    record_failure blocking_failures "MACOSX_DEPLOYMENT_TARGET is missing"
  elif ! version_at_least "$host_macos_version" "$project_macos_target"; then
    record_failure skippable_failures "host macOS is ${host_macos_version:-unknown}, below MACOSX_DEPLOYMENT_TARGET $project_macos_target"
  fi

  destinations_file="$(mktemp "${TMPDIR:-/tmp}/cypherair-destinations.XXXXXX")"
  if show_destinations "$destinations_file"; then
    destinations_status=0
  else
    destinations_status=$?
  fi

  if [ "$destinations_status" -ne 0 ]; then
    record_failure blocking_failures "xcodebuild -showdestinations failed"
  elif ! grep -Eq "platform:macOS.*arch:arm64e" "$destinations_file"; then
    record_failure blocking_failures "macOS arm64e test destination is not eligible"
  fi

  rm -f "$destinations_file"

  if [ -n "$blocking_failures" ]; then
    printf '%s\n' "$blocking_failures"
    if [ -n "$skippable_failures" ]; then
      printf '%s\n' "$skippable_failures"
    fi
    return 2
  fi

  if [ -n "$skippable_failures" ]; then
    printf '%s\n' "$skippable_failures"
    return 1
  fi

  return 0
}

failure_summary() {
  awk 'NF { sub(/^- /, ""); printf "%s%s", sep, $0; sep="; " }'
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
printf 'Host macOS: %s\n' "$(sw_vers -productVersion 2>/dev/null || printf 'unknown')"
printf 'DEVELOPER_DIR: %s\n' "$DEVELOPER_DIR"
DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -version || true
end_group

begin_group "Available SDKs"
DEVELOPER_DIR="$DEVELOPER_DIR" xcodebuild -showsdks || true
end_group

begin_group "Available simulator runtimes"
DEVELOPER_DIR="$DEVELOPER_DIR" xcrun simctl list runtimes available || true
end_group

readiness_status=0
case "$mode" in
  preflight)
    readiness_title="Xcode $required_version Platform Probe Readiness"
    ready_message="Xcode $required_version platform probes are ready."
    warning_message="Skipping Xcode $required_version platform probes because this runner is not ready"
    required_message="Xcode $required_version platform probes are required but this runner is not ready"
    blocking_message="Xcode $required_version platform probe preflight failed due to project configuration"
    readiness_failures="$(check_platform_readiness)" || readiness_status=$?
    ;;
  macos-unit-test-preflight)
    readiness_title="Hosted Swift Unit Test Readiness"
    ready_message="Hosted Swift unit tests are ready."
    warning_message="Skipping hosted Swift unit tests because this runner is not ready"
    required_message="Hosted Swift unit tests are required but this runner is not ready"
    blocking_message="Hosted Swift unit-test preflight failed due to project configuration"
    readiness_failures="$(check_macos_unit_test_readiness)" || readiness_status=$?
    ;;
esac

if [ "$readiness_status" -eq 0 ]; then
  github_output_set ready "true"
  github_output_set skip_reason ""
  summary_line "### $readiness_title"
  summary_line ""
  summary_line "- Status: ready"
  summary_line "- Xcode: $DEVELOPER_DIR"
  echo "$ready_message"
  exit 0
fi

skip_reason="$(printf '%s\n' "$readiness_failures" | failure_summary)"

if [ "$readiness_status" -eq 2 ]; then
  summary_line "### $readiness_title"
  summary_line ""
  summary_line "- Status: failed"
  summary_line "- Reason: $skip_reason"
  printf '::error::%s: %s\n' "$blocking_message" "$skip_reason"
  printf '%s\n' "$readiness_failures"
  exit 1
fi

github_output_set ready "false"
github_output_set skip_reason "$skip_reason"
summary_line "### $readiness_title"
summary_line ""
summary_line "- Status: not ready"
summary_line "- Reason: $skip_reason"

if [ "$strict" = "true" ]; then
  printf '::error::%s: %s\n' "$required_message" "$skip_reason"
  printf '%s\n' "$readiness_failures"
  exit 1
fi

printf '::warning::%s: %s\n' "$warning_message" "$skip_reason"
printf '%s\n' "$readiness_failures"
