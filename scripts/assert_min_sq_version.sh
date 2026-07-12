#!/usr/bin/env bash
# Assert the installed sequoia-sq meets a minimum version and echo the detected
# version as evidence-of-record for the sq cross-tool interop lane (issue #567).
#
# The interop contract (RFC 9580 v6 + RFC 9980 composite suites, --profile
# rfc9580, PQ cipher suites) is stable across sq >= 1.3, so the lane asserts a
# floor rather than pinning an exact release; the runner's actual sq and
# sequoia-openpgp versions are recorded in the job log.
#
# Usage: assert_min_sq_version.sh <min-version, e.g. 1.3.0>
set -euo pipefail

min_version="${1:?usage: assert_min_sq_version.sh <min-version e.g. 1.3.0>}"

version_output="$(sq version 2>&1)"
echo "Detected sq:"
echo "${version_output}"

version_line="$(printf '%s\n' "${version_output}" | grep -E '^sq ' | head -n1)"
detected="$(printf '%s\n' "${version_line}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
if [ -z "${detected}" ]; then
  echo "::error::could not parse an sq version from: ${version_output}"
  exit 1
fi

# detected >= min_version when the version-sorted minimum of the two equals min_version.
lowest="$(printf '%s\n%s\n' "${min_version}" "${detected}" | sort -V | head -n1)"
if [ "${lowest}" != "${min_version}" ]; then
  echo "::error::sq ${detected} is below the required interop floor ${min_version}"
  exit 1
fi

echo "sq ${detected} satisfies the >= ${min_version} interop floor"
