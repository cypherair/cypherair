#!/usr/bin/env bash
# Assert the installed GnuPG meets a minimum version and echo the detected version
# as evidence-of-record for the Secure Enclave custody GnuPG interop lane.
#
# The interop contract (v4 ECDSA/ECDH P-256, PKESK v3, SEIPDv1/MDC, v6 rejection) is
# stable across GnuPG >= 2.4, so the lane asserts a floor rather than pinning an exact
# release; the runner's actual version is recorded in the job log.
#
# Usage: assert_min_gpg_version.sh <min-version, e.g. 2.4.0>
set -euo pipefail

min_version="${1:?usage: assert_min_gpg_version.sh <min-version e.g. 2.4.0>}"

version_line="$(gpg --version | head -n1)"
echo "Detected GnuPG: ${version_line}"

detected="$(printf '%s\n' "${version_line}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
if [ -z "${detected}" ]; then
  echo "::error::could not parse a GnuPG version from: ${version_line}"
  exit 1
fi

# detected >= min_version when the version-sorted minimum of the two equals min_version.
lowest="$(printf '%s\n%s\n' "${min_version}" "${detected}" | sort -V | head -n1)"
if [ "${lowest}" != "${min_version}" ]; then
  echo "::error::GnuPG ${detected} is below the required interop floor ${min_version}"
  exit 1
fi

echo "GnuPG ${detected} satisfies the >= ${min_version} interop floor"
