from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT


READY_DESTINATIONS = """\
Available destinations for the "CypherAir" scheme:
    { platform:iOS, id:dvtdevice-DVTiPhonePlaceholder-iphoneos:placeholder, name:Any iOS Device }
    { platform:visionOS, id:dvtdevice-DVTiOSDevicePlaceholder-xros:placeholder, name:Any visionOS Device }
"""


RUNTIME_MISSING_DESTINATIONS = """\
Ineligible destinations for the "CypherAir" scheme:
    { platform:iOS, name:Any iOS Device, error:iOS 26.5 is not installed. }
    { platform:visionOS, name:Any visionOS Device, error:visionOS 26.5 is not installed. }
"""


AVAILABLE_RUNTIMES = {
    "runtimes": [
        {
            "isAvailable": True,
            "name": "iOS 26.5",
            "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26-5",
            "version": "26.5",
        },
        {
            "isAvailable": True,
            "name": "visionOS 26.5",
            "identifier": "com.apple.CoreSimulator.SimRuntime.xrOS-26-5",
            "version": "26.5",
        },
    ]
}


class XcodePlatformPreflightTests(unittest.TestCase):
    def test_ready_when_runner_and_generic_destinations_are_available(self) -> None:
        result = self.run_preflight(destinations=READY_DESTINATIONS)

        self.assertEqual(result.process.returncode, 0, result.combined_output)
        self.assertEqual(result.outputs["ready"], "true")
        self.assertEqual(result.outputs["skip_reason"], "")
        self.assertIn("platform probes are ready", result.process.stdout)

    def test_runtime_missing_is_skippable_in_non_strict_preflight(self) -> None:
        result = self.run_preflight(
            destinations=RUNTIME_MISSING_DESTINATIONS,
            runtimes={"runtimes": []},
        )

        self.assertEqual(result.process.returncode, 0, result.combined_output)
        self.assertEqual(result.outputs["ready"], "false")
        self.assertIn("iOS 26.5 simulator runtime is not available", result.outputs["skip_reason"])
        self.assertIn(
            "generic visionOS destination reports visionOS 26.5 is not installed",
            result.outputs["skip_reason"],
        )

    def test_showdestinations_runtime_missing_failure_is_skippable(self) -> None:
        result = self.run_preflight(
            destinations=RUNTIME_MISSING_DESTINATIONS,
            destinations_status=70,
            runtimes={"runtimes": []},
        )

        self.assertEqual(result.process.returncode, 0, result.combined_output)
        self.assertEqual(result.outputs["ready"], "false")
        self.assertIn("generic iOS destination reports iOS 26.5 is not installed", result.outputs["skip_reason"])
        self.assertNotIn("xcodebuild -showdestinations failed", result.outputs["skip_reason"])

    def test_showdestinations_failure_without_runtime_missing_is_blocking(self) -> None:
        result = self.run_preflight(
            destinations="xcodebuild: error: Scheme CypherAir is not configured for this project.\n",
            destinations_status=65,
        )

        self.assertEqual(result.process.returncode, 1, result.combined_output)
        self.assertNotIn("ready", result.outputs)
        self.assertIn("::error::", result.combined_output)
        self.assertIn("xcodebuild -showdestinations failed", result.combined_output)

    def test_missing_generic_destination_is_blocking(self) -> None:
        cases = {
            "iOS": """\
Available destinations for the "CypherAir" scheme:
    { platform:visionOS, id:dvtdevice-DVTiOSDevicePlaceholder-xros:placeholder, name:Any visionOS Device }
""",
            "visionOS": """\
Available destinations for the "CypherAir" scheme:
    { platform:iOS, id:dvtdevice-DVTiPhonePlaceholder-iphoneos:placeholder, name:Any iOS Device }
""",
        }

        for platform, destinations in cases.items():
            with self.subTest(platform=platform):
                result = self.run_preflight(destinations=destinations)

                self.assertEqual(result.process.returncode, 1, result.combined_output)
                self.assertNotIn("ready", result.outputs)
                self.assertIn(f"generic {platform} destination is not eligible", result.combined_output)

    def test_strict_runtime_missing_fails(self) -> None:
        result = self.run_preflight(
            args=["preflight", "--strict"],
            destinations=RUNTIME_MISSING_DESTINATIONS,
            runtimes={"runtimes": []},
        )

        self.assertEqual(result.process.returncode, 1, result.combined_output)
        self.assertEqual(result.outputs["ready"], "false")
        self.assertIn("iOS 26.5 simulator runtime is not available", result.outputs["skip_reason"])
        self.assertIn("platform probes are required", result.combined_output)

    def run_preflight(
        self,
        *,
        args: list[str] | None = None,
        destinations: str,
        destinations_status: int = 0,
        runtimes: dict[str, object] | None = None,
    ) -> "PreflightResult":
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            fake_bin = temp_root / "bin"
            fake_bin.mkdir()
            developer_dir = temp_root / "Xcode_26.5.app" / "Contents" / "Developer"
            developer_dir.mkdir(parents=True)

            destinations_file = temp_root / "destinations.txt"
            destinations_file.write_text(destinations, encoding="utf-8")
            github_output = temp_root / "github-output.txt"
            github_summary = temp_root / "github-summary.md"

            self.write_executable(
                fake_bin / "xcode-select",
                """\
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-p" ]; then
  printf '%s\n' "${DEVELOPER_DIR:-/tmp/fake-xcode}"
  exit 0
fi
printf 'unsupported xcode-select args: %s\n' "$*" >&2
exit 64
""",
            )
            self.write_executable(
                fake_bin / "xcodebuild",
                """\
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -version)
    printf 'Xcode %s\nBuild version Fake\n' "${FAKE_XCODE_VERSION:-26.5}"
    ;;
  -showsdks)
    printf 'iOS SDKs:\n\tiPhoneOS%s.sdk\nvisionOS SDKs:\n\txrOS%s.sdk\n' \
      "${FAKE_IPHONEOS_VERSION:-26.5}" "${FAKE_XROS_VERSION:-26.5}"
    ;;
  -showdestinations)
    cat "$FAKE_DESTINATIONS_FILE"
    exit "${FAKE_DESTINATIONS_STATUS:-0}"
    ;;
  *)
    printf 'unsupported xcodebuild args: %s\n' "$*" >&2
    exit 64
    ;;
esac
""",
            )
            self.write_executable(
                fake_bin / "xcrun",
                """\
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--sdk" ]; then
  case "${2:-}" in
    iphoneos)
      printf '%s\n' "${FAKE_IPHONEOS_VERSION:-26.5}"
      ;;
    xros)
      printf '%s\n' "${FAKE_XROS_VERSION:-26.5}"
      ;;
    *)
      printf 'unsupported sdk: %s\n' "${2:-}" >&2
      exit 64
      ;;
  esac
  exit 0
fi

if [ "${1:-}" = "simctl" ] && [ "${2:-}" = "list" ] && [ "${3:-}" = "runtimes" ] && [ "${4:-}" = "available" ]; then
  if [ "${5:-}" = "-j" ]; then
    printf '%s\n' "$FAKE_RUNTIMES_JSON"
  else
    printf 'Fake available runtimes\n'
  fi
  exit 0
fi

printf 'unsupported xcrun args: %s\n' "$*" >&2
exit 64
""",
            )

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "XCODE_26_DEVELOPER_DIR": str(developer_dir),
                    "XCODE_PLATFORM_REQUIRED_VERSION": "26.5",
                    "FAKE_DESTINATIONS_FILE": str(destinations_file),
                    "FAKE_DESTINATIONS_STATUS": str(destinations_status),
                    "FAKE_RUNTIMES_JSON": json.dumps(runtimes or AVAILABLE_RUNTIMES),
                    "GITHUB_OUTPUT": str(github_output),
                    "GITHUB_STEP_SUMMARY": str(github_summary),
                    "RUNNER_OS": "macOS",
                    "RUNNER_ARCH": "ARM64",
                    "ImageOS": "macos26",
                    "ImageVersion": "20260517.1",
                }
            )

            process = subprocess.run(
                [
                    "bash",
                    str(REPO_ROOT / "scripts/ci_xcode_platform_preflight.sh"),
                    *(args or ["preflight"]),
                ],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            return PreflightResult(
                process=process,
                outputs=self.read_github_output(github_output),
            )

    @staticmethod
    def write_executable(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    @staticmethod
    def read_github_output(path: Path) -> dict[str, str]:
        if not path.exists():
            return {}

        outputs: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            outputs[name] = value
        return outputs


class PreflightResult:
    def __init__(self, *, process: subprocess.CompletedProcess[str], outputs: dict[str, str]) -> None:
        self.process = process
        self.outputs = outputs

    @property
    def combined_output(self) -> str:
        return f"{self.process.stdout}\n{self.process.stderr}"

