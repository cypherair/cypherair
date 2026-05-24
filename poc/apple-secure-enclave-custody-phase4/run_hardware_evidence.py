#!/usr/bin/env python3
"""Run Phase 4/4.5 Secure Enclave hardware evidence locally.

This is a POC-only manual runner.  It intentionally keeps stdout sanitized:
no temp paths, fingerprints, Keychain locators, plaintext, shared secrets,
session keys, or KEKs are printed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "com.cypherair.poc.secure-enclave-custody.phase4.request.v1"
BUNDLE_ID = "com.chentianren.cypherair.poc.secureenclavecustody.probe"
PROBE_NAME = "SecureEnclaveCustodyProbe"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
RUST_MANIFEST = SCRIPT_DIR / "rust" / "Cargo.toml"
XCODE_PROJECT = REPO_ROOT / "CypherAir.xcodeproj"


class RunnerError(Exception):
    pass


class EvidenceRunner:
    def __init__(self) -> None:
        self.step = 0
        self.total_steps = 7
        self.reports: dict[str, dict[str, Any]] = {}
        self.failures: list[str] = []
        self.run_dir: Path | None = None
        self.rust_dir: Path | None = None
        self.probe_executable: Path | None = None
        self.cleanup_attempted = False
        self.cleanup_passed = False

    def run(self) -> int:
        print("Phase 4/4.5 Secure Enclave hardware evidence runner")
        print("Output is sanitized; raw command output is captured, not streamed.")

        try:
            self.build_probe()
            self.create_requests()
            self.bootstrap()
            self.rust_mode("secure-enclave-decrypt", "secure-enclave-decrypt")
            self.rust_mode("failure", "rust-failure")
            self.rust_mode("gnupg-interop", "gnupg-interop")
            self.swift_failure()
        except RunnerError as error:
            self.failures.append(str(error))
        finally:
            self.cleanup()
            self.remove_rust_temp()

        self.print_summary()
        if not self.cleanup_passed and self.cleanup_attempted:
            return 2
        if self.failures:
            return 1
        return 0

    def build_probe(self) -> None:
        self.start("build signed probe")
        command = [
            "xcodebuild",
            "build",
            "-project",
            str(XCODE_PROJECT),
            "-scheme",
            PROBE_NAME,
            "-destination",
            "platform=macOS",
        ]
        result = self.command(command)
        if result.returncode != 0:
            self.fail("build signed probe", "xcodebuild failed")
            raise RunnerError("build-probe")
        self.probe_executable = self.resolve_probe_executable()
        self.pass_step("build signed probe", "xcodebuild passed")

    def resolve_probe_executable(self) -> Path:
        settings_result = self.command(
            [
                "xcodebuild",
                "-project",
                str(XCODE_PROJECT),
                "-scheme",
                PROBE_NAME,
                "-destination",
                "platform=macOS",
                "-showBuildSettings",
            ]
        )
        if settings_result.returncode == 0:
            settings = self.parse_build_settings(settings_result.stdout)
            products = settings.get("BUILT_PRODUCTS_DIR")
            executable = settings.get("EXECUTABLE_PATH")
            if products and executable:
                candidate = Path(products) / executable
                if candidate.is_file():
                    return candidate

        derived_data = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
        candidates = list(
            derived_data.glob(
                f"CypherAir-*/Build/Products/Debug/{PROBE_NAME}.app/Contents/MacOS/{PROBE_NAME}"
            )
        )
        candidates = [candidate for candidate in candidates if candidate.is_file()]
        if candidates:
            return max(candidates, key=lambda candidate: candidate.stat().st_mtime)
        raise RunnerError("probe-executable-missing")

    def parse_build_settings(self, stdout: str) -> dict[str, str]:
        settings: dict[str, str] = {}
        for line in stdout.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            settings[key.strip()] = value.strip()
        return settings

    def create_requests(self) -> None:
        container_tmp = (
            Path.home()
            / "Library"
            / "Containers"
            / BUNDLE_ID
            / "Data"
            / "tmp"
        )
        container_tmp.mkdir(parents=True, exist_ok=True)
        self.run_dir = Path(
            tempfile.mkdtemp(prefix="cypherair-se45.", dir=str(container_tmp))
        )
        os.chmod(self.run_dir, 0o700)

        self.rust_dir = Path(tempfile.mkdtemp(prefix="cypherair-se45-rust."))
        os.chmod(self.rust_dir, 0o700)

        self.write_json_0600(
            self.run_dir / "bootstrap-request.json",
            {
                "schema": SCHEMA,
                "runDirectory": str(self.run_dir),
                "statePath": str(self.run_dir / "state.json"),
                "fixturePath": str(self.run_dir / "fixture.json"),
            },
        )
        self.write_json_0600(
            self.rust_dir / "phase4-rust-request.json",
            {
                "schema": SCHEMA,
                "fixturePath": str(self.run_dir / "fixture.json"),
                "signerApp": str(self.probe_executable),
                "bridgeStatePath": str(self.run_dir / "state.json"),
                "workDirectory": str(self.run_dir),
            },
        )

    def bootstrap(self) -> None:
        self.start("bootstrap secure enclave keys")
        report = self.run_probe(
            "bootstrap",
            self.require_run_dir() / "bootstrap-request.json",
        )
        self.reports["bootstrap"] = report
        if report.get("status") != "passed":
            self.fail("bootstrap secure enclave keys", "probe reported failure")
            raise RunnerError("bootstrap")
        key_count = report.get("keyCount", "?")
        se_available = report.get("secureEnclaveAvailable") is True
        self.pass_step(
            "bootstrap secure enclave keys",
            f"keys={key_count}, secureEnclaveAvailable={se_available}",
        )

    def rust_mode(self, mode: str, label: str) -> None:
        self.start(label)
        request = self.require_rust_dir() / "phase4-rust-request.json"
        command = [
            "cargo",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            "--mode",
            mode,
            "--request",
            str(request),
        ]
        result = self.command(command)
        report = self.parse_json_report(result.stdout)
        self.reports[label] = report
        if result.returncode != 0 or report.get("status") != "passed":
            self.fail(label, "probe reported failure")
            self.failures.append(label)
            return
        self.pass_step(label, self.summary_for(label, report))

    def swift_failure(self) -> None:
        self.start("swift failure")
        request = self.require_run_dir() / "swift-failure-request.json"
        self.write_json_0600(
            request,
            {
                "schema": SCHEMA,
                "statePath": str(self.require_run_dir() / "state.json"),
                "workDirectory": str(self.require_run_dir()),
            },
        )
        report = self.run_probe("failure", request)
        self.reports["swift-failure"] = report
        if report.get("status") != "passed":
            self.fail("swift failure", "probe reported failure")
            self.failures.append("swift-failure")
            return
        case_count = report.get("caseCount", "?")
        phase = report.get("phase", "?")
        self.pass_step("swift failure", f"cases={case_count}, phase={phase}")

    def cleanup(self) -> None:
        if self.run_dir is None or not (self.run_dir / "state.json").exists():
            self.start("cleanup")
            self.pass_step("cleanup", "skipped; no state file")
            return

        self.cleanup_attempted = True
        self.start("cleanup")
        cleanup_request = self.run_dir / "cleanup-request.json"
        additional_paths = [
            str(path)
            for path in self.run_dir.iterdir()
            if path.name != "state.json"
        ]
        if str(cleanup_request) not in additional_paths:
            additional_paths.append(str(cleanup_request))
        self.write_json_0600(
            cleanup_request,
            {
                "schema": SCHEMA,
                "statePath": str(self.run_dir / "state.json"),
                "additionalPaths": additional_paths,
                "removeRunDirectory": True,
            },
        )
        report = self.run_probe("cleanup", cleanup_request, allow_failure=True)
        self.reports["cleanup"] = report
        if report.get("status") == "passed":
            self.cleanup_passed = True
            deleted_rows = report.get("deletedKeychainRows", "?")
            deleted_files = report.get("deletedCapabilityFiles", "?")
            run_dir_removed = not self.run_dir.exists()
            self.pass_step(
                "cleanup",
                f"keyRows={deleted_rows}, files={deleted_files}, runDirRemoved={run_dir_removed}",
            )
        else:
            self.fail("cleanup", "probe reported failure")
            self.failures.append("cleanup")

    def remove_rust_temp(self) -> None:
        if self.rust_dir is not None:
            shutil.rmtree(self.rust_dir, ignore_errors=True)

    def run_probe(
        self, mode: str, request: Path, allow_failure: bool = False
    ) -> dict[str, Any]:
        command = [
            str(self.require_probe_executable()),
            "--mode",
            mode,
            "--request",
            str(request),
        ]
        result = self.command(command)
        report = self.parse_json_report(result.stdout)
        if result.returncode != 0 and not allow_failure:
            raise RunnerError(mode)
        return report

    def command(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def parse_json_report(self, stdout: str) -> dict[str, Any]:
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start < 0 or end < start:
            return {"status": "failed", "materialsPrinted": False}
        try:
            value = json.loads(stdout[start : end + 1])
        except json.JSONDecodeError:
            return {"status": "failed", "materialsPrinted": False}
        if isinstance(value, dict):
            return value
        return {"status": "failed", "materialsPrinted": False}

    def write_json_0600(self, path: Path, value: dict[str, Any]) -> None:
        data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(path, 0o600)

    def summary_for(self, label: str, report: dict[str, Any]) -> str:
        if label == "secure-enclave-decrypt":
            candidates = report.get("candidateCount", "?")
            lengths = report.get("rawSharedSecretLengths", [])
            return f"candidates={candidates}, sharedSecretLengths={self.short_list(lengths)}"
        if label == "rust-failure":
            return f"cases={report.get('caseCount', '?')}"
        if label == "gnupg-interop":
            gpg = report.get("gpgVersion", "gpg version unavailable")
            packet_ok = self.packet_shape_passed(report)
            lengths = report.get("rawSharedSecretLengths", [])
            import_report = report.get("publicCertImport")
            if isinstance(import_report, dict):
                processed = import_report.get("processedCount", "?")
                imported = import_report.get("importedCount", "?")
            else:
                processed = "?"
                imported = "?"
            return (
                f"{gpg}, importProcessed={processed}, importImported={imported}, "
                f"packetShapeOk={packet_ok}, "
                f"sharedSecretLengths={self.short_list(lengths)}"
            )
        return "passed"

    def packet_shape_passed(self, report: dict[str, Any]) -> bool:
        shape_paths = [
            ("gpgEncryptSeDecrypt", "packetShape"),
            ("seSignEncryptGpgDecryptVerify", "packetShape"),
            ("gpgSignEncryptSeDecryptVerify", "packetShape"),
        ]
        for section_name, shape_name in shape_paths:
            section = report.get(section_name)
            if not isinstance(section, dict):
                return False
            shape = section.get(shape_name)
            if not isinstance(shape, dict):
                return False
            if shape.get("pkeskVersion3Ecdh") is not True:
                return False
            if shape.get("seipdv1Mdc") is not True:
                return False
            if shape.get("unexpectedAeadTag20") is not False:
                return False
        return True

    def short_list(self, value: Any) -> str:
        if not isinstance(value, list):
            return "[]"
        return "[" + ",".join(str(item) for item in value) + "]"

    def print_summary(self) -> None:
        print("Summary:")
        for name in [
            "bootstrap",
            "secure-enclave-decrypt",
            "rust-failure",
            "gnupg-interop",
            "swift-failure",
            "cleanup",
        ]:
            report = self.reports.get(name)
            if not report:
                continue
            status = report.get("status", "unknown")
            print(f"  {name}: {status}")
        if self.cleanup_attempted and not self.cleanup_passed:
            print("  cleanup-risk: cleanup failed; manual review is required")
        if self.failures:
            print("Result: failed")
        else:
            print("Result: passed")

    def start(self, label: str) -> None:
        self.step += 1
        print(f"[{self.step}/{self.total_steps}] {label}: running", flush=True)

    def pass_step(self, label: str, detail: str) -> None:
        print(f"[{self.step}/{self.total_steps}] {label}: passed ({detail})", flush=True)

    def fail(self, label: str, detail: str) -> None:
        print(f"[{self.step}/{self.total_steps}] {label}: failed ({detail})", flush=True)

    def require_run_dir(self) -> Path:
        if self.run_dir is None:
            raise RunnerError("missing-run-dir")
        return self.run_dir

    def require_rust_dir(self) -> Path:
        if self.rust_dir is None:
            raise RunnerError("missing-rust-dir")
        return self.rust_dir

    def require_probe_executable(self) -> Path:
        if self.probe_executable is None:
            raise RunnerError("missing-probe-executable")
        return self.probe_executable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the local Phase 4/4.5 Secure Enclave + GnuPG hardware "
            "evidence flow. Requires real macOS Secure Enclave availability."
        )
    )
    return parser.parse_args()


def main() -> int:
    parse_args()
    return EvidenceRunner().run()


if __name__ == "__main__":
    sys.exit(main())
