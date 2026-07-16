#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


EXPECTED_SCHEMA_VERSION = 3
EXPECTED_RELEASE_TAG_PREFIX = "rust-arm64e-stage1-stable197"
EXPECTED_STABLE_BASE_RELEASE = "1.97.0"
EXPECTED_STABLE_BASE_COMMIT = "2d8144b7880597b6e6d3dfd63a9a9efae3f533d3"
EXPECTED_LLVM_SOURCE_KIND = "bundled-gitlink"
EXPECTED_LLVM_GITLINK_COMMIT = "08c84e69a84d95936296dfcab0e38b34100725d5"
EXPECTED_LLVM_VERSION = "22.1.6"
EXPECTED_LLVM_IDENTITY_RELATIVE_PATH = "lib/rustlib/arm64e-stage1-llvm-provenance.json"
EXPECTED_ASSET_PREFIX = "rust-stage1-for-arm64e"
EXPECTED_ASSET_PURPOSE = EXPECTED_ASSET_PREFIX
PROJECT_REQUIRED_ARM64E_TARGETS = (
    "arm64e-apple-darwin",
    "arm64e-apple-ios",
    "arm64e-apple-tvos",
    "arm64e-apple-visionos",
)


class Stage1ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Stage1AssetPin:
    sha256: str
    size: int


@dataclass(frozen=True)
class Stage1ReleasePin:
    tag: str
    repository: str
    source_ref: str
    source_commit: str
    assets: dict[str, Stage1AssetPin]


@dataclass(frozen=True)
class ValidatedManifest:
    host_triple: str
    rustc_version_verbose: str
    packaged_llc_version_verbose: str
    llvm_config_version: str
    identity_relative_path: str


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise Stage1ValidationError(f"{label} must be a JSON object")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise Stage1ValidationError(f"{label} must be a non-empty string")
    return value


def _require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise Stage1ValidationError(f"{label} must be {expected!r}, got {actual!r}")


def load_stage1_release_pin(pin_path: Path) -> Stage1ReleasePin:
    pin = _require_object(_load_json(pin_path, "Rust stage1 pin"), "Rust stage1 pin")
    _require_equal(pin.get("schemaVersion"), 1, "Rust stage1 pin schemaVersion")
    _require_equal(
        pin.get("dependencyName"),
        "rust-arm64e-stage1-toolchain",
        "Rust stage1 pin dependencyName",
    )
    repository = _require_string(pin.get("repository"), "Rust stage1 pin repository")
    release = _require_object(pin.get("release"), "Rust stage1 pin release")
    tag = _require_string(release.get("tag"), "Rust stage1 pin release.tag")
    source_ref = _require_string(release.get("sourceRef"), "Rust stage1 pin release.sourceRef")
    source_commit = _require_string(
        release.get("commitSha"),
        "Rust stage1 pin release.commitSha",
    )
    if not source_ref.startswith("refs/heads/"):
        raise Stage1ValidationError(
            "Rust stage1 pin release.sourceRef must be a canonical refs/heads/* ref"
        )
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise Stage1ValidationError(
            "Rust stage1 pin release.commitSha must be a lowercase 40-character Git commit"
        )

    raw_assets = _require_object(pin.get("assets"), "Rust stage1 pin assets")
    if not raw_assets:
        raise Stage1ValidationError("Rust stage1 pin assets must not be empty")
    assets: dict[str, Stage1AssetPin] = {}
    for asset_name, raw_asset in raw_assets.items():
        if not isinstance(asset_name, str) or not asset_name:
            raise Stage1ValidationError(
                "Rust stage1 pin asset names must be non-empty strings"
            )
        asset = _require_object(
            raw_asset,
            f"Rust stage1 pin assets[{asset_name!r}]",
        )
        sha256 = _require_string(
            asset.get("sha256"),
            f"Rust stage1 pin assets[{asset_name!r}].sha256",
        )
        if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise Stage1ValidationError(
                f"Rust stage1 pin assets[{asset_name!r}].sha256 must be a "
                "lowercase 64-character SHA-256 digest"
            )
        size = asset.get("size")
        if type(size) is not int or size <= 0:
            raise Stage1ValidationError(
                f"Rust stage1 pin assets[{asset_name!r}].size must be a positive integer"
            )
        assets[asset_name] = Stage1AssetPin(sha256=sha256, size=size)

    return Stage1ReleasePin(
        tag=tag,
        repository=repository,
        source_ref=source_ref,
        source_commit=source_commit,
        assets=assets,
    )


def _version_core(value: str, label: str) -> str:
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9].*)?", value.strip())
    if match is None:
        raise Stage1ValidationError(f"{label} does not contain a valid LLVM version: {value!r}")
    return match.group(1)


def _unique_line_match(text: str, pattern: str, label: str) -> str:
    matches = [match.group(1) for line in text.splitlines() if (match := re.fullmatch(pattern, line))]
    if len(matches) != 1:
        raise Stage1ValidationError(f"{label} must contain exactly one LLVM identity line")
    return matches[0]


def rustc_llvm_version(version_verbose: str) -> str:
    value = _unique_line_match(
        version_verbose,
        r"LLVM version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:[^\s]*)?)",
        "rustc -vV output",
    )
    return _version_core(value, "rustc LLVM version")


def llc_llvm_version(version_output: str) -> str:
    value = _unique_line_match(
        version_output,
        r"\s*LLVM version\s+([0-9]+\.[0-9]+\.[0-9]+(?:[^\s]*)?)\s*",
        "llc --version output",
    )
    return _version_core(value, "llc LLVM version")


def rustc_host(version_verbose: str) -> str:
    hosts = [line.removeprefix("host: ") for line in version_verbose.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1 or not hosts[0]:
        raise Stage1ValidationError("rustc -vV output must contain exactly one host triple")
    return hosts[0]


def _require_target_list(payload: dict[str, object], key: str, required_targets: set[str]) -> set[str]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise Stage1ValidationError(f"{key} must be a list of non-empty strings")
    targets = set(value)
    missing = sorted(required_targets - targets)
    if missing:
        raise Stage1ValidationError(f"{key} is missing required targets: {', '.join(missing)}")
    return targets


def validate_stage1_manifest_payload(
    payload: object,
    expected_release: Stage1ReleasePin,
    required_targets: Iterable[str] = PROJECT_REQUIRED_ARM64E_TARGETS,
    expected_host: str | None = None,
) -> ValidatedManifest:
    manifest = _require_object(payload, "Rust stage1 manifest")
    if not expected_release.tag.startswith(f"{EXPECTED_RELEASE_TAG_PREFIX}-"):
        raise Stage1ValidationError(
            f"expected release tag must start with {EXPECTED_RELEASE_TAG_PREFIX}-"
        )
    required = set(required_targets)
    if not required:
        raise Stage1ValidationError("at least one required target must be supplied")

    _require_equal(manifest.get("schemaVersion"), EXPECTED_SCHEMA_VERSION, "schemaVersion")
    _require_equal(manifest.get("releaseTag"), expected_release.tag, "releaseTag")
    _require_equal(
        manifest.get("sourceRepository"),
        expected_release.repository,
        "sourceRepository",
    )
    _require_equal(manifest.get("sourceRef"), expected_release.source_ref, "sourceRef")
    _require_equal(
        manifest.get("sourceCommit"),
        expected_release.source_commit,
        "sourceCommit",
    )
    _require_equal(
        manifest.get("checkedOutCommit"),
        expected_release.source_commit,
        "checkedOutCommit",
    )
    _require_equal(manifest.get("stableBaseRelease"), EXPECTED_STABLE_BASE_RELEASE, "stableBaseRelease")
    _require_equal(manifest.get("stableBaseCommit"), EXPECTED_STABLE_BASE_COMMIT, "stableBaseCommit")
    if manifest.get("requiresBuildStd") is not False:
        raise Stage1ValidationError("requiresBuildStd must be false")

    host = _require_string(manifest.get("hostTriple"), "hostTriple")
    if expected_host is not None:
        _require_equal(host, expected_host, "hostTriple")
    _require_equal(manifest.get("includedHostStdTarget"), host, "includedHostStdTarget")
    prebuilt_targets = _require_target_list(manifest, "includedPrebuiltStdTargets", required)
    _require_target_list(manifest, "includedAppleArm64eTargets", required)
    if host not in prebuilt_targets:
        raise Stage1ValidationError("includedPrebuiltStdTargets must include hostTriple")

    asset_base = f"{EXPECTED_ASSET_PREFIX}-{host}"
    asset_file_name = f"{asset_base}.tar.zst"
    asset_sha256_file_name = f"{asset_base}.sha256"
    asset_manifest_file_name = f"{asset_base}.json"
    for required_asset_name in (
        asset_file_name,
        asset_sha256_file_name,
        asset_manifest_file_name,
    ):
        if required_asset_name not in expected_release.assets:
            raise Stage1ValidationError(
                "Rust stage1 pin assets is missing required host asset: "
                f"{required_asset_name}"
            )

    asset = _require_object(manifest.get("asset"), "asset")
    _require_equal(asset.get("purpose"), EXPECTED_ASSET_PURPOSE, "asset.purpose")
    _require_equal(asset.get("fileName"), asset_file_name, "asset.fileName")
    _require_equal(
        asset.get("sha256FileName"),
        asset_sha256_file_name,
        "asset.sha256FileName",
    )
    _require_equal(
        asset.get("sizeBytes"),
        expected_release.assets[asset_file_name].size,
        "asset.sizeBytes",
    )

    rustc_verbose = _require_string(manifest.get("stage1RustcVersionVerbose"), "stage1RustcVersionVerbose")
    llc_verbose = _require_string(manifest.get("packagedLlcVersionVerbose"), "packagedLlcVersionVerbose")
    _require_equal(rustc_host(rustc_verbose), host, "stage1RustcVersionVerbose host")
    _require_equal(rustc_llvm_version(rustc_verbose), EXPECTED_LLVM_VERSION, "stage1 rustc LLVM version")
    _require_equal(llc_llvm_version(llc_verbose), EXPECTED_LLVM_VERSION, "packaged llc LLVM version")

    llvm = _require_object(manifest.get("llvmProvenance"), "llvmProvenance")
    _require_equal(llvm.get("sourceKind"), EXPECTED_LLVM_SOURCE_KIND, "llvmProvenance.sourceKind")
    if llvm.get("downloadCiLlvm") is not False:
        raise Stage1ValidationError("llvmProvenance.downloadCiLlvm must be false")
    _require_equal(llvm.get("gitlinkCommit"), EXPECTED_LLVM_GITLINK_COMMIT, "llvmProvenance.gitlinkCommit")
    _require_equal(llvm.get("checkedOutCommit"), EXPECTED_LLVM_GITLINK_COMMIT, "llvmProvenance.checkedOutCommit")
    _require_equal(llvm.get("sourceVersion"), EXPECTED_LLVM_VERSION, "llvmProvenance.sourceVersion")
    llvm_config_version = _require_string(llvm.get("llvmConfigVersion"), "llvmProvenance.llvmConfigVersion")
    _require_equal(_version_core(llvm_config_version, "llvmProvenance.llvmConfigVersion"), EXPECTED_LLVM_VERSION, "llvmProvenance llvm-config version")
    _require_equal(llvm.get("rustcReportedVersion"), EXPECTED_LLVM_VERSION, "llvmProvenance.rustcReportedVersion")
    _require_equal(llvm.get("llcReportedVersion"), EXPECTED_LLVM_VERSION, "llvmProvenance.llcReportedVersion")
    _require_equal(
        llvm.get("packagedIdentityFile"),
        EXPECTED_LLVM_IDENTITY_RELATIVE_PATH,
        "llvmProvenance.packagedIdentityFile",
    )

    return ValidatedManifest(
        host_triple=host,
        rustc_version_verbose=rustc_verbose,
        packaged_llc_version_verbose=llc_verbose,
        llvm_config_version=llvm_config_version,
        identity_relative_path=EXPECTED_LLVM_IDENTITY_RELATIVE_PATH,
    )


def validate_packaged_identity_payload(
    payload: object,
    manifest: ValidatedManifest,
) -> None:
    identity = _require_object(payload, "packaged LLVM identity")
    _require_equal(identity.get("schemaVersion"), 1, "packaged LLVM identity schemaVersion")
    _require_equal(identity.get("sourceKind"), EXPECTED_LLVM_SOURCE_KIND, "packaged LLVM identity sourceKind")
    if identity.get("downloadCiLlvm") is not False:
        raise Stage1ValidationError("packaged LLVM identity downloadCiLlvm must be false")
    _require_equal(identity.get("gitlinkCommit"), EXPECTED_LLVM_GITLINK_COMMIT, "packaged LLVM identity gitlinkCommit")
    _require_equal(identity.get("checkedOutCommit"), EXPECTED_LLVM_GITLINK_COMMIT, "packaged LLVM identity checkedOutCommit")
    _require_equal(identity.get("sourceVersion"), EXPECTED_LLVM_VERSION, "packaged LLVM identity sourceVersion")
    _require_equal(identity.get("llvmConfigVersion"), manifest.llvm_config_version, "packaged LLVM identity llvmConfigVersion")
    _require_equal(identity.get("hostTriple"), manifest.host_triple, "packaged LLVM identity hostTriple")

    tools = _require_object(identity.get("tools"), "packaged LLVM identity tools")
    rustc = _require_object(tools.get("rustc"), "packaged LLVM identity tools.rustc")
    llc = _require_object(tools.get("llc"), "packaged LLVM identity tools.llc")
    _require_equal(rustc.get("llvmVersion"), EXPECTED_LLVM_VERSION, "packaged LLVM identity rustc LLVM version")
    _require_equal(rustc.get("versionVerbose"), manifest.rustc_version_verbose, "packaged LLVM identity rustc versionVerbose")
    _require_equal(llc.get("llvmVersion"), EXPECTED_LLVM_VERSION, "packaged LLVM identity llc LLVM version")
    _require_equal(llc.get("versionVerbose"), manifest.packaged_llc_version_verbose, "packaged LLVM identity llc versionVerbose")


def _load_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Stage1ValidationError(f"unable to read {label} {path}: {error}") from error


def _run_tool(args: list[str], label: str) -> str:
    try:
        completed = subprocess.run(args, check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise Stage1ValidationError(f"unable to run {label}: {error}") from error
    return completed.stdout.rstrip("\n")


def _require_executable(path: Path, label: str) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise Stage1ValidationError(f"{label} is missing or not executable: {path}")


def validate_stage1_toolchain(
    manifest_path: Path,
    rustc_path: Path,
    expected_release: Stage1ReleasePin,
    required_targets: Iterable[str],
) -> None:
    _require_executable(rustc_path, "arm64e rustc")
    manifest = validate_stage1_manifest_payload(
        _load_json(manifest_path, "Rust stage1 manifest"),
        expected_release,
        required_targets,
    )

    # Check the checksum-bound identity already present in the extracted
    # sysroot before executing the downloaded compiler or LLVM tools.
    sysroot = rustc_path.resolve().parent.parent
    if not sysroot.is_dir():
        raise Stage1ValidationError(f"rustc sysroot is missing: {sysroot}")
    identity_path = sysroot / EXPECTED_LLVM_IDENTITY_RELATIVE_PATH
    validate_packaged_identity_payload(_load_json(identity_path, "packaged LLVM identity"), manifest)

    llc_path = sysroot / "lib" / "rustlib" / manifest.host_triple / "bin" / "llc"
    _require_executable(llc_path, "packaged llc")

    actual_rustc_verbose = _run_tool([str(rustc_path), "-vV"], "arm64e rustc -vV")
    _require_equal(rustc_host(actual_rustc_verbose), manifest.host_triple, "actual rustc hostTriple")
    _require_equal(actual_rustc_verbose, manifest.rustc_version_verbose, "actual rustc -vV identity")
    _require_equal(rustc_llvm_version(actual_rustc_verbose), EXPECTED_LLVM_VERSION, "actual rustc LLVM version")

    actual_sysroot_text = _run_tool(
        [str(rustc_path), "--print", "sysroot"],
        "arm64e rustc --print sysroot",
    )
    try:
        actual_sysroot = Path(actual_sysroot_text).resolve(strict=True)
    except OSError as error:
        raise Stage1ValidationError(f"unable to resolve rustc sysroot identity: {error}") from error
    _require_equal(actual_sysroot, sysroot, "actual rustc sysroot")

    actual_llc_verbose = _run_tool([str(llc_path), "--version"], "packaged llc --version")
    _require_equal(llc_llvm_version(actual_llc_verbose), EXPECTED_LLVM_VERSION, "actual llc LLVM version")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a downloaded CypherAir Rust arm64e stage1 toolchain.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--pin-file", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--required-target", action="append", required=True, dest="required_targets")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    expected_release = load_stage1_release_pin(args.pin_file)
    _require_equal(args.release_tag, expected_release.tag, "requested release tag")
    validate_stage1_toolchain(
        args.manifest,
        args.rustc,
        expected_release,
        args.required_targets,
    )
    print(f"validated Rust arm64e stage1 toolchain: {args.release_tag}")


if __name__ == "__main__":
    try:
        main()
    except Stage1ValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
