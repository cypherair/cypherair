#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OPENSSL_SRC_BRANCH = "carry/apple-arm64e-openssl-fork"
DEFAULT_OPENSSL_BRANCH = "carry/apple-arm64e-targets"
DEFAULT_OPENSSL_SRC_REPO = "https://github.com/cypherair/openssl-src-rs"
DEFAULT_OPENSSL_REPO = "https://github.com/cypherair/openssl"


class MetadataError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect and validate CypherAir arm64e release metadata."
    )
    parser.add_argument("--cargo-lock", type=Path, required=True)
    parser.add_argument("--xcframework", type=Path)
    parser.add_argument("--rust-stage1-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--freshness-level",
        choices=("off", "warn", "error"),
        default="warn",
        help="How to report branch freshness drift for the OpenSSL carry chain.",
    )
    return parser.parse_args()


def run_git(*args: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", "-c", "http.version=HTTP/1.1", *args],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def parse_openssl_src_lock(cargo_lock_path: Path) -> dict[str, str]:
    text = cargo_lock_path.read_text(encoding="utf-8")
    match = re.search(
        r'\[\[package\]\]\s+name = "openssl-src"\s+version = "([^"]+)"\s+source = "([^"]+)"',
        text,
        flags=re.MULTILINE,
    )
    if match is None:
        raise MetadataError("openssl-src package source was not found in Cargo.lock")

    version = match.group(1)
    source = match.group(2)
    source_match = re.match(r"git\+([^?#]+)(?:\?([^#]+))?#([0-9a-fA-F]+)$", source)
    if source_match is None:
        raise MetadataError(f"openssl-src source is not a git source with a resolved commit: {source}")

    repository = source_match.group(1)
    query = urllib.parse.parse_qs(source_match.group(2) or "")
    branch = query.get("branch", [DEFAULT_OPENSSL_SRC_BRANCH])[0]
    branch = branch.replace("%2F", "/")
    return {
        "version": version,
        "source": source,
        "repository": repository,
        "branch": branch,
        "resolvedCommit": source_match.group(3),
    }


def remote_branch_head(repository: str, branch: str) -> str:
    last_error: subprocess.CalledProcessError | None = None
    output = ""
    for attempt in range(3):
        try:
            output = run_git("ls-remote", repository, f"refs/heads/{branch}")
            break
        except subprocess.CalledProcessError as error:
            last_error = error
            if attempt < 2:
                time.sleep((attempt + 1) * 5)
    if not output and last_error is not None:
        raise last_error
    if not output:
        raise MetadataError(f"remote branch was not found: {repository} {branch}")
    return output.split()[0]


def openssl_submodule_pointer(openssl_src_repository: str, openssl_src_commit: str) -> str:
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        run_git("init", cwd=temp_dir)
        run_git("remote", "add", "origin", openssl_src_repository, cwd=temp_dir)
        run_git("fetch", "--depth=1", "origin", openssl_src_commit, cwd=temp_dir)
        tree_line = run_git("ls-tree", "FETCH_HEAD", "openssl", cwd=temp_dir)

    parts = tree_line.split()
    if len(parts) < 3 or parts[0] != "160000" or parts[1] != "commit":
        raise MetadataError("openssl-src resolved commit does not contain an openssl submodule")
    return parts[2]


def collect_dependency_chain(cargo_lock_path: Path, freshness_level: str) -> dict[str, object]:
    openssl_src = parse_openssl_src_lock(cargo_lock_path)
    openssl_src["remoteBranchHead"] = remote_branch_head(
        openssl_src["repository"],
        openssl_src["branch"],
    )
    openssl_src["isFresh"] = (
        openssl_src["resolvedCommit"] == openssl_src["remoteBranchHead"]
    )

    openssl_submodule_commit = openssl_submodule_pointer(
        openssl_src["repository"],
        openssl_src["resolvedCommit"],
    )
    openssl_remote_head = remote_branch_head(DEFAULT_OPENSSL_REPO, DEFAULT_OPENSSL_BRANCH)
    openssl = {
        "repository": DEFAULT_OPENSSL_REPO,
        "branch": DEFAULT_OPENSSL_BRANCH,
        "submoduleCommit": openssl_submodule_commit,
        "remoteBranchHead": openssl_remote_head,
        "isFresh": openssl_submodule_commit == openssl_remote_head,
    }

    stale_messages = []
    if not openssl_src["isFresh"]:
        stale_messages.append(
            "openssl-src-rs Cargo.lock commit "
            f"{openssl_src['resolvedCommit']} is not the current "
            f"{openssl_src['branch']} head {openssl_src['remoteBranchHead']}"
        )
    if not openssl["isFresh"]:
        stale_messages.append(
            "openssl-src-rs submodule commit "
            f"{openssl_submodule_commit} is not the current "
            f"{DEFAULT_OPENSSL_BRANCH} head {openssl_remote_head}"
        )

    if stale_messages and freshness_level != "off":
        prefix = "error" if freshness_level == "error" else "warning"
        for message in stale_messages:
            print(f"::{prefix}::{message}", file=sys.stderr)
        if freshness_level == "error":
            raise MetadataError("; ".join(stale_messages))

    return {
        "opensslSrc": openssl_src,
        "openssl": openssl,
        "freshness": {
            "level": freshness_level,
            "isFresh": not stale_messages,
            "messages": stale_messages,
        },
    }


def lipo_architectures(library_path: Path) -> list[str]:
    completed = subprocess.run(
        ["lipo", "-info", str(library_path)],
        check=True,
        text=True,
        capture_output=True,
    )
    output = completed.stdout.strip()
    fat_match = re.search(r"are:\s+(.+)$", output)
    if fat_match is not None:
        return fat_match.group(1).split()
    thin_match = re.search(r"is architecture:\s+(.+)$", output)
    if thin_match is not None:
        return [thin_match.group(1).strip()]
    raise MetadataError(f"unable to parse lipo output for {library_path}: {output}")


def collect_xcframework_metadata(xcframework_path: Path | None) -> dict[str, object]:
    if xcframework_path is None:
        return {}

    info_path = xcframework_path / "Info.plist"
    if not info_path.exists():
        raise MetadataError(f"XCFramework Info.plist is missing: {info_path}")

    info = plistlib.loads(info_path.read_bytes())
    libraries = []
    for library in info.get("AvailableLibraries", []):
        identifier = library["LibraryIdentifier"]
        library_path = xcframework_path / identifier / library["LibraryPath"]
        libraries.append(
            {
                "libraryIdentifier": identifier,
                "supportedPlatform": library.get("SupportedPlatform", ""),
                "supportedPlatformVariant": library.get("SupportedPlatformVariant", ""),
                "supportedArchitectures": library.get("SupportedArchitectures", []),
                "lipoArchitectures": lipo_architectures(library_path),
            }
        )

    required = {
        ("ios", ""): ["arm64", "arm64e"],
        ("ios", "simulator"): ["arm64"],
        ("macos", ""): ["arm64", "arm64e"],
        ("xros", ""): ["arm64", "arm64e"],
        ("xros", "simulator"): ["arm64"],
    }
    seen = {
        (library["supportedPlatform"], library["supportedPlatformVariant"]): sorted(
            library["supportedArchitectures"]
        )
        for library in libraries
    }
    missing_or_wrong = []
    for key, expected_archs in required.items():
        actual_archs = seen.get(key)
        if actual_archs != sorted(expected_archs):
            missing_or_wrong.append(
                {
                    "platform": key[0],
                    "variant": key[1],
                    "expectedArchitectures": expected_archs,
                    "actualArchitectures": actual_archs or [],
                }
            )

    if missing_or_wrong:
        raise MetadataError(f"XCFramework arm64e slice validation failed: {missing_or_wrong}")

    return {
        "path": str(xcframework_path),
        "libraries": libraries,
        "requiredSlicesPresent": True,
    }


def load_rust_stage1_manifest(path: Path | None) -> dict[str, object]:
    if path is not None and path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise MetadataError("Rust stage1 manifest must contain a JSON object")
        return payload

    rustc = os.environ.get("ARM64E_RUSTC", "").strip()
    release_tag = os.environ.get("ARM64E_RUST_STAGE1_RELEASE_TAG", "").strip()
    return {
        "source": "local" if rustc else "unknown",
        "releaseTag": release_tag,
        "rustc": rustc,
    }


def main() -> None:
    args = parse_args()
    dependency_chain = collect_dependency_chain(args.cargo_lock, args.freshness_level)
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "generatedBy": "scripts/arm64e_release_metadata.py",
        "dependencyChain": dependency_chain,
        "rustStage1": load_rust_stage1_manifest(args.rust_stage1_manifest),
        "xcframework": collect_xcframework_metadata(args.xcframework),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
