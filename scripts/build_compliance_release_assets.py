#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build stable compliance release assets for CypherAir."
    )
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--marketing-version", required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--source-bundle-output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--binary-asset", type=Path, action="append", default=[])
    return parser.parse_args()


def run(*args: str, cwd: Path | None = None, capture_output: bool = False) -> str:
    completed = subprocess.run(
        list(args),
        cwd=cwd or ROOT,
        check=True,
        text=True,
        capture_output=capture_output,
    )
    return completed.stdout if capture_output else ""


def sha256_for_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dependency_versions() -> dict[str, str]:
    text = (ROOT / "pgp-mobile" / "Cargo.lock").read_text(encoding="utf-8")
    packages = dict(
        re.findall(
            r'\[\[package\]\]\s+name = "([^"]+)"\s+version = "([^"]+)"',
            text,
            re.MULTILINE,
        )
    )
    return {
        "sequoia-openpgp": packages["sequoia-openpgp"],
        "buffered-reader": packages["buffered-reader"],
    }


def build_source_bundle(output_path: Path, commit_sha: str, release_tag: str) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        checkout_root = temp_dir / "CypherAir-source-bundle"
        checkout_root.mkdir(parents=True)

        archive_bytes = subprocess.check_output(
            ["git", "-C", str(ROOT), "archive", "--format=tar", commit_sha]
        )
        archive_path = temp_dir / "source.tar"
        archive_path.write_bytes(archive_bytes)
        run("bsdtar", "-xf", str(archive_path), "-C", str(checkout_root))

        vendor_dir = checkout_root / "vendor"
        vendor_dir.mkdir(parents=True, exist_ok=True)
        config_snippet = run(
            "cargo",
            "vendor",
            "--locked",
            "--versioned-dirs",
            vendor_dir.name,
            "--manifest-path",
            str(checkout_root / "pgp-mobile" / "Cargo.toml"),
            cwd=checkout_root,
            capture_output=True,
        )

        cargo_config_dir = checkout_root / ".cargo"
        cargo_config_dir.mkdir(parents=True, exist_ok=True)
        (cargo_config_dir / "config.toml").write_text(config_snippet, encoding="utf-8")

        readme_text = "\n".join(
            [
                "# CypherAir Compliance Source Bundle",
                "",
                f"- Release tag: `{release_tag}`",
                f"- Commit: `{commit_sha}`",
                "",
                "This bundle contains the exact first-party source snapshot, vendored Rust sources,",
                "and Cargo source configuration used to reproduce the tagged build.",
                "",
                "Typical rebuild path:",
                "",
                "```bash",
                "cargo test --manifest-path pgp-mobile/Cargo.toml",
                "./build-xcframework.sh --release",
                "```",
            ]
        )
        (checkout_root / "COMPLIANCE_BUNDLE_README.md").write_text(readme_text, encoding="utf-8")

        tar_process = subprocess.Popen(
            [
                "bsdtar",
                "-cf",
                "-",
                "-C",
                str(temp_dir),
                checkout_root.name,
            ],
            stdout=subprocess.PIPE,
        )
        zstd_process = subprocess.Popen(
            ["zstd", "-T0", "-19", "-o", str(output_path)],
            stdin=tar_process.stdout,
        )
        assert tar_process.stdout is not None
        tar_process.stdout.close()
        tar_return = tar_process.wait()
        zstd_return = zstd_process.wait()
        if tar_return != 0 or zstd_return != 0:
            raise RuntimeError("failed to create source bundle archive")

    return sha256_for_path(output_path)


def binary_asset_entries(paths: list[Path]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for path in paths:
        resolved_path = path.resolve()
        entries.append(
            {
                "fileName": resolved_path.name,
                "sha256": sha256_for_path(resolved_path),
            }
        )
    return entries


def main() -> None:
    global args
    args = parse_args()

    source_bundle_sha = build_source_bundle(
        args.source_bundle_output,
        args.commit_sha,
        args.release_tag,
    )
    binary_entries = binary_asset_entries(args.binary_asset)
    dependencies = dependency_versions()

    manifest = {
        "productKind": "unifiedBuild",
        "channel": args.channel,
        "releaseTag": args.release_tag,
        "marketingVersion": args.marketing_version,
        "buildNumber": args.build_number,
        "commitSHA": args.commit_sha,
        "sourceBundle": {
            "fileName": args.source_bundle_output.name,
            "sha256": source_bundle_sha,
        },
        "binaryAssets": binary_entries,
        "sequoiaOpenPGPVersion": dependencies["sequoia-openpgp"],
        "bufferedReaderVersion": dependencies["buffered-reader"],
        "fulfillmentBasis": "LGPL 2.1",
        "firstPartyLicense": "GPL-3.0-or-later OR MPL-2.0",
    }

    args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # pragma: no cover - helper script
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
