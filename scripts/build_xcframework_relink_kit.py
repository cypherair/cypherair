#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-apple-darwin",
    "aarch64-apple-visionos",
    "aarch64-apple-visionos-sim",
)
DEP_PATTERNS = (
    "libpgp_mobile-*.a",
    "libpgp_mobile-*.rlib",
    "libsequoia_openpgp-*.rlib",
    "libbuffered_reader-*.rlib",
    "libopenssl-*.rlib",
    "libopenssl_sys-*.rlib",
)
OPENSSL_PATTERNS = (
    "libcrypto*.a",
    "libssl*.a",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the stable XCFramework relink kit."
    )
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--marketing-version", required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--xcframework-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def sha256_for_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_matches(patterns: tuple[str, ...], source_dir: Path, destination_dir: Path) -> list[str]:
    copied: list[str] = []
    for pattern in patterns:
        for match in sorted(source_dir.glob(pattern)):
            if match.is_file():
                shutil.copy2(match, destination_dir / match.name)
                copied.append(match.name)
    return copied


def create_archive(source_dir: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tar_process = subprocess.Popen(
        ["bsdtar", "-cf", "-", "-C", str(source_dir.parent), source_dir.name],
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
        raise RuntimeError("failed to create relink kit archive")


def main() -> None:
    args = parse_args()
    xcframework_sha = sha256_for_path(args.xcframework_zip.resolve())

    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        root_dir = temp_dir / "PgpMobile-relink-kit"
        root_dir.mkdir(parents=True, exist_ok=True)

        manifest: dict[str, object] = {
            "releaseTag": args.release_tag,
            "marketingVersion": args.marketing_version,
            "buildNumber": args.build_number,
            "commitSHA": args.commit_sha,
            "xcframeworkZip": {
                "fileName": args.xcframework_zip.name,
                "sha256": xcframework_sha,
            },
            "targets": {},
        }

        readme_lines = [
            "# PgpMobile Relink Kit",
            "",
            f"- Release tag: `{args.release_tag}`",
            f"- Commit: `{args.commit_sha}`",
            f"- XCFramework zip: `{args.xcframework_zip.name}`",
            f"- XCFramework zip SHA256: `{xcframework_sha}`",
            "",
            "This kit contains target-scoped build intermediates and notes for relink-focused",
            "review of the stable XCFramework channel. Rebuild the tagged source bundle and",
            "use `./build-xcframework.sh --release` as the canonical path to regenerate the",
            "final XCFramework after modifying bundled dependencies.",
        ]

        for target in TARGETS:
            release_dir = ROOT / "pgp-mobile" / "target" / target / "release"
            if not release_dir.exists():
                raise RuntimeError(f"missing release directory for target {target}: {release_dir}")

            target_dir = root_dir / target
            target_dir.mkdir(parents=True, exist_ok=True)

            staticlib_path = release_dir / "libpgp_mobile.a"
            if staticlib_path.exists():
                shutil.copy2(staticlib_path, target_dir / staticlib_path.name)

            deps_dir = release_dir / "deps"
            dep_files = copy_matches(DEP_PATTERNS, deps_dir, target_dir)

            openssl_files: list[str] = []
            build_dir = release_dir / "build"
            if build_dir.exists():
                for pattern in OPENSSL_PATTERNS:
                    for match in sorted(build_dir.rglob(pattern)):
                        if match.is_file():
                            destination = target_dir / match.name
                            shutil.copy2(match, destination)
                            openssl_files.append(match.name)

            target_manifest = {
                "staticlib": staticlib_path.name if staticlib_path.exists() else "",
                "deps": dep_files,
                "opensslInputs": sorted(set(openssl_files)),
                "rebuildCommand": f"cargo build --release --target {target} --manifest-path pgp-mobile/Cargo.toml",
                "xcframeworkCommand": "./build-xcframework.sh --release",
            }
            cast_targets = manifest["targets"]
            assert isinstance(cast_targets, dict)
            cast_targets[target] = target_manifest

            readme_lines.extend(
                [
                    "",
                    f"## {target}",
                    "",
                    f"- Rebuild: `{target_manifest['rebuildCommand']}`",
                    "- After rebuilding modified dependency inputs, regenerate the final packaged artifact with:",
                    f"  `{target_manifest['xcframeworkCommand']}`",
                ]
            )

        (root_dir / "README.md").write_text("\n".join(readme_lines) + "\n", encoding="utf-8")
        (root_dir / "relink-kit-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        create_archive(root_dir, args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # pragma: no cover - helper script
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
