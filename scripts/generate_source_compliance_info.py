#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPOSITORY_URL = "https://github.com/cypherair/cypherair"
KEY_DEPENDENCIES = (
    "sequoia-openpgp",
    "buffered-reader",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate SourceComplianceInfo.json for CypherAir app builds."
    )
    parser.add_argument("--cargo-lock", type=Path, required=True)
    parser.add_argument("--marketing-version", required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--repository-url", default=DEFAULT_REPOSITORY_URL)
    parser.add_argument("--stable-release-tag", default="")
    parser.add_argument("--stable-release-url", default="")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_dependency_versions(cargo_lock_path: Path) -> list[dict[str, str]]:
    text = cargo_lock_path.read_text(encoding="utf-8")
    package_map: dict[str, str] = {}
    package_pattern = re.compile(
        r'\[\[package\]\]\s+name = "([^"]+)"\s+version = "([^"]+)"',
        re.MULTILINE,
    )
    for name, version in package_pattern.findall(text):
        package_map[name] = version

    missing = [name for name in KEY_DEPENDENCIES if name not in package_map]
    if missing:
        raise RuntimeError(f"missing key dependencies in Cargo.lock: {', '.join(missing)}")

    return [{"name": name, "version": package_map[name]} for name in KEY_DEPENDENCIES]


def resolved_commit_sha(explicit_commit_sha: str) -> str:
    if explicit_commit_sha:
        return explicit_commit_sha
    return "unknown"


def resolved_release_url(repository_url: str, release_tag: str, explicit_release_url: str) -> str:
    if explicit_release_url:
        return explicit_release_url
    if release_tag:
        return f"{repository_url.rstrip('/')}/releases/tag/{release_tag}"
    return ""


def generate() -> None:
    args = parse_args()

    stable_release_tag = args.stable_release_tag.strip()
    stable_release_url = resolved_release_url(
        args.repository_url.strip(),
        stable_release_tag,
        args.stable_release_url.strip(),
    )

    info = {
        "marketingVersion": args.marketing_version.strip(),
        "buildNumber": args.build_number.strip(),
        "commitSHA": resolved_commit_sha(args.commit_sha.strip()),
        "stableReleaseTag": stable_release_tag,
        "stableReleaseURL": stable_release_url,
        "dependencies": load_dependency_versions(args.cargo_lock),
        "firstPartyLicense": "GPL-3.0-or-later OR MPL-2.0",
        "fulfillmentBasis": "LGPL 2.1",
        "isStableReleaseBuild": bool(stable_release_url),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        generate()
    except Exception as error:  # pragma: no cover - helper script
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
