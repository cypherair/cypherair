#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import subprocess
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
    parser.add_argument("--metadata-file", type=Path)
    parser.add_argument("--repository-url", default=DEFAULT_REPOSITORY_URL)
    parser.add_argument("--stable-release-tag", default="")
    parser.add_argument("--stable-release-url", default="")
    parser.add_argument("--require-stable-release", default="NO")
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


def resolve_git_head_commit(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def load_source_compliance_metadata(metadata_file: Path | None) -> dict[str, str]:
    if metadata_file is None or not metadata_file.exists():
        return {}

    payload = json.loads(metadata_file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("source compliance metadata file must contain a JSON object")

    return {
        "commit_sha": str(payload.get("commit_sha", "")).strip(),
        "stable_release_tag": str(payload.get("stable_release_tag", "")).strip(),
        "stable_release_url": str(payload.get("stable_release_url", "")).strip(),
    }


def resolved_metadata_value(explicit_value: str, metadata_value: str) -> str:
    return explicit_value.strip() or metadata_value.strip()


def resolved_commit_sha(
    explicit_commit_sha: str,
    require_stable_release: bool,
    repo_root: Path = ROOT,
    metadata_commit_sha: str = "",
) -> str:
    for candidate_commit_sha in (explicit_commit_sha, metadata_commit_sha):
        normalized_commit_sha = candidate_commit_sha.strip()
        if normalized_commit_sha and normalized_commit_sha.lower() != "unknown":
            return normalized_commit_sha

    if require_stable_release:
        try:
            resolved_commit = resolve_git_head_commit(repo_root)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                "stable-required build must resolve an exact git commit SHA"
            ) from error

        if not resolved_commit:
            raise RuntimeError("stable-required build resolved an empty git commit SHA")
        return resolved_commit

    return "unknown"


def resolved_release_url(repository_url: str, release_tag: str, explicit_release_url: str) -> str:
    if explicit_release_url:
        return explicit_release_url
    if release_tag:
        return f"{repository_url.rstrip('/')}/releases/tag/{release_tag}"
    return ""


def requires_stable_release(raw_value: str) -> bool:
    return raw_value.strip().upper() in {"YES", "TRUE", "1"}


def derived_release_tag(marketing_version: str, build_number: str) -> str:
    return f"cypherair-v{marketing_version}-build{build_number}"


def generate() -> None:
    args = parse_args()
    stable_release_required = requires_stable_release(args.require_stable_release)
    metadata_values = load_source_compliance_metadata(args.metadata_file)

    stable_release_tag = resolved_metadata_value(
        args.stable_release_tag,
        metadata_values.get("stable_release_tag", ""),
    )
    if stable_release_required and not stable_release_tag:
        stable_release_tag = derived_release_tag(
            args.marketing_version.strip(),
            args.build_number.strip(),
        )

    stable_release_url = resolved_release_url(
        args.repository_url.strip(),
        stable_release_tag,
        resolved_metadata_value(
            args.stable_release_url,
            metadata_values.get("stable_release_url", ""),
        ),
    )

    info = {
        "marketingVersion": args.marketing_version.strip(),
        "buildNumber": args.build_number.strip(),
        "commitSHA": resolved_commit_sha(
            args.commit_sha,
            stable_release_required,
            metadata_commit_sha=metadata_values.get("commit_sha", ""),
        ),
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
