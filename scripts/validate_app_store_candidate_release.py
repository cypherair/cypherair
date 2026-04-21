#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


DEFAULT_REPOSITORY = "cypherair/cypherair"


class CandidateValidationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate that an App Store candidate archive matches the published stable release."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--marketing-version", required=True)
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--github-repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--output-metadata-file", type=Path)
    parser.add_argument(
        "--require-stable-release",
        default=os.environ.get("SOURCE_COMPLIANCE_REQUIRE_STABLE_RELEASE", "NO"),
    )
    return parser.parse_args()


def requires_stable_release(raw_value: str) -> bool:
    return raw_value.strip().upper() in {"YES", "TRUE", "1"}


def derived_release_tag(marketing_version: str, build_number: str) -> str:
    return f"cypherair-v{marketing_version}-build{build_number}"


def stable_release_url(repository_full_name: str, release_tag: str) -> str:
    return f"https://github.com/{repository_full_name}/releases/tag/{release_tag}"


def write_candidate_release_metadata(
    output_path: Path,
    *,
    commit_sha: str,
    repository_full_name: str,
    release_tag: str,
) -> None:
    payload = {
        "commit_sha": commit_sha,
        "stable_release_tag": release_tag,
        "stable_release_url": stable_release_url(repository_full_name, release_tag),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_git(repo_root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=check,
        text=True,
        capture_output=True,
    )


def current_branch(repo_root: Path) -> str:
    return run_git(repo_root, "branch", "--show-current").stdout.strip()


def tracked_status_lines(repo_root: Path) -> list[str]:
    status_text = run_git(
        repo_root,
        "status",
        "--short",
        "--untracked-files=no",
    ).stdout
    return [line for line in status_text.splitlines() if line]


def head_commit_sha(repo_root: Path) -> str:
    return run_git(repo_root, "rev-parse", "HEAD").stdout.strip()


def remote_tag_commit_sha(repo_root: Path, release_tag: str, remote_name: str = "origin") -> str:
    try:
        completed = run_git(
            repo_root,
            "ls-remote",
            "--tags",
            remote_name,
            f"refs/tags/{release_tag}",
            f"refs/tags/{release_tag}^{{}}",
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip()
        detail_suffix = f" Git reported: {detail}" if detail else ""
        raise CandidateValidationError(
            f"Unable to resolve stable tag {release_tag} from remote {remote_name}.{detail_suffix}"
        ) from error

    direct_sha = ""
    peeled_sha = ""
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        sha, ref = parts
        if ref == f"refs/tags/{release_tag}":
            direct_sha = sha
        elif ref == f"refs/tags/{release_tag}^{{}}":
            peeled_sha = sha

    resolved_sha = peeled_sha or direct_sha
    if not resolved_sha:
        raise CandidateValidationError(
            f"Stable tag {release_tag} was not found on remote {remote_name}."
        )
    return resolved_sha


def stable_release_exists(repository_full_name: str, release_tag: str) -> bool:
    if shutil.which("gh"):
        auth_status = subprocess.run(
            ["gh", "auth", "status"],
            check=False,
            text=True,
            capture_output=True,
        )
        if auth_status.returncode == 0:
            release_view = subprocess.run(
                ["gh", "release", "view", release_tag, "-R", repository_full_name],
                check=False,
                text=True,
                capture_output=True,
            )
            return release_view.returncode == 0

    api_url = f"https://api.github.com/repos/{repository_full_name}/releases/tags/{release_tag}"
    request = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "CypherAir"},
    )

    try:
        with urllib.request.urlopen(request) as response:
            return response.status == 200
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise CandidateValidationError(
            f"Unable to verify GitHub stable release {release_tag}: HTTP {error.code}."
        ) from error
    except urllib.error.URLError as error:
        raise CandidateValidationError(
            f"Unable to verify GitHub stable release {release_tag}: {error.reason}."
        ) from error


def validate_candidate_release(
    repo_root: Path,
    marketing_version: str,
    build_number: str,
    repository_full_name: str,
    require_stable_release: bool,
) -> str:
    if not require_stable_release:
        return derived_release_tag(marketing_version.strip(), build_number.strip())

    if not marketing_version.strip() or not build_number.strip():
        raise CandidateValidationError(
            "MARKETING_VERSION and CURRENT_PROJECT_VERSION are required for App Store candidate archives."
        )

    branch = current_branch(repo_root)
    if branch != "main":
        raise CandidateValidationError(
            f"App Store candidate archives are only allowed from the main branch. Current branch: {branch or 'unknown'}."
        )

    dirty_lines = tracked_status_lines(repo_root)
    if dirty_lines:
        details = "\n".join(dirty_lines)
        raise CandidateValidationError(
            "App Store candidate archives require a clean tracked worktree and index.\n"
            f"Tracked changes:\n{details}"
        )

    release_tag = derived_release_tag(marketing_version.strip(), build_number.strip())
    if not stable_release_exists(repository_full_name, release_tag):
        raise CandidateValidationError(
            f"Missing GitHub stable release {release_tag}. Publish the stable release before archiving an App Store candidate."
        )

    local_head_sha = head_commit_sha(repo_root)
    remote_tag_sha = remote_tag_commit_sha(repo_root, release_tag)
    if local_head_sha != remote_tag_sha:
        raise CandidateValidationError(
            "App Store candidate archives must match the remote stable tag commit.\n"
            f"Expected stable tag {release_tag} commit: {remote_tag_sha}\n"
            f"Current HEAD commit: {local_head_sha}"
        )

    return release_tag


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    stable_release_required = requires_stable_release(args.require_stable_release)
    try:
        release_tag = validate_candidate_release(
            repo_root=repo_root,
            marketing_version=args.marketing_version,
            build_number=args.build_number,
            repository_full_name=args.github_repository,
            require_stable_release=stable_release_required,
        )
        if stable_release_required and args.output_metadata_file is not None:
            write_candidate_release_metadata(
                args.output_metadata_file,
                commit_sha=head_commit_sha(repo_root),
                repository_full_name=args.github_repository,
                release_tag=release_tag,
            )
    except CandidateValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
