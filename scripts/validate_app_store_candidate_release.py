#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_arm64e_stage1_toolchain import (  # noqa: E402
    Stage1ReleasePin,
    Stage1ValidationError,
    load_stage1_release_pin,
    validate_stage1_manifest_payload,
)


DEFAULT_REPOSITORY = "cypherair/cypherair"
ARM64E_MANIFEST_ASSET_NAME = "PgpMobile.arm64e-build-manifest.json"
ARM64E_STATUS_RELATIVE_PATH = Path("docs/ARM64E_STATUS.md")
ARM64E_STAGE1_PIN_RELATIVE_PATH = Path("third_party/arm64e-stage1-toolchain.pin.json")
SQLCIPHER_PIN_RELATIVE_PATH = Path("third_party/sqlcipher-xcframework.pin.json")
PINNED_RUST_STAGE1_TAG_PATTERN = re.compile(
    r"^- \*\*Pinned prerelease tag:\*\* `([^`\r\n]+)`\s*$",
    flags=re.MULTILINE,
)


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
    parser.add_argument(
        "--require-arm64e-release-manifest",
        default=os.environ.get("SOURCE_COMPLIANCE_REQUIRE_ARM64E_RELEASE_MANIFEST", "YES"),
    )
    parser.add_argument(
        "--require-sqlcipher-release-pin",
        default=os.environ.get("SOURCE_COMPLIANCE_REQUIRE_SQLCIPHER_RELEASE_PIN", "YES"),
    )
    return parser.parse_args()


def requires_stable_release(raw_value: str) -> bool:
    return raw_value.strip().upper() in {"YES", "TRUE", "1"}


def derived_release_tag(marketing_version: str, build_number: str) -> str:
    return f"cypherair-v{marketing_version}-build{build_number}"


def stable_release_url(repository_full_name: str, release_tag: str) -> str:
    return f"https://github.com/{repository_full_name}/releases/tag/{release_tag}"


def canonical_repository_url(repository_full_name: str) -> str:
    return f"https://github.com/{repository_full_name}.git"


def pinned_rust_stage1_release(repo_root: Path) -> Stage1ReleasePin:
    pin_path = repo_root / ARM64E_STAGE1_PIN_RELATIVE_PATH
    try:
        expected_release = load_stage1_release_pin(pin_path)
    except Stage1ValidationError as error:
        raise CandidateValidationError(
            f"Unable to read canonical Rust stage1 machine pin: {pin_path}: {error}"
        ) from error

    status_path = repo_root / ARM64E_STATUS_RELATIVE_PATH
    try:
        status_text = status_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CandidateValidationError(
            f"Unable to read canonical arm64e status document: {status_path}"
        ) from error

    matches = PINNED_RUST_STAGE1_TAG_PATTERN.findall(status_text)
    if len(matches) != 1:
        raise CandidateValidationError(
            "Canonical arm64e status must contain exactly one pinned Rust stage1 "
            f"prerelease tag; found {len(matches)} in {status_path}."
        )
    if matches[0] != expected_release.tag:
        raise CandidateValidationError(
            "Canonical arm64e status and Rust stage1 machine pin disagree.\n"
            f"Status tag: {matches[0]}\n"
            f"Machine pin tag: {expected_release.tag}"
        )
    return expected_release


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


def xcode_cloud_context(env: dict[str, str] | None = None) -> dict[str, str] | None:
    """Return the Xcode Cloud tag/commit identity when running in Xcode Cloud.

    Xcode Cloud checks out a detached HEAD at the triggering tag, so the local
    ``main`` branch identity check does not apply. When ``CI_XCODE_CLOUD`` is
    set, callers verify the build's tag and commit identity from the Xcode Cloud
    environment instead. Returns ``None`` for local/non-Xcode-Cloud runs so the
    existing break-glass branch logic is preserved unchanged.
    """
    resolved_env = os.environ if env is None else env
    if resolved_env.get("CI_XCODE_CLOUD", "").strip().upper() not in {"TRUE", "1", "YES"}:
        return None
    return {
        "tag": resolved_env.get("CI_TAG", "").strip(),
        "commit": resolved_env.get("CI_COMMIT", "").strip(),
    }


def remote_tag_commit_sha(repo_root: Path, release_tag: str, repository_url: str) -> str:
    try:
        completed = run_git(
            repo_root,
            "ls-remote",
            "--tags",
            repository_url,
            f"refs/tags/{release_tag}",
            f"refs/tags/{release_tag}^{{}}",
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip()
        detail_suffix = f" Git reported: {detail}" if detail else ""
        raise CandidateValidationError(
            f"Unable to resolve stable tag {release_tag} from canonical repository {repository_url}.{detail_suffix}"
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
            f"Stable tag {release_tag} was not found on canonical repository {repository_url}."
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


def load_release_asset(repository_full_name: str, release_tag: str, asset_name: str) -> bytes:
    if shutil.which("gh"):
        auth_status = subprocess.run(
            ["gh", "auth", "status"],
            check=False,
            text=True,
            capture_output=True,
        )
        if auth_status.returncode == 0:
            with tempfile.TemporaryDirectory() as temp_dir_name:
                temp_dir = Path(temp_dir_name)
                download = subprocess.run(
                    [
                        "gh",
                        "release",
                        "download",
                        release_tag,
                        "-R",
                        repository_full_name,
                        "--pattern",
                        asset_name,
                        "--dir",
                        str(temp_dir),
                    ],
                    check=False,
                    text=True,
                    capture_output=True,
                )
                if download.returncode == 0:
                    asset_path = temp_dir / asset_name
                    if asset_path.exists():
                        return asset_path.read_bytes()

    api_url = f"https://api.github.com/repos/{repository_full_name}/releases/tags/{release_tag}"
    request = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "CypherAir"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            release_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise CandidateValidationError(
            f"Unable to load GitHub stable release {release_tag}: HTTP {error.code}."
        ) from error
    except urllib.error.URLError as error:
        raise CandidateValidationError(
            f"Unable to load GitHub stable release {release_tag}: {error.reason}."
        ) from error

    for asset in release_payload.get("assets", []):
        if asset.get("name") != asset_name:
            continue
        asset_url = asset.get("browser_download_url")
        if not asset_url:
            break
        asset_request = urllib.request.Request(
            asset_url,
            headers={"Accept": "application/octet-stream", "User-Agent": "CypherAir"},
        )
        try:
            with urllib.request.urlopen(asset_request) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise CandidateValidationError(
                f"Unable to download stable release asset {asset_name}: HTTP {error.code}."
            ) from error
        except urllib.error.URLError as error:
            raise CandidateValidationError(
                f"Unable to download stable release asset {asset_name}: {error.reason}."
            ) from error

    raise CandidateValidationError(
        f"Stable release {release_tag} is missing required asset {asset_name}."
    )


def validate_arm64e_manifest_payload(
    payload: dict[str, object],
    expected_rust_stage1_release: Stage1ReleasePin,
) -> None:
    dependency_chain = payload.get("dependencyChain")
    if not isinstance(dependency_chain, dict):
        raise CandidateValidationError("arm64e manifest is missing dependencyChain.")

    openssl_src = dependency_chain.get("opensslSrc")
    openssl = dependency_chain.get("openssl")
    ctor = dependency_chain.get("ctor")
    if not isinstance(openssl_src, dict) or not openssl_src.get("resolvedCommit"):
        raise CandidateValidationError("arm64e manifest is missing openssl-src resolved commit.")
    if not isinstance(openssl, dict) or not openssl.get("submoduleCommit"):
        raise CandidateValidationError("arm64e manifest is missing OpenSSL submodule commit.")
    if not isinstance(ctor, dict) or not ctor.get("resolvedCommit"):
        raise CandidateValidationError("arm64e manifest is missing ctor resolved commit.")

    rust_stage1 = payload.get("rustStage1")
    try:
        validate_stage1_manifest_payload(
            rust_stage1,
            expected_rust_stage1_release,
        )
    except Stage1ValidationError as error:
        raise CandidateValidationError(
            f"arm64e manifest has invalid Rust stage1 provenance: {error}"
        ) from error

    xcframework = payload.get("xcframework")
    if not isinstance(xcframework, dict) or not xcframework.get("requiredSlicesPresent"):
        raise CandidateValidationError("arm64e manifest does not declare required XCFramework slices.")

    libraries = xcframework.get("libraries")
    if not isinstance(libraries, list):
        raise CandidateValidationError("arm64e manifest is missing XCFramework library entries.")

    expected = {
        ("ios", ""): ["arm64", "arm64e"],
        ("ios", "simulator"): ["arm64"],
        ("macos", ""): ["arm64", "arm64e"],
        ("xros", ""): ["arm64", "arm64e"],
        ("xros", "simulator"): ["arm64"],
    }
    seen = {}
    for library in libraries:
        if not isinstance(library, dict):
            continue
        key = (
            str(library.get("supportedPlatform", "")),
            str(library.get("supportedPlatformVariant", "")),
        )
        seen[key] = sorted(str(arch) for arch in library.get("supportedArchitectures", []))

    for key, expected_archs in expected.items():
        if seen.get(key) != sorted(expected_archs):
            raise CandidateValidationError(
                "arm64e manifest has wrong XCFramework architectures for "
                f"{key[0]}/{key[1] or 'device'}: expected {expected_archs}, got {seen.get(key, [])}"
            )


def validate_stable_release_arm64e_manifest(
    repository_full_name: str,
    release_tag: str,
    expected_rust_stage1_release: Stage1ReleasePin,
) -> None:
    raw_asset = load_release_asset(
        repository_full_name,
        release_tag,
        ARM64E_MANIFEST_ASSET_NAME,
    )
    try:
        payload = json.loads(raw_asset.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateValidationError(
            "arm64e release manifest must contain valid UTF-8 JSON."
        ) from error
    if not isinstance(payload, dict):
        raise CandidateValidationError("arm64e release manifest must contain a JSON object.")
    validate_arm64e_manifest_payload(payload, expected_rust_stage1_release)


def validate_sqlcipher_dependency(repo_root: Path) -> None:
    pin_path = repo_root / SQLCIPHER_PIN_RELATIVE_PATH
    if not pin_path.is_file():
        raise CandidateValidationError(f"SQLCipher pin file is missing: {pin_path}")

    validator = repo_root / "scripts" / "validate_sqlcipher_xcframework.py"
    if not validator.is_file():
        raise CandidateValidationError(f"SQLCipher validator is missing: {validator}")

    completed = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--root",
            str(repo_root),
            "--pin-file",
            str(pin_path),
            "--skip-release-assets",
            "--skip-smoke",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = "\n".join(
            part.strip()
            for part in (completed.stdout, completed.stderr)
            if part.strip()
        )
        raise CandidateValidationError(
            "SQLCipher restored artifact does not match the pinned formal dependency."
            + (f"\n{detail}" if detail else "")
        )


def validate_candidate_release(
    repo_root: Path,
    marketing_version: str,
    build_number: str,
    repository_full_name: str,
    require_stable_release: bool,
    require_arm64e_release_manifest: bool = True,
    require_sqlcipher_release_pin: bool = False,
) -> str:
    if not require_stable_release:
        return derived_release_tag(marketing_version.strip(), build_number.strip())

    if not marketing_version.strip() or not build_number.strip():
        raise CandidateValidationError(
            "MARKETING_VERSION and CURRENT_PROJECT_VERSION are required for App Store candidate archives."
        )

    release_tag = derived_release_tag(marketing_version.strip(), build_number.strip())

    xcode_cloud = xcode_cloud_context()
    if xcode_cloud is not None:
        # Xcode Cloud checks out a detached HEAD at the triggering tag, so the
        # local "main branch" identity check does not apply. Verify tag/commit
        # identity from the Xcode Cloud environment instead; the remote stable
        # tag commit match below still anchors HEAD to the canonical tag.
        if xcode_cloud["tag"] != release_tag:
            raise CandidateValidationError(
                "Xcode Cloud build tag does not match the App Store candidate tag.\n"
                f"CI_TAG: {xcode_cloud['tag'] or 'unknown'}\n"
                f"Candidate tag: {release_tag}"
            )
        ci_head_sha = head_commit_sha(repo_root)
        if xcode_cloud["commit"] and xcode_cloud["commit"] != ci_head_sha:
            raise CandidateValidationError(
                "Xcode Cloud HEAD does not match CI_COMMIT.\n"
                f"CI_COMMIT: {xcode_cloud['commit']}\n"
                f"HEAD: {ci_head_sha}"
            )
    else:
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

    if not stable_release_exists(repository_full_name, release_tag):
        raise CandidateValidationError(
            f"Missing GitHub stable release {release_tag}. Publish the stable release before archiving an App Store candidate."
        )

    if require_arm64e_release_manifest:
        validate_stable_release_arm64e_manifest(
            repository_full_name,
            release_tag,
            pinned_rust_stage1_release(repo_root),
        )

    if require_sqlcipher_release_pin:
        validate_sqlcipher_dependency(repo_root)

    local_head_sha = head_commit_sha(repo_root)
    remote_tag_sha = remote_tag_commit_sha(
        repo_root,
        release_tag,
        canonical_repository_url(repository_full_name),
    )
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
            require_arm64e_release_manifest=requires_stable_release(
                args.require_arm64e_release_manifest
            ),
            require_sqlcipher_release_pin=requires_stable_release(
                args.require_sqlcipher_release_pin
            ),
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
