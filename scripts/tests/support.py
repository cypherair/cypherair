from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_script_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script module: {module_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if args and args[0] == "git":
        env.update(
            {
                "GIT_AUTHOR_NAME": "Codex Tests",
                "GIT_AUTHOR_EMAIL": "codex-tests@example.com",
                "GIT_COMMITTER_NAME": "Codex Tests",
                "GIT_COMMITTER_EMAIL": "codex-tests@example.com",
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "commit.gpgSign",
                "GIT_CONFIG_VALUE_0": "false",
                "GIT_CONFIG_KEY_1": "tag.gpgSign",
                "GIT_CONFIG_VALUE_1": "false",
            }
        )
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )


def init_repo_with_remote(root: Path) -> tuple[Path, Path]:
    repo_root = root / "repo"
    remote_root = root / "origin.git"

    run(["git", "init", "--bare", str(remote_root)])
    run(["git", "init", "-b", "main", str(repo_root)])
    run(["git", "config", "user.name", "Codex Tests"], cwd=repo_root)
    run(["git", "config", "user.email", "codex-tests@example.com"], cwd=repo_root)
    run(["git", "config", "commit.gpgSign", "false"], cwd=repo_root)
    run(["git", "config", "tag.gpgSign", "false"], cwd=repo_root)

    tracked_file = repo_root / "tracked.txt"
    tracked_file.write_text("base\n", encoding="utf-8")
    run(["git", "add", "tracked.txt"], cwd=repo_root)
    run(["git", "commit", "-m", "Initial commit"], cwd=repo_root)
    run(["git", "remote", "add", "origin", str(remote_root)], cwd=repo_root)
    run(["git", "push", "-u", "origin", "main"], cwd=repo_root)

    return repo_root, remote_root


def create_annotated_stable_tag(
    repo_root: Path,
    marketing_version: str = "1.2.9",
    build_number: str = "3",
) -> str:
    release_tag = f"cypherair-v{marketing_version}-build{build_number}"
    run(["git", "tag", "-a", release_tag, "-m", release_tag], cwd=repo_root)
    run(["git", "push", "origin", release_tag], cwd=repo_root)
    return release_tag


def head_sha(repo_root: Path) -> str:
    return run(["git", "rev-parse", "HEAD"], cwd=repo_root).stdout.strip()
