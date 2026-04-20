from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_script_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script module: {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )


def init_repo_with_remote(root: Path) -> tuple[Path, Path]:
    repo_root = root / "repo"
    remote_root = root / "origin.git"

    run(["git", "init", "--bare", str(remote_root)])
    run(["git", "init", "-b", "main", str(repo_root)])
    run(["git", "config", "user.name", "Codex Tests"], cwd=repo_root)
    run(["git", "config", "user.email", "codex-tests@example.com"], cwd=repo_root)

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
