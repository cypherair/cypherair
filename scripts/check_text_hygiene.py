#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def tracked_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    return [
        repo_root / path.decode("utf-8")
        for path in result.stdout.split(b"\0")
        if path
    ]


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:4096]


def trailing_whitespace_locations(path: Path) -> list[int]:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    if is_binary(data):
        return []

    locations: list[int] = []
    for line_number, line in enumerate(data.splitlines(keepends=True), start=1):
        content = line.rstrip(b"\r\n")
        if content.endswith((b" ", b"\t")):
            locations.append(line_number)
    return locations


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    failures: list[str] = []
    for path in tracked_files(repo_root):
        for line_number in trailing_whitespace_locations(path):
            failures.append(f"{path.relative_to(repo_root)}:{line_number}: trailing whitespace")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
