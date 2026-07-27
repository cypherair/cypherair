#!/usr/bin/env python3
"""Fail closed when the shipped open-source notices drift from the crate graph.

Sources/Resources/OpenSourceNotices/open_source_notices.json is generated from
the pgp-mobile dependency graph by scripts/generate_open_source_notices.py, and
nothing used to notice when a dependency change landed without regenerating it.
The app then ships a legal screen that names the wrong versions.

Re-running the generator in CI is not a usable gate: it needs `cargo metadata`
for eight Apple targets, reads license texts out of the local cargo registry,
and falls back to fetching repository archives over the network. Its output is
also not byte-stable -- two Sequoia LGPL license texts churn on form feeds. So
this gate compares the *inputs and the dependency set* instead:

  1. pgp-mobile/Cargo.lock still hashes to the value recorded when the notices
     were generated (any dependency change trips this, which is exactly the
     documented dependency-update workflow);
  2. open_source_notices.json still hashes to the value recorded at generation
     (a hand-edited manifest trips this);
  3. every crate-sourced notice names a package that Cargo.lock actually
     resolves at that exact version;
  4. every notice's license text resource is present in the bundle directory.

The recorded values live in third_party/open-source-notices.fingerprint.json,
which the generator writes at the end of a successful run (--write).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CARGO_LOCK = "pgp-mobile/Cargo.lock"
NOTICES_DIR = "Sources/Resources/OpenSourceNotices"
NOTICES_FILE = f"{NOTICES_DIR}/open_source_notices.json"
FINGERPRINT_FILE = "third_party/open-source-notices.fingerprint.json"
REGENERATE_COMMAND = "python3 scripts/generate_open_source_notices.py"
SCHEMA_VERSION = 1

CARGO_LOCK_PACKAGE = re.compile(
    r"^\[\[package\]\]\s*$(?P<body>.*?)(?=^\[\[|\Z)",
    re.MULTILINE | re.DOTALL,
)


class NoticesFreshnessError(RuntimeError):
    """The notices manifest is stale, hand-edited, or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo_lock_packages(text: str) -> set[str]:
    """Return {name@version} for every package resolved by Cargo.lock."""
    packages: set[str] = set()
    for match in CARGO_LOCK_PACKAGE.finditer(text):
        body = match.group("body")
        name = re.search(r'^name = "(?P<value>[^"]+)"', body, re.MULTILINE)
        version = re.search(r'^version = "(?P<value>[^"]+)"', body, re.MULTILINE)
        if name and version:
            packages.add(f"{name.group('value')}@{version.group('value')}")
    return packages


def external_notice_ids(repo_root: Path) -> set[str]:
    """Ids the generator injects by hand; they are not cargo packages."""
    module_path = repo_root / "scripts" / "generate_open_source_notices.py"
    spec = importlib.util.spec_from_file_location("generate_open_source_notices", module_path)
    if spec is None or spec.loader is None:
        raise NoticesFreshnessError(f"unable to load the notices generator: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return {record["id"] for record in module.EXTERNAL_NOTICE_RECORDS}


def load_notices(repo_root: Path) -> list[dict]:
    path = repo_root / NOTICES_FILE
    if not path.is_file():
        raise NoticesFreshnessError(f"notices manifest is missing: {NOTICES_FILE}")
    try:
        notices = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise NoticesFreshnessError(f"notices manifest is not valid JSON ({error})") from error
    if not isinstance(notices, list) or not notices:
        raise NoticesFreshnessError("notices manifest must be a non-empty array")
    return notices


def build_fingerprint(repo_root: Path) -> dict:
    notices = load_notices(repo_root)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": "scripts/generate_open_source_notices.py",
        "regenerateCommand": REGENERATE_COMMAND,
        "cargoLock": {
            "path": CARGO_LOCK,
            "sha256": sha256_file(repo_root / CARGO_LOCK),
        },
        "notices": {
            "path": NOTICES_FILE,
            "sha256": sha256_file(repo_root / NOTICES_FILE),
            "recordCount": len(notices),
        },
    }


def write_fingerprint(repo_root: Path) -> Path:
    payload = build_fingerprint(repo_root)
    destination = repo_root / FINGERPRINT_FILE
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _recorded(repo_root: Path) -> dict:
    path = repo_root / FINGERPRINT_FILE
    if not path.is_file():
        raise NoticesFreshnessError(
            f"notices fingerprint is missing: {FINGERPRINT_FILE}\n"
            f"       Regenerate the notices: {REGENERATE_COMMAND}"
        )
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise NoticesFreshnessError(f"notices fingerprint is not valid JSON ({error})") from error
    if not isinstance(recorded, dict):
        raise NoticesFreshnessError(f"notices fingerprint is malformed: {FINGERPRINT_FILE}")
    return recorded


def check(repo_root: Path) -> None:
    recorded = _recorded(repo_root)
    current = build_fingerprint(repo_root)
    problems: list[str] = []

    recorded_lock = recorded.get("cargoLock", {}).get("sha256")
    if recorded_lock != current["cargoLock"]["sha256"]:
        problems.append(
            f"{CARGO_LOCK} changed since the notices were generated\n"
            f"         recorded sha256 {recorded_lock}\n"
            f"         current  sha256 {current['cargoLock']['sha256']}"
        )

    recorded_notices = recorded.get("notices", {}).get("sha256")
    if recorded_notices != current["notices"]["sha256"]:
        problems.append(
            f"{NOTICES_FILE} changed since it was generated\n"
            f"         recorded sha256 {recorded_notices}\n"
            f"         current  sha256 {current['notices']['sha256']}"
        )

    notices = load_notices(repo_root)
    packages = cargo_lock_packages((repo_root / CARGO_LOCK).read_text(encoding="utf-8"))
    external_ids = external_notice_ids(repo_root)

    unresolved = sorted(
        notice["id"]
        for notice in notices
        if notice.get("kind") == "thirdParty"
        and notice["id"] not in external_ids
        and notice["id"] not in packages
    )
    if unresolved:
        listed = "\n".join(f"         - {item}" for item in unresolved[:20])
        problems.append(
            f"{len(unresolved)} notice(s) name packages that {CARGO_LOCK} does not resolve:\n{listed}"
        )

    notices_dir = repo_root / NOTICES_DIR
    missing_texts = sorted(
        {
            notice["licenseFileResourceName"]
            for notice in notices
            if notice.get("licenseFileResourceName")
            and not (notices_dir / notice["licenseFileResourceName"]).is_file()
        }
    )
    if missing_texts:
        listed = "\n".join(f"         - {item}" for item in missing_texts[:20])
        problems.append(f"{len(missing_texts)} license text resource(s) are missing:\n{listed}")

    if problems:
        joined = "\n       ".join(problems)
        raise NoticesFreshnessError(
            f"open source notices are stale:\n       {joined}\n"
            f"       Regenerate them and re-record the fingerprint: {REGENERATE_COMMAND}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="record the fingerprint of the current notices")
    mode.add_argument("--check", action="store_true", help="verify the notices against the recorded fingerprint")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    try:
        if args.write:
            destination = write_fingerprint(repo_root)
            print(f"recorded open source notices fingerprint: {destination}")
        else:
            check(repo_root)
            print("open source notices match the recorded dependency set")
    except NoticesFreshnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
