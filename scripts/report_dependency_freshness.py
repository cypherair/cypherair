#!/usr/bin/env python3
"""On-demand dependency freshness report for CypherAir (tracker #674, lane 6).

Prints a drift report for every machine-consumed dependency class the
repository has, without modifying or weakening any pin:

- compatible-range crates (``cargo update --dry-run`` count),
- exact pins vs upstream latest (sequoia-openpgp and UniFFI on crates.io,
  the SQLCipher wrapper pin JSON vs the owned fork's latest release, the
  openssl-src / linktime carry refs vs their fork branch heads, and the
  arm64e stage1 toolchain pin vs the latest stage1 release),
- pinned GitHub Actions vs each action's latest release.

Visibility only: exact pins are updated exclusively through their owning
lanes (repin-arm64e, the fork-release repin flow, tracker dependency PRs).
The process always exits 0 -- a freshness report must never fail a pipeline.
``--json`` emits a machine-readable document instead of the text summary.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
CARGO_MANIFEST = "pgp-mobile/Cargo.toml"
CARGO_LOCK = "pgp-mobile/Cargo.lock"
WORKFLOWS_DIR = ".github/workflows"
SQLCIPHER_PIN = "third_party/sqlcipher-xcframework.pin.json"
STAGE1_PIN = "third_party/arm64e-stage1-toolchain.pin.json"
STAGE1_TAG_PREFIX = "rust-arm64e-stage1-"
USER_AGENT = "cypherair-dependency-freshness (https://github.com/cypherair/cypherair)"

STATUS_CURRENT = "current"
STATUS_UPDATE = "update-available"
STATUS_DRIFT = "drift"
STATUS_UNAVAILABLE = "unavailable"


def _load_arm64e_module():
    """Load scripts/arm64e_release_metadata.py for its carry-lock parsers."""

    module_path = REPO_ROOT / "scripts" / "arm64e_release_metadata.py"
    spec = importlib.util.spec_from_file_location("arm64e_release_metadata", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- fetchers (network access lives here; tests inject fakes) ---------------


def http_get_json(url: str) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if url.startswith("https://api.github.com/"):
        request.add_header("Accept", "application/vnd.github+json")
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def crates_io_max_stable_version(crate: str) -> str:
    data = http_get_json(f"https://crates.io/api/v1/crates/{crate}")
    return str(data["crate"]["max_stable_version"])


def github_latest_release(repository: str) -> dict:
    data = http_get_json(f"https://api.github.com/repos/{repository}/releases/latest")
    assert isinstance(data, dict)
    return data


def github_releases(repository: str) -> list[dict]:
    data = http_get_json(f"https://api.github.com/repos/{repository}/releases?per_page=50")
    assert isinstance(data, list)
    return data


def github_tag_commit(repository: str, tag: str) -> str:
    ref = http_get_json(f"https://api.github.com/repos/{repository}/git/ref/tags/{tag}")
    assert isinstance(ref, dict)
    object_type = ref["object"]["type"]
    object_sha = ref["object"]["sha"]
    if object_type == "tag":
        tag_object = http_get_json(
            f"https://api.github.com/repos/{repository}/git/tags/{object_sha}"
        )
        assert isinstance(tag_object, dict)
        return str(tag_object["object"]["sha"])
    return str(object_sha)


def cargo_update_dry_run(repo_root: Path) -> str:
    completed = subprocess.run(
        [
            "cargo",
            "update",
            "--dry-run",
            "--manifest-path",
            str(repo_root / CARGO_MANIFEST),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        timeout=600,
        check=True,
    )
    return completed.stderr + completed.stdout


class Fetchers:
    """Injection point so unit tests never touch the network."""

    def __init__(
        self,
        crates_latest: Callable[[str], str] = crates_io_max_stable_version,
        latest_release: Callable[[str], dict] = github_latest_release,
        releases: Callable[[str], list[dict]] = github_releases,
        tag_commit: Callable[[str, str], str] = github_tag_commit,
        branch_head: Callable[[str, str], str] | None = None,
        cargo_dry_run: Callable[[Path], str] = cargo_update_dry_run,
    ) -> None:
        self.crates_latest = crates_latest
        self.latest_release = latest_release
        self.releases = releases
        self.tag_commit = tag_commit
        self._branch_head = branch_head
        self.cargo_dry_run = cargo_dry_run

    def branch_head(self, repository_url: str, branch: str) -> str:
        if self._branch_head is not None:
            return self._branch_head(repository_url, branch)
        return _load_arm64e_module().remote_branch_head(repository_url, branch)


# --- pure parsers (unit-tested, no I/O) -------------------------------------


def parse_cargo_update_dry_run(output: str) -> list[dict]:
    """Extract ``Updating name vX -> vY`` rows from cargo's dry-run output."""

    updates = []
    for match in re.finditer(
        r"^\s*Updating\s+(\S+)\s+v(\S+)\s+->\s+v(\S+)\s*$", output, flags=re.MULTILINE
    ):
        updates.append(
            {"name": match.group(1), "from": match.group(2), "to": match.group(3)}
        )
    return updates


def parse_workflow_action_pins(workflow_texts: dict[str, str]) -> list[dict]:
    """Extract unique SHA-pinned third-party actions from workflow contents.

    ``workflow_texts`` maps a display name (file name) to the file's text.
    Local composite actions (``./...``) and non-SHA refs are ignored; the
    repository policy is full-SHA pins with a version comment.
    """

    pins: dict[tuple[str, str], dict] = {}
    pattern = re.compile(
        r"^\s*(?:-\s+)?uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})"
        r"(?:\s*#\s*(\S+))?",
        flags=re.MULTILINE,
    )
    for file_name in sorted(workflow_texts):
        for match in pattern.finditer(workflow_texts[file_name]):
            action, sha, comment = match.group(1), match.group(2), match.group(3)
            entry = pins.setdefault(
                (action, sha),
                {"action": action, "sha": sha, "comment": comment or "", "files": []},
            )
            if file_name not in entry["files"]:
                entry["files"].append(file_name)
    return [pins[key] for key in sorted(pins)]


def parse_exact_pin(cargo_toml_text: str, package: str) -> str:
    """Return the ``=X.Y.Z`` exact-pin version for a package, if declared."""

    match = re.search(
        rf'^{re.escape(package)}\s*=\s*\{{[^}}]*?version\s*=\s*"=([^"]+)"',
        cargo_toml_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise ValueError(f"no exact pin found for {package}")
    return match.group(1)


def parse_locked_version(cargo_lock_text: str, package: str) -> str:
    """Return the resolved version of a package from Cargo.lock."""

    match = re.search(
        rf'\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"',
        cargo_lock_text,
    )
    if match is None:
        raise ValueError(f"{package} not found in Cargo.lock")
    return match.group(1)


def latest_stage1_release(releases: list[dict]) -> dict | None:
    """Pick the newest ``rust-arm64e-stage1-*`` release by publish time."""

    stage1 = [
        release
        for release in releases
        if str(release.get("tag_name", "")).startswith(STAGE1_TAG_PREFIX)
        and not release.get("draft", False)
    ]
    if not stage1:
        return None
    return max(stage1, key=lambda release: str(release.get("published_at", "")))


def version_tuple(version: str) -> tuple:
    parts = []
    for part in re.split(r"[.+-]", version):
        parts.append(int(part) if part.isdigit() else part)
    return tuple(parts)


def versions_equal_or_newer(pinned: str, latest: str) -> bool:
    try:
        return version_tuple(pinned) >= version_tuple(latest)
    except TypeError:
        return pinned == latest


def entry(section: str, name: str, status: str, pinned: str, latest: str, note: str = "") -> dict:
    return {
        "section": section,
        "name": name,
        "status": status,
        "pinned": pinned,
        "latest": latest,
        "note": note,
    }


def unavailable(section: str, name: str, error: Exception) -> dict:
    reason = f"{type(error).__name__}: {error}"
    return entry(section, name, STATUS_UNAVAILABLE, "", "", reason)


# --- checks -----------------------------------------------------------------


def check_crates(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    try:
        updates = parse_cargo_update_dry_run(fetchers.cargo_dry_run(repo_root))
    except Exception as error:  # noqa: BLE001 - report, never fail
        return [unavailable("crates", "cargo update --dry-run", error)]
    if not updates:
        return [
            entry(
                "crates",
                "cargo update --dry-run",
                STATUS_CURRENT,
                "lockfile",
                "lockfile",
                "no compatible updates",
            )
        ]
    preview = ", ".join(
        f"{update['name']} v{update['from']} -> v{update['to']}" for update in updates[:8]
    )
    if len(updates) > 8:
        preview += f", and {len(updates) - 8} more"
    return [
        entry(
            "crates",
            "cargo update --dry-run",
            STATUS_UPDATE,
            "lockfile",
            f"{len(updates)} compatible updates",
            preview,
        )
    ]


def check_exact_crate_pins(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    entries = []

    try:
        pinned = parse_exact_pin((repo_root / CARGO_MANIFEST).read_text(encoding="utf-8"), "sequoia-openpgp")
        latest = fetchers.crates_latest("sequoia-openpgp")
        status = STATUS_CURRENT if versions_equal_or_newer(pinned, latest) else STATUS_UPDATE
        entries.append(
            entry(
                "exact-pins",
                "sequoia-openpgp (crates.io)",
                status,
                pinned,
                latest,
                "exact pin; bumps re-run interop, notices, and the composite_kem port re-diff",
            )
        )
    except Exception as error:  # noqa: BLE001
        entries.append(unavailable("exact-pins", "sequoia-openpgp (crates.io)", error))

    try:
        locked = parse_locked_version((repo_root / CARGO_LOCK).read_text(encoding="utf-8"), "uniffi")
        latest = fetchers.crates_latest("uniffi")
        status = STATUS_CURRENT if versions_equal_or_newer(locked, latest) else STATUS_UPDATE
        entries.append(
            entry(
                "exact-pins",
                "uniffi (crates.io)",
                status,
                locked,
                latest,
                "breaking-version lane; bumps regenerate bindings and the XCFramework",
            )
        )
    except Exception as error:  # noqa: BLE001
        entries.append(unavailable("exact-pins", "uniffi (crates.io)", error))

    return entries


def check_sqlcipher_pin(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    name = "SQLCipher.xcframework (cypherair/sqlcipher-xcframework)"
    try:
        pin = json.loads((repo_root / SQLCIPHER_PIN).read_text(encoding="utf-8"))
        pinned_tag = pin["release"]["tag"]
        repository = pin["repository"]
        latest = fetchers.latest_release(repository)
        latest_tag = str(latest.get("tag_name", ""))
        status = STATUS_CURRENT if latest_tag == pinned_tag else STATUS_UPDATE
        note = "wrapper releases are rebuilt on the fork before the app pin changes"
        return [entry("exact-pins", name, status, pinned_tag, latest_tag, note)]
    except Exception as error:  # noqa: BLE001
        return [unavailable("exact-pins", name, error)]


def check_carry_refs(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    entries = []
    try:
        arm64e = _load_arm64e_module()
        carries = (
            ("openssl-src carry (cypherair/openssl-src-rs)", arm64e.parse_openssl_src_lock),
            ("ctor carry (cypherair/linktime)", arm64e.parse_ctor_lock),
        )
    except Exception as error:  # noqa: BLE001
        return [unavailable("carries", "carry-lock parsers", error)]

    for name, parser in carries:
        try:
            lock = parser(repo_root / CARGO_LOCK)
            head = fetchers.branch_head(lock["repository"], lock["branch"])
            pinned = lock["resolvedCommit"]
            status = STATUS_CURRENT if head == pinned else STATUS_DRIFT
            note = (
                f"branch {lock['branch']}; report-only -- carry rebases follow the "
                "fork-PR -> consumer-pin flow"
            )
            entries.append(entry("carries", name, status, pinned[:12], head[:12], note))
        except Exception as error:  # noqa: BLE001
            entries.append(unavailable("carries", name, error))
    return entries


def check_stage1_pin(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    name = "arm64e stage1 toolchain (cypherair/rust)"
    try:
        pin = json.loads((repo_root / STAGE1_PIN).read_text(encoding="utf-8"))
        pinned_tag = pin["release"]["tag"]
        published_at = str(pin["release"].get("publishedAt", ""))
        latest = latest_stage1_release(fetchers.releases(pin["repository"]))
        if latest is None:
            return [
                entry(
                    "exact-pins",
                    name,
                    STATUS_UNAVAILABLE,
                    pinned_tag,
                    "",
                    "no stage1 releases visible",
                )
            ]
        latest_tag = str(latest.get("tag_name", ""))
        status = STATUS_CURRENT if latest_tag == pinned_tag else STATUS_UPDATE
        note = f"pin published {published_at}; rotation owned by repin-arm64e"
        return [entry("exact-pins", name, status, pinned_tag, latest_tag, note)]
    except Exception as error:  # noqa: BLE001
        return [unavailable("exact-pins", name, error)]


def check_action_pins(repo_root: Path, fetchers: Fetchers) -> list[dict]:
    try:
        workflow_texts = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted((repo_root / WORKFLOWS_DIR).glob("*.yml"))
        }
        pins = parse_workflow_action_pins(workflow_texts)
    except Exception as error:  # noqa: BLE001
        return [unavailable("actions", "workflow scan", error)]

    entries = []
    for pin in pins:
        name = f"{pin['action']} ({', '.join(pin['files'])})"
        try:
            latest = fetchers.latest_release(pin["action"])
            latest_tag = str(latest.get("tag_name", ""))
            latest_sha = fetchers.tag_commit(pin["action"], latest_tag)
            status = STATUS_CURRENT if latest_sha == pin["sha"] else STATUS_UPDATE
            pinned_label = f"{pin['sha'][:12]} ({pin['comment'] or 'no comment'})"
            latest_label = f"{latest_sha[:12]} ({latest_tag})"
            entries.append(entry("actions", name, status, pinned_label, latest_label, ""))
        except Exception as error:  # noqa: BLE001
            entries.append(unavailable("actions", name, error))
    return entries


# --- report assembly --------------------------------------------------------

SECTION_TITLES = {
    "crates": "Compatible-range crates (Cargo.lock)",
    "exact-pins": "Exact pins vs upstream latest",
    "carries": "Owned-fork carry refs (report-only)",
    "actions": "Pinned GitHub Actions",
}


def build_report(repo_root: Path, fetchers: Fetchers) -> dict:
    entries = []
    entries.extend(check_crates(repo_root, fetchers))
    entries.extend(check_exact_crate_pins(repo_root, fetchers))
    entries.extend(check_sqlcipher_pin(repo_root, fetchers))
    entries.extend(check_stage1_pin(repo_root, fetchers))
    entries.extend(check_carry_refs(repo_root, fetchers))
    entries.extend(check_action_pins(repo_root, fetchers))

    summary = {status: 0 for status in (STATUS_CURRENT, STATUS_UPDATE, STATUS_DRIFT, STATUS_UNAVAILABLE)}
    for item in entries:
        summary[item["status"]] += 1
    return {
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "entries": entries,
        "summary": summary,
    }


def render_text(report: dict) -> str:
    lines = [
        f"CypherAir dependency freshness report -- {report['generatedAt']}",
        "Visibility only: pins are updated exclusively through their owning lanes.",
        "",
    ]
    for section in ("crates", "exact-pins", "carries", "actions"):
        section_entries = [item for item in report["entries"] if item["section"] == section]
        if not section_entries:
            continue
        lines.append(SECTION_TITLES[section])
        for item in section_entries:
            headline = f"  [{item['status']}] {item['name']}"
            if item["pinned"] or item["latest"]:
                headline += f": pinned {item['pinned'] or '-'}; latest {item['latest'] or '-'}"
            lines.append(headline)
            if item["note"]:
                lines.append(f"      {item['note']}")
        lines.append("")
    summary = report["summary"]
    lines.append(
        "Summary: "
        + ", ".join(f"{summary[status]} {status}" for status in sorted(summary))
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None, repo_root: Path = REPO_ROOT, fetchers: Fetchers | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable JSON report")
    args = parser.parse_args(argv)

    try:
        report = build_report(repo_root, fetchers or Fetchers())
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(render_text(report))
    except Exception as error:  # noqa: BLE001 - reporting must never fail a pipeline
        print(f"dependency freshness report could not be generated: {error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
