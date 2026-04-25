#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "pgp-mobile" / "Cargo.toml"
RESOURCE_DIR = ROOT / "Sources" / "Resources" / "OpenSourceNotices"
NOTICE_FILE = RESOURCE_DIR / "open_source_notices.json"
APP_LICENSE_TEXT_PATHS = [
    ROOT / "LICENSE-GPL",
    ROOT / "LICENSE-MPL",
]
APP_REPOSITORY_URL = "https://github.com/cypherair/cypherair"
REGISTRY_LICENSE_PATTERN = re.compile(r"(?i)^(license|copying|unlicense|copyright)([.-].+)?$")
LICENSE_FETCH_HEADERS = {"User-Agent": "CypherAir Open Source Notices"}

SPDX_FILE_HINTS = {
    "0BSD": ["LICENSE-0BSD", "COPYING-0BSD"],
    "Apache-2.0": ["LICENSE-APACHE", "LICENSE-APACHE-2.0"],
    "BSD-3-Clause": ["LICENSE", "COPYING"],
    "LGPL-2.0-or-later": ["LICENSE.txt", "LICENSE-LGPL", "COPYING.LESSER", "COPYING"],
    "LGPL-2.1-or-later": ["LICENSE-LGPL", "COPYING.LESSER", "COPYING"],
    "MIT": ["LICENSE-MIT", "MIT-LICENSE", "LICENSE"],
    "MPL-2.0": ["LICENSE", "LICENSE-MPL", "LICENSE-MPL-2.0"],
    "Unicode-3.0": ["LICENSE-UNICODE", "LICENSE"],
    "Unlicense": ["UNLICENSE", "LICENSE-UNLICENSE", "COPYING"],
}

SPDX_TEXT_FALLBACKS = {
    "Apache-2.0": {"search_names": ["LICENSE-APACHE", "LICENSE-APACHE-2.0"]},
    "LGPL-2.1-or-later": {"url": "https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt", "name": "LGPL-2.1.txt"},
    "MIT": {"search_names": ["LICENSE-MIT", "MIT-LICENSE"]},
}

@dataclass(frozen=True)
class PackageRecord:
    id: str
    name: str
    version: str
    license_name: str
    repository_url: str
    manifest_path: Path
    is_direct_dependency: bool


@dataclass(frozen=True)
class LicenseSource:
    kind: str
    items: list[str]


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True)


def load_metadata() -> dict:
    return json.loads(
        run("cargo", "metadata", "--manifest-path", str(MANIFEST_PATH), "--format-version", "1")
    )


def reachable_packages(metadata: dict) -> list[PackageRecord]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root_id = next(package["id"] for package in metadata["packages"] if package["name"] == "pgp-mobile")
    direct_dependency_names = direct_dependency_name_set(metadata)

    seen = {root_id}
    queue: deque[str] = deque([root_id])
    while queue:
        node_id = queue.popleft()
        for dependency in nodes[node_id].get("deps", []):
            dependency_kinds = {item["kind"] or "normal" for item in dependency.get("dep_kinds", [])}
            if "normal" not in dependency_kinds:
                continue
            package = packages[dependency["pkg"]]
            target_kinds = {kind for target in package["targets"] for kind in target["kind"]}
            if "proc-macro" in target_kinds:
                continue
            if dependency["pkg"] in seen:
                continue
            seen.add(dependency["pkg"])
            queue.append(dependency["pkg"])

    openssl_src = next(package["id"] for package in metadata["packages"] if package["name"] == "openssl-src")
    seen.add(openssl_src)

    records: list[PackageRecord] = []
    for package_id in sorted(seen):
        package = packages[package_id]
        if package["name"] == "pgp-mobile":
            continue
        records.append(
            PackageRecord(
                id=f"{package['name']}@{package['version']}",
                name=package["name"],
                version=package["version"],
                license_name=package.get("license") or "Unknown",
                repository_url=normalize_url(package.get("repository") or ""),
                manifest_path=Path(package["manifest_path"]),
                is_direct_dependency=package["name"] in direct_dependency_names,
            )
        )

    records.sort(key=lambda item: (item.name.lower(), item.version))
    return records


def normalize_url(url: str) -> str:
    normalized = url.rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def direct_dependency_name_set(metadata: dict) -> set[str]:
    root_package = next(package for package in metadata["packages"] if package["name"] == "pgp-mobile")
    return {
        dependency["name"]
        for dependency in root_package["dependencies"]
        if (dependency["kind"] or "normal") == "normal"
    }


def extract_license_identifiers(license_expression: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9.+-]+(?:-or-later|-only)?", license_expression)


def license_candidate_paths(package: PackageRecord) -> list[Path]:
    return license_candidate_paths_at(package.manifest_path.parent, package.license_name)


def license_candidate_paths_at(root: Path, license_name: str) -> list[Path]:
    candidates = [entry for entry in root.iterdir() if entry.is_file() and REGISTRY_LICENSE_PATTERN.match(entry.name)]
    license_files: list[Path] = []
    identifiers = extract_license_identifiers(license_name)
    for identifier in identifiers:
        for name in SPDX_FILE_HINTS.get(identifier, []):
            path = root / name
            if path.is_file() and path not in license_files:
                license_files.append(path)

    if license_files:
        return license_files

    if len(candidates) == 1:
        return candidates

    for path in sorted(candidates):
        if path not in license_files:
            license_files.append(path)
    return license_files


def major_minor_patch(version: str) -> str:
    match = re.match(r"(\d+\.\d+\.\d+)", version)
    return match.group(1) if match else version


def candidate_remote_tags(package: PackageRecord) -> list[str]:
    normalized_name = package.name.replace("_", "-")
    short_version = major_minor_patch(package.version)
    candidates = [
        f"v{package.version}",
        package.version,
        f"{normalized_name}-{package.version}",
        f"{normalized_name}-{short_version}",
        f"v{short_version}",
        short_version,
    ]
    seen = set()
    unique: list[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def github_repo_path(repository_url: str) -> str | None:
    match = re.match(r"https://github\.com/([^/]+/[^/]+)$", repository_url.rstrip("/"))
    if not match:
        return None
    return match.group(1)


def remote_archive_license_files(package: PackageRecord) -> tuple[list[tuple[str, str]], list[str]]:
    repo_path = github_repo_path(package.repository_url)
    if repo_path is None:
        return [], []

    for tag in candidate_remote_tags(package):
        archive_url = f"https://codeload.github.com/{repo_path}/tar.gz/refs/tags/{tag}"
        request = urllib.request.Request(archive_url, headers=LICENSE_FETCH_HEADERS)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                archive_bytes = response.read()
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "archive.tar.gz"
            archive_path.write_bytes(archive_bytes)
            with tarfile.open(archive_path) as archive:
                archive.extractall(temp_dir, filter="data")

            extracted_roots = [path for path in Path(temp_dir).iterdir() if path.is_dir()]
            if not extracted_roots:
                continue
            license_paths = license_candidate_paths_at(extracted_roots[0], package.license_name)
            if not license_paths:
                continue
            return (
                [(path.name, path.read_text(encoding="utf-8")) for path in license_paths],
                [f"{tag}:{path.name}" for path in license_paths],
            )

    return [], []


def fallback_license_texts(package: PackageRecord) -> tuple[list[tuple[str, str]], list[str]]:
    texts: list[tuple[str, str]] = []
    details: list[str] = []
    for identifier in extract_license_identifiers(package.license_name):
        fallback = SPDX_TEXT_FALLBACKS.get(identifier)
        if fallback is None:
            continue

        if "search_names" in fallback:
            found_path = first_registry_match(fallback["search_names"])
            if found_path is None:
                continue
            texts.append((found_path.name, found_path.read_text(encoding="utf-8")))
            details.append(f"{identifier}: canonical text from {found_path.name}")
            continue

        request = urllib.request.Request(fallback["url"], headers=LICENSE_FETCH_HEADERS)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                texts.append((fallback["name"], response.read().decode("utf-8")))
                details.append(f"{identifier}: standard text from {fallback['url']}")
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue

    deduplicated: list[tuple[str, str]] = []
    seen = set()
    for name, text in texts:
        key = (name, text)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append((name, text))
    return deduplicated, details


def first_registry_match(file_names: list[str]) -> Path | None:
    registry_root = Path.home() / ".cargo" / "registry" / "src"
    for file_name in file_names:
        matches = sorted(registry_root.rglob(file_name))
        if matches:
            return matches[0]
    return None


def render_license_text(package: PackageRecord) -> tuple[str, LicenseSource]:
    local_paths = license_candidate_paths(package)
    if local_paths:
        texts = [(path.name, path.read_text(encoding="utf-8")) for path in local_paths]
        return combine_license_texts(texts), LicenseSource(
            kind="cratePackage",
            items=[path.name for path in local_paths],
        )

    remote_texts, remote_details = remote_archive_license_files(package)
    if remote_texts:
        return combine_license_texts(remote_texts), LicenseSource(
            kind="repositoryArchive",
            items=remote_details,
        )

    fallback_texts, fallback_details = fallback_license_texts(package)
    if fallback_texts:
        return combine_license_texts(fallback_texts), LicenseSource(
            kind="spdxFallback",
            items=fallback_details,
        )

    raise RuntimeError(f"No license text found for {package.name} {package.version}")


def combine_license_texts(texts: list[tuple[str, str]]) -> str:
    if len(texts) == 1:
        return texts[0][1]

    chunks = []
    for index, (name, text) in enumerate(texts):
        if index > 0:
            chunks.append("\n\n")
        chunks.append(f"===== {name} =====\n\n{text}")
    return "".join(chunks)


def resource_file_name(package: PackageRecord) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{package.name}-{package.version}")
    return f"{stem}.txt"


def build_notice_manifest(packages: list[PackageRecord], license_sources: dict[str, LicenseSource]) -> list[dict]:
    notices = [
        {
            "id": "cypherair",
            "displayName": "CypherAir",
            "version": app_version_string(),
            "repositoryURL": APP_REPOSITORY_URL,
            "licenseName": "GPL-3.0-or-later OR MPL-2.0",
            "licenseFileResourceName": "CypherAir-DUAL-LICENSE.txt",
            "kind": "app",
            "isDirectDependency": False,
            "licenseSourceKind": "projectFile",
            "licenseSourceItems": [
                "LICENSE-GPL",
                "LICENSE-MPL",
            ],
        }
    ]

    for package in packages:
        license_source = license_sources[package.id]
        notices.append(
            {
                "id": package.id,
                "displayName": package.name,
                "version": package.version,
                "repositoryURL": package.repository_url,
                "licenseName": package.license_name,
                "licenseFileResourceName": resource_file_name(package),
                "kind": "thirdParty",
                "isDirectDependency": package.is_direct_dependency,
                "licenseSourceKind": license_source.kind,
                "licenseSourceItems": license_source.items,
            }
        )

    return notices


def app_version_string() -> str:
    plist_path = ROOT / "CypherAir-Info.plist"
    if not plist_path.exists():
        return "Unspecified"
    try:
        with plist_path.open("rb") as file:
            info_plist = plistlib.load(file)
    except Exception:
        return "Unspecified"
    version = info_plist.get("CFBundleShortVersionString", "").strip()
    build = info_plist.get("CFBundleVersion", "").strip()
    if version and build:
        return f"{version} ({build})"
    return version or build or "Unspecified"


def generate() -> None:
    metadata = load_metadata()
    packages = reachable_packages(metadata)
    license_sources: dict[str, LicenseSource] = {}

    if RESOURCE_DIR.exists():
        for entry in RESOURCE_DIR.iterdir():
            if entry.name == ".gitkeep":
                continue
            if entry.is_dir():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    else:
        RESOURCE_DIR.mkdir(parents=True)

    app_license_text = combine_license_texts(
        [(path.name, path.read_text(encoding="utf-8")) for path in APP_LICENSE_TEXT_PATHS]
    )
    (RESOURCE_DIR / "CypherAir-DUAL-LICENSE.txt").write_text(app_license_text, encoding="utf-8")

    for package in packages:
        license_text, license_source = render_license_text(package)
        license_sources[package.id] = license_source
        (RESOURCE_DIR / resource_file_name(package)).write_text(license_text, encoding="utf-8")

    notices = build_notice_manifest(packages, license_sources)
    NOTICE_FILE.write_text(json.dumps(notices, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Generated {len(notices)} notices in {RESOURCE_DIR}")


if __name__ == "__main__":
    try:
        generate()
    except Exception as error:  # pragma: no cover - helper script
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
