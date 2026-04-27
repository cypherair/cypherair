#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path


ACKNOWLEDGEMENTS_FILE_NAME = "Acknowledgements.plist"
CORE_DEPENDENCY_IDS = {
    "base64",
    "openssl",
    "openssl-src",
    "sequoia-openpgp",
    "thiserror",
    "uniffi",
    "zeroize",
}


def main() -> int:
    try:
        sync_settings_bundle_from_environment()
    except Exception as error:  # pragma: no cover - build phase entrypoint
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def sync_settings_bundle_from_environment() -> None:
    srcroot = required_path_env("SRCROOT")
    target_build_dir = required_path_env("TARGET_BUILD_DIR")
    resources_folder = required_env("UNLOCALIZED_RESOURCES_FOLDER_PATH")

    settings_src = srcroot / "Settings.bundle"
    settings_dst = target_build_dir / resources_folder / "Settings.bundle"
    notices_manifest = srcroot / "Sources" / "Resources" / "OpenSourceNotices" / "open_source_notices.json"

    sync_settings_bundle(
        settings_src=settings_src,
        settings_dst=settings_dst,
        notices_manifest=notices_manifest,
        version_string=build_version_string(
            os.environ.get("MARKETING_VERSION", ""),
            os.environ.get("CURRENT_PROJECT_VERSION", ""),
        ),
        swift_version=apple_swift_version(),
        rust_version=rust_version(),
    )


def sync_settings_bundle(
    *,
    settings_src: Path,
    settings_dst: Path,
    notices_manifest: Path,
    version_string: str,
    swift_version: str,
    rust_version: str,
) -> None:
    if not settings_src.is_dir():
        raise FileNotFoundError(f"Settings bundle source is missing: {settings_src}")
    if not notices_manifest.is_file():
        raise FileNotFoundError(f"Open source notices manifest is missing: {notices_manifest}")

    if settings_dst.exists() and not settings_dst.is_dir():
        settings_dst.unlink()

    settings_dst.mkdir(parents=True, exist_ok=True)
    copy_settings_resource(settings_src / "Root.plist", settings_dst / "Root.plist")

    for locale in ("en.lproj", "zh-Hans.lproj"):
        locale_src = settings_src / locale
        locale_dst = settings_dst / locale
        locale_dst.mkdir(parents=True, exist_ok=True)
        copy_settings_resource(locale_src / "Root.strings", locale_dst / "Root.strings")
        copy_settings_resource(locale_src / "Acknowledgements.strings", locale_dst / "Acknowledgements.strings")

    stamp_root_version(settings_dst / "Root.plist", version_string)
    notices = load_notices(notices_manifest)
    acknowledgements = build_acknowledgements_plist(
        notices=notices,
        swift_version=swift_version,
        rust_version=rust_version,
    )
    write_plist(acknowledgements, settings_dst / ACKNOWLEDGEMENTS_FILE_NAME)


def build_acknowledgements_plist(
    *,
    notices: list[dict],
    swift_version: str,
    rust_version: str,
) -> dict:
    app_notice = find_notice(notices, "cypherair")
    core_notices = core_dependency_notices(notices)

    preference_specifiers = [
        {
            "Type": "PSGroupSpecifier",
            "Title": "Open Source",
            "FooterText": (
                "CypherAir is built with open-source cryptography and tooling. "
                "Complete notices and license text are available inside the app "
                "under Settings, About, Source & Compliance."
            ),
        }
    ]

    if app_notice is not None:
        preference_specifiers.append(
            title_value_specifier(
                title="CypherAir",
                key="cypherair.acknowledgements.app",
                value=license_summary(app_notice),
            )
        )

    for notice in core_notices:
        preference_specifiers.append(
            title_value_specifier(
                title=display_title(notice),
                key=f"cypherair.acknowledgements.{normalized_key(notice['displayName'])}",
                value=version_license_summary(notice),
            )
        )

    preference_specifiers.append(
        title_value_specifier(
            title="Toolchain",
            key="cypherair.acknowledgements.toolchain",
            value=toolchain_summary(swift_version=swift_version, rust_version=rust_version),
        )
    )

    return {
        "StringsTable": "Acknowledgements",
        "PreferenceSpecifiers": preference_specifiers,
    }


def load_notices(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Open source notices manifest must be a JSON array")
    return data


def find_notice(notices: list[dict], notice_id: str) -> dict | None:
    return next((notice for notice in notices if notice.get("id") == notice_id), None)


def core_dependency_notices(notices: list[dict]) -> list[dict]:
    selected = [
        notice
        for notice in notices
        if notice.get("kind") == "thirdParty"
        and (
            notice.get("isDirectDependency") is True
            or package_name(notice) in {"openssl-src"}
        )
        and package_name(notice) in CORE_DEPENDENCY_IDS
    ]
    return sorted(selected, key=lambda notice: notice["displayName"].lower())


def package_name(notice: dict) -> str:
    return str(notice.get("id", "")).split("@", 1)[0]


def display_title(notice: dict) -> str:
    name = str(notice["displayName"])
    if name == "sequoia-openpgp":
        return "Sequoia OpenPGP"
    if name == "openssl-src":
        return "OpenSSL Source"
    if name == "openssl":
        return "OpenSSL Rust Bindings"
    if name == "uniffi":
        return "UniFFI"
    return name


def version_license_summary(notice: dict) -> str:
    version = str(notice.get("version", "")).strip()
    license_name = license_summary(notice)
    if version:
        return f"{version} / {license_name}"
    return license_name


def license_summary(notice: dict) -> str:
    return str(notice.get("licenseName", "Unknown")).strip() or "Unknown"


def toolchain_summary(*, swift_version: str, rust_version: str) -> str:
    pieces = [swift_version or "Apple Swift", rust_version or "Rust"]
    return " / ".join(pieces)


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", ".", value.lower()).strip(".")


def title_value_specifier(*, title: str, key: str, value: str) -> dict:
    return {
        "Type": "PSTitleValueSpecifier",
        "Title": title,
        "Key": key,
        "DefaultValue": value,
    }


def stamp_root_version(root_plist: Path, version_string: str) -> None:
    plist = read_plist(root_plist)
    for item in plist.get("PreferenceSpecifiers", []):
        if item.get("Key") == "cypherair.settings.version":
            item["DefaultValue"] = version_string
            write_plist(plist, root_plist)
            return
    raise ValueError("cypherair.settings.version not found in Settings.bundle Root.plist")


def build_version_string(marketing_version: str, build_number: str) -> str:
    version = marketing_version.strip()
    build = build_number.strip()
    if version and build:
        return f"{version} ({build})"
    return version or build or "Unspecified"


def apple_swift_version() -> str:
    output = command_output(["xcrun", "swift", "--version"])
    if output is None:
        return "Apple Swift"
    match = re.search(r"Apple Swift version ([^\s]+)", output)
    if match:
        return f"Apple Swift {match.group(1)}"
    return "Apple Swift"


def rust_version() -> str:
    output = command_output(["rustc", "--version"])
    if output is None:
        return "Rust"
    parts = output.split()
    if len(parts) >= 2 and parts[0] == "rustc":
        return f"Rust {parts[1]}"
    return "Rust"


def command_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(args, text=True, capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def copy_settings_resource(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"Settings resource is missing: {source}")
    shutil.copy2(source, destination)


def read_plist(path: Path) -> dict:
    with path.open("rb") as file:
        return plistlib.load(file)


def write_plist(payload: dict, path: Path) -> None:
    with path.open("wb") as file:
        plistlib.dump(payload, file)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise EnvironmentError(f"{name} is required")
    return value


def required_path_env(name: str) -> Path:
    return Path(required_env(name))


if __name__ == "__main__":
    raise SystemExit(main())
