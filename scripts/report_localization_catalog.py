#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CATALOGS = [
    "Sources/Resources/Localizable.xcstrings",
    "Sources/Resources/InfoPlist.xcstrings",
]
REQUIRED_LOCALES = ["en", "zh-Hans"]


@dataclass(frozen=True)
class LocalizationIssue:
    catalog_path: Path
    key: str
    locale: str
    code: str
    message: str


@dataclass(frozen=True)
class CatalogReport:
    path: Path
    entry_count: int
    issues: list[LocalizationIssue]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report non-blocking String Catalog localization health.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--catalog", action="append", dest="catalogs", help="Catalog path relative to --root.")
    parser.add_argument("--github-annotations", action="store_true", help="Emit GitHub warning annotations to stderr.")
    parser.add_argument("--max-annotations", type=int, default=50)
    parser.add_argument("--strict", action="store_true", help="Exit 1 when localization issues are found.")
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def analyze_catalog(path: Path, display_path: Path | None = None) -> CatalogReport:
    report_path = display_path or path
    payload = load_json(path)
    strings = payload.get("strings")
    if not isinstance(strings, dict):
        raise ValueError(f"{path} does not contain a String Catalog 'strings' object")

    issues: list[LocalizationIssue] = []
    for key, entry in sorted(strings.items()):
        if not isinstance(entry, dict):
            issues.append(issue(report_path, key, "", "invalid-entry", "entry is not an object"))
            continue
        issues.extend(analyze_entry(report_path, key, entry))
    return CatalogReport(path=report_path, entry_count=len(strings), issues=issues)


def analyze_entry(path: Path, key: str, entry: dict) -> list[LocalizationIssue]:
    issues: list[LocalizationIssue] = []
    if entry.get("extractionState") == "stale":
        issues.append(issue(path, key, "", "stale", "entry is marked stale by Xcode"))

    localizations = entry.get("localizations")
    if not isinstance(localizations, dict):
        return issues + [issue(path, key, "", "missing-localizations", "entry has no localizations object")]

    for locale in REQUIRED_LOCALES:
        localization = localizations.get(locale)
        if not isinstance(localization, dict):
            issues.append(issue(path, key, locale, "missing-locale", f"missing required {locale} localization"))
            continue
        issues.extend(analyze_localization(path, key, locale, localization))
    return issues


def analyze_localization(path: Path, key: str, locale: str, localization: dict) -> list[LocalizationIssue]:
    string_unit = localization.get("stringUnit")
    if isinstance(string_unit, dict):
        state = str(string_unit.get("state", ""))
        if state != "translated":
            return [issue(path, key, locale, "untranslated", f"{locale} string unit state is {state or 'missing'}")]
        return []

    plural = ((localization.get("variations") or {}).get("plural") or {})
    if isinstance(plural, dict) and plural:
        return analyze_plural(path, key, locale, plural)

    return [issue(path, key, locale, "missing-string-unit", f"{locale} has no string unit or plural variations")]


def analyze_plural(path: Path, key: str, locale: str, plural: dict) -> list[LocalizationIssue]:
    issues: list[LocalizationIssue] = []
    if "other" not in plural:
        issues.append(issue(path, key, locale, "missing-plural-other", f"{locale} plural variations are missing 'other'"))
    if locale == "en" and "one" not in plural:
        issues.append(issue(path, key, locale, "missing-plural-one", "en plural variations are missing 'one'"))

    for category, variation in sorted(plural.items()):
        string_unit = variation.get("stringUnit") if isinstance(variation, dict) else None
        if not isinstance(string_unit, dict):
            issues.append(
                issue(path, key, locale, "missing-plural-string-unit", f"{locale} plural category {category} has no string unit")
            )
            continue
        state = str(string_unit.get("state", ""))
        if state != "translated":
            issues.append(
                issue(path, key, locale, "untranslated-plural", f"{locale} plural category {category} state is {state or 'missing'}")
            )
    return issues


def issue(path: Path, key: str, locale: str, code: str, message: str) -> LocalizationIssue:
    return LocalizationIssue(catalog_path=path, key=key, locale=locale, code=code, message=message)


def render_markdown(reports: list[CatalogReport]) -> str:
    total_entries = sum(report.entry_count for report in reports)
    issues = [item for report in reports for item in report.issues]
    lines = [
        "# Localization Catalog Report",
        "",
        f"Checked {len(reports)} catalog(s), {total_entries} string entr{'y' if total_entries == 1 else 'ies'}.",
        f"Found {len(issues)} warning(s).",
        "",
    ]
    for report in reports:
        lines.append(f"- `{report.path}`: {report.entry_count} entries, {len(report.issues)} warning(s)")
    if issues:
        lines.extend(["", "| Catalog | Key | Locale | Issue |", "| --- | --- | --- | --- |"])
        for item in issues[:200]:
            locale = item.locale or "-"
            lines.append(
                f"| `{item.catalog_path}` | `{markdown_escape(item.key)}` | `{locale}` | {markdown_escape(item.message)} |"
            )
        if len(issues) > 200:
            lines.append(f"| ... | ... | ... | {len(issues) - 200} more warning(s) omitted from summary |")
    else:
        lines.extend(["", "No stale or incomplete required localizations found."])
    return "\n".join(lines) + "\n"


def emit_github_annotations(issues: list[LocalizationIssue], max_annotations: int) -> None:
    for item in issues[:max_annotations]:
        location = github_escape(str(item.catalog_path))
        title = github_escape(f"Localization {item.code}")
        body = github_escape(f"{item.key}{f' ({item.locale})' if item.locale else ''}: {item.message}")
        print(f"::warning file={location},title={title}::{body}", file=sys.stderr)
    if len(issues) > max_annotations:
        print(
            f"::warning title=Localization report::{len(issues) - max_annotations} additional localization warning(s) omitted",
            file=sys.stderr,
        )


def github_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    catalog_names = args.catalogs or DEFAULT_CATALOGS
    try:
        reports = [analyze_catalog(root / catalog_name, Path(catalog_name)) for catalog_name in catalog_names]
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"error: localization catalog report failed: {error}", file=sys.stderr)
        return 1

    issues = [item for report in reports for item in report.issues]
    print(render_markdown(reports), end="")
    if args.github_annotations or os.environ.get("GITHUB_ACTIONS") == "true":
        emit_github_annotations(issues, args.max_annotations)
    if args.strict and issues:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
