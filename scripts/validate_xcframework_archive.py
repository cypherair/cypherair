#!/usr/bin/env python3
"""Reject XCFramework archives that could write outside their extraction root.

`ditto -x -k` runs with full filesystem privileges and honours whatever paths an
archive contains, so a pinned checksum alone does not make extraction safe: the
archive still has to be structurally trustworthy before any byte lands on disk.

Two checks, applied by every XCFramework restore path:

  --zip     entry names must be relative, free of `..` components, and confined
            to the single expected `<Name>.xcframework/` root. Run this *before*
            extracting anything.
  --tree    symlinks inside the extracted bundle must resolve within it.
            Symlinks are legitimate in an xcframework (macOS framework bundles
            use versioned-layout links); only escaping ones are rejected.

This is the validation scripts/restore_sqlcipher_xcframework.sh introduced for
the SQLCipher restore, lifted into one owner so the PgpMobile restore in
ci_scripts/ci_post_clone.sh applies exactly the same rules.
"""

from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path


MAX_REPORTED = 10


class ArchiveValidationError(RuntimeError):
    """The archive or the extracted tree failed a containment check."""


def validate_zip_entries(zip_path: Path, expected_root: str) -> None:
    """Every entry must live at or under `expected_root`, with no escapes."""
    if not zip_path.is_file():
        raise ArchiveValidationError(f"archive is missing: {zip_path}")

    try:
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile) as error:
        raise ArchiveValidationError(f"archive is unreadable: {zip_path} ({error})") from error

    errors: list[str] = []
    if not names:
        errors.append("archive has no entries")

    prefix = f"{expected_root}/"
    for name in names:
        if name.startswith("/"):
            errors.append(f"absolute path entry: {name!r}")
        elif ".." in name.split("/"):
            errors.append(f"parent-directory entry: {name!r}")
        elif name.rstrip("/") != expected_root and not name.startswith(prefix):
            errors.append(f"entry outside {prefix}: {name!r}")

    if errors:
        raise ArchiveValidationError(
            f"rejecting {expected_root} archive: " + "; ".join(errors[:MAX_REPORTED])
        )


def validate_extracted_symlinks(tree: Path) -> None:
    """Reject links whose resolved target escapes the extracted tree."""
    if not tree.is_dir():
        raise ArchiveValidationError(f"extracted tree is missing: {tree}")

    root = os.path.realpath(tree)
    errors: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for entry in dirnames + filenames:
            path = os.path.join(dirpath, entry)
            if not os.path.islink(path):
                continue
            resolved = os.path.realpath(path)
            if resolved != root and not resolved.startswith(root + os.sep):
                errors.append(
                    f"symlink escapes the xcframework: "
                    f"{os.path.relpath(path, root)} -> {os.readlink(path)}"
                )

    if errors:
        raise ArchiveValidationError(
            f"rejecting {Path(root).name} archive: " + "; ".join(errors[:MAX_REPORTED])
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--zip", type=Path, help="archive to validate before extraction")
    mode.add_argument("--tree", type=Path, help="extracted xcframework to validate after extraction")
    parser.add_argument(
        "--expected-root",
        help="the single top-level bundle every zip entry must live under, e.g. SQLCipher.xcframework",
    )
    args = parser.parse_args(argv)

    try:
        if args.zip is not None:
            if not args.expected_root:
                parser.error("--zip requires --expected-root")
            validate_zip_entries(args.zip, args.expected_root)
        else:
            validate_extracted_symlinks(args.tree)
    except ArchiveValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
