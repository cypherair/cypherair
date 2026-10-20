from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from support import REPO_ROOT, load_script_module


module = load_script_module("validate_xcframework_archive", "scripts/validate_xcframework_archive.py")


def write_zip(path: Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "payload")


class ValidateZipEntriesTests(unittest.TestCase):
    def test_well_formed_archive_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "PgpMobile.xcframework.zip"
            write_zip(
                zip_path,
                [
                    "PgpMobile.xcframework/Info.plist",
                    "PgpMobile.xcframework/macos-arm64_arm64e/libpgp_mobile.a",
                ],
            )
            module.validate_zip_entries(zip_path, "PgpMobile.xcframework")

    def test_absolute_path_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "archive.zip"
            write_zip(zip_path, ["PgpMobile.xcframework/Info.plist", "/etc/launchd.conf"])
            with self.assertRaises(module.ArchiveValidationError) as raised:
                module.validate_zip_entries(zip_path, "PgpMobile.xcframework")
            self.assertIn("absolute path entry", str(raised.exception))

    def test_parent_directory_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "archive.zip"
            write_zip(zip_path, ["PgpMobile.xcframework/Info.plist", "../../.ssh/authorized_keys"])
            with self.assertRaises(module.ArchiveValidationError) as raised:
                module.validate_zip_entries(zip_path, "PgpMobile.xcframework")
            self.assertIn("parent-directory entry", str(raised.exception))

    def test_entry_outside_the_expected_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "archive.zip"
            write_zip(zip_path, ["PgpMobile.xcframework/Info.plist", "Other.xcframework/Info.plist"])
            with self.assertRaises(module.ArchiveValidationError) as raised:
                module.validate_zip_entries(zip_path, "PgpMobile.xcframework")
            self.assertIn("entry outside PgpMobile.xcframework/", str(raised.exception))

    def test_sibling_prefix_entry_is_rejected(self) -> None:
        # "PgpMobile.xcframework.evil/..." shares a prefix with the expected
        # root but is a different directory.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "archive.zip"
            write_zip(zip_path, ["PgpMobile.xcframework.evil/payload"])
            with self.assertRaises(module.ArchiveValidationError):
                module.validate_zip_entries(zip_path, "PgpMobile.xcframework")

    def test_empty_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            zip_path = Path(temp_dir_name) / "archive.zip"
            write_zip(zip_path, [])
            with self.assertRaises(module.ArchiveValidationError) as raised:
                module.validate_zip_entries(zip_path, "PgpMobile.xcframework")
            self.assertIn("no entries", str(raised.exception))

    def test_missing_archive_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            with self.assertRaises(module.ArchiveValidationError):
                module.validate_zip_entries(Path(temp_dir_name) / "absent.zip", "PgpMobile.xcframework")


class ValidateExtractedSymlinksTests(unittest.TestCase):
    def make_tree(self, root: Path) -> Path:
        tree = root / "PgpMobile.xcframework"
        (tree / "macos-arm64_arm64e").mkdir(parents=True)
        (tree / "Info.plist").write_text("<plist/>\n", encoding="utf-8")
        (tree / "macos-arm64_arm64e" / "libpgp_mobile.a").write_text("archive", encoding="utf-8")
        return tree

    def test_internal_symlinks_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            tree = self.make_tree(Path(temp_dir_name))
            (tree / "Current").symlink_to("macos-arm64_arm64e")
            (tree / "macos-arm64_arm64e" / "Latest.a").symlink_to("libpgp_mobile.a")
            module.validate_extracted_symlinks(tree)

    def test_escaping_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = Path(temp_dir_name)
            outside = root / "outside.txt"
            outside.write_text("secret\n", encoding="utf-8")
            tree = self.make_tree(root)
            (tree / "Escape").symlink_to(outside)

            with self.assertRaises(module.ArchiveValidationError) as raised:
                module.validate_extracted_symlinks(tree)
            self.assertIn("symlink escapes the xcframework", str(raised.exception))

    def test_escaping_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = Path(temp_dir_name)
            (root / "elsewhere").mkdir()
            tree = self.make_tree(root)
            (tree / "Linked").symlink_to(root / "elsewhere", target_is_directory=True)

            with self.assertRaises(module.ArchiveValidationError):
                module.validate_extracted_symlinks(tree)

    def test_missing_tree_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            with self.assertRaises(module.ArchiveValidationError):
                module.validate_extracted_symlinks(Path(temp_dir_name) / "absent")


if __name__ == "__main__":
    unittest.main()
