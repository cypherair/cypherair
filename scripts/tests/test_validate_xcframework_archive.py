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


class SQLCipherRestoreCallSiteTests(unittest.TestCase):
    """The SQLCipher restore must still reject hostile archives before ditto."""

    def test_zip_slip_entry_fails_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            repo_root = temp_dir / "repo"
            (repo_root / "scripts").mkdir(parents=True)
            for script in (
                "restore_sqlcipher_xcframework.sh",
                "validate_xcframework_archive.py",
                "validate_sqlcipher_xcframework.py",
            ):
                (repo_root / "scripts" / script).symlink_to(REPO_ROOT / "scripts" / script)

            local_build = temp_dir / "local-build"
            local_build.mkdir()
            work_dir = temp_dir / "work"
            fake_bin = temp_dir / "bin"
            fake_bin.mkdir()

            zip_path = local_build / "SQLCipher.xcframework.zip"
            write_zip(zip_path, ["SQLCipher.xcframework/Info.plist", "../evil.txt"])
            zip_bytes = zip_path.read_bytes()
            zip_digest = hashlib.sha256(zip_bytes).hexdigest()

            assets = {
                "SQLCipher.xcframework.zip": zip_bytes,
                "SQLCipher.xcframework.sha256": f"{zip_digest}  SQLCipher.xcframework.zip\n".encode(),
                "SQLCipher.arm64e-build-manifest.json": b"{}\n",
                "SQLCipher-PrivacyInfo.xcprivacy": b"{}\n",
                "SQLCipher.xcframework.release.json": b"{}\n",
            }
            pin_assets: dict[str, dict[str, object]] = {}
            for name, contents in assets.items():
                (local_build / name).write_bytes(contents)
                pin_assets[name] = {
                    "sha256": hashlib.sha256(contents).hexdigest(),
                    "size": len(contents),
                }

            pin_path = temp_dir / "pin.json"
            pin_path.write_text(
                json.dumps(
                    {
                        "repository": "cypherair/sqlcipher-xcframework",
                        "release": {
                            "tag": "sqlcipher-xcframework-v4.17.0-cypherair.1",
                            "commitSha": "9d8c3627ad67b521a5bd5145bdea98632c80a22b",
                            "sourceRef": "refs/tags/sqlcipher-xcframework-v4.17.0-cypherair.1",
                            "signerWorkflow": "cypherair/sqlcipher-xcframework/.github/workflows/stable-release.yml",
                            "channel": "stable",
                        },
                        "assets": pin_assets,
                    }
                ),
                encoding="utf-8",
            )

            extraction_marker = temp_dir / "extraction-attempted"
            fake_ditto = fake_bin / "ditto"
            fake_ditto.write_text('#!/bin/sh\ntouch "$DITTO_MARKER"\nexit 99\n', encoding="utf-8")
            fake_ditto.chmod(0o755)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "DITTO_MARKER": str(extraction_marker),
                    "SQLCIPHER_PIN_FILE": str(pin_path),
                    "SQLCIPHER_RESTORE_WORK_DIR": str(work_dir),
                }
            )
            completed = subprocess.run(
                [
                    "bash",
                    str(repo_root / "scripts" / "restore_sqlcipher_xcframework.sh"),
                    "--from-local-build",
                    str(local_build),
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("parent-directory entry", completed.stderr)
            self.assertFalse(extraction_marker.exists())


if __name__ == "__main__":
    unittest.main()
