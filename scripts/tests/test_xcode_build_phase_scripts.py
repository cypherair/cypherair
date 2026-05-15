from __future__ import annotations

import json
import os
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT, load_script_module


class XcodeBuildPhaseScriptTests(unittest.TestCase):
    def test_settings_bundle_phase_generates_acknowledgements_from_manifest(self) -> None:
        module = load_script_module("sync_settings_bundle", "scripts/sync_settings_bundle.py")

        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            srcroot = temp_root / "repo"
            settings_src = srcroot / "Settings.bundle"
            notices_dir = srcroot / "Sources/Resources/OpenSourceNotices"
            target_build_dir = temp_root / "build"
            resources_dir = "CypherAir.app/Contents/Resources"
            settings_dst = target_build_dir / resources_dir / "Settings.bundle"

            (settings_src / "en.lproj").mkdir(parents=True)
            (settings_src / "zh-Hans.lproj").mkdir(parents=True)
            notices_dir.mkdir(parents=True)
            (srcroot / "scripts").mkdir(parents=True)
            (srcroot / "scripts/sync_settings_bundle.py").symlink_to(
                REPO_ROOT / "scripts/sync_settings_bundle.py"
            )

            with (settings_src / "Root.plist").open("wb") as file:
                plistlib.dump(
                    {
                        "StringsTable": "Root",
                        "PreferenceSpecifiers": [
                            {"Type": "PSGroupSpecifier", "Title": "About CypherAir"},
                            {
                                "Type": "PSTitleValueSpecifier",
                                "Title": "Version",
                                "Key": "cypherair.settings.version",
                                "DefaultValue": "Unspecified",
                            },
                        ],
                    },
                    file,
                )
            for locale in ("en.lproj", "zh-Hans.lproj"):
                (settings_src / locale / "Root.strings").write_text('"Version" = "Version";\n', encoding="utf-8")
                (settings_src / locale / "Acknowledgements.strings").write_text(
                    '"Open Source" = "Open Source";\n',
                    encoding="utf-8",
                )

            (notices_dir / "open_source_notices.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "cypherair",
                            "displayName": "CypherAir",
                            "version": "Unspecified",
                            "licenseName": "GPL-3.0-or-later OR MPL-2.0",
                            "kind": "app",
                            "isDirectDependency": False,
                        },
                        {
                            "id": "sequoia-openpgp@2.2.0",
                            "displayName": "sequoia-openpgp",
                            "version": "2.2.0",
                            "licenseName": "LGPL-2.0-or-later",
                            "kind": "thirdParty",
                            "isDirectDependency": True,
                        },
                        {
                            "id": "openssl@0.10.77",
                            "displayName": "openssl",
                            "version": "0.10.77",
                            "licenseName": "Apache-2.0",
                            "kind": "thirdParty",
                            "isDirectDependency": True,
                        },
                        {
                            "id": "openssl-src@300.6.0+3.6.2",
                            "displayName": "openssl-src",
                            "version": "300.6.0+3.6.2",
                            "licenseName": "MIT/Apache-2.0",
                            "kind": "thirdParty",
                            "isDirectDependency": False,
                        },
                        {
                            "id": "uniffi@0.31.1",
                            "displayName": "uniffi",
                            "version": "0.31.1",
                            "licenseName": "MPL-2.0",
                            "kind": "thirdParty",
                            "isDirectDependency": True,
                        },
                        {
                            "id": "transitive-only@1.0.0",
                            "displayName": "transitive-only",
                            "version": "1.0.0",
                            "licenseName": "MIT",
                            "kind": "thirdParty",
                            "isDirectDependency": False,
                        },
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env.update(
                {
                    "SRCROOT": str(srcroot),
                    "TARGET_BUILD_DIR": str(target_build_dir),
                    "UNLOCALIZED_RESOURCES_FOLDER_PATH": resources_dir,
                    "MARKETING_VERSION": "1.3.5",
                    "CURRENT_PROJECT_VERSION": "7",
                }
            )

            subprocess.run(
                ["python3", str(srcroot / "scripts/sync_settings_bundle.py")],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            root_plist = plistlib.loads((settings_dst / "Root.plist").read_bytes())
            version_item = next(
                item for item in root_plist["PreferenceSpecifiers"]
                if item.get("Key") == "cypherair.settings.version"
            )
            self.assertEqual(version_item["DefaultValue"], "1.3.5 (7)")

            acknowledgements = plistlib.loads((settings_dst / "Acknowledgements.plist").read_bytes())
            values_by_title = {
                item.get("Title"): item.get("DefaultValue")
                for item in acknowledgements["PreferenceSpecifiers"]
                if item.get("Type") == "PSTitleValueSpecifier"
            }
            self.assertEqual(values_by_title["CypherAir"], "GPL-3.0-or-later OR MPL-2.0")
            self.assertEqual(values_by_title["Sequoia OpenPGP"], "2.2.0 / LGPL-2.0-or-later")
            self.assertEqual(values_by_title["OpenSSL Rust Bindings"], "0.10.77 / Apache-2.0")
            self.assertEqual(values_by_title["OpenSSL Source"], "300.6.0+3.6.2 / MIT/Apache-2.0")
            self.assertEqual(values_by_title["UniFFI"], "0.31.1 / MPL-2.0")
            self.assertIn("Apple Swift", module.toolchain_summary(swift_version="", rust_version=""))
            self.assertNotIn("transitive-only", values_by_title)

    def test_repository_audit_snapshot_removes_stale_files_before_copying_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            srcroot = temp_root / "repo"
            target_build_dir = temp_root / "build"
            resources_dir = "CypherAirTests.xctest/Contents/Resources"
            snapshot_dst = target_build_dir / resources_dir / "RepositoryAudit"

            required_files = [
                "Sources/App/Encrypt/EncryptView.swift",
                "Sources/Resources/Localizable.xcstrings",
                "Sources/Resources/InfoPlist.xcstrings",
            ]
            for relative_path in required_files:
                path = srcroot / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"// {relative_path}\n", encoding="utf-8")

            stale_file = snapshot_dst / "Sources/App/DeletedView.swift"
            stale_file.parent.mkdir(parents=True, exist_ok=True)
            stale_file.write_text("// stale\n", encoding="utf-8")

            snapshot_list = srcroot / "Tests/RepositoryAuditInputs.xcfilelist"
            snapshot_list.parent.mkdir(parents=True, exist_ok=True)
            snapshot_list.write_text(
                "\n".join(f"$(SRCROOT)/{relative_path}" for relative_path in required_files) + "\n",
                encoding="utf-8",
            )
            snapshot_output_list = srcroot / "Tests/RepositoryAuditOutputs.xcfilelist"
            snapshot_output_list.write_text(
                "\n".join(
                    "$(TARGET_BUILD_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/"
                    f"RepositoryAudit/{relative_path}"
                    for relative_path in required_files
                ) + "\n",
                encoding="utf-8",
            )
            target_build_dir.mkdir(parents=True, exist_ok=True)

            env = os.environ.copy()
            env.update(
                {
                    "SRCROOT": str(srcroot),
                    "TARGET_BUILD_DIR": str(target_build_dir),
                    "UNLOCALIZED_RESOURCES_FOLDER_PATH": resources_dir,
                }
            )

            subprocess.run(
                ["bash", str(REPO_ROOT / "scripts/snapshot_repository_audit_inputs.sh")],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            self.assertFalse(stale_file.exists())
            for relative_path in required_files:
                self.assertTrue((snapshot_dst / relative_path).exists())

    def test_source_compliance_phase_uses_metadata_commit_without_git_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            srcroot = temp_root / "repo"
            scripts_dir = srcroot / "scripts"
            cargo_dir = srcroot / "pgp-mobile"
            target_build_dir = temp_root / "build"
            target_temp_dir = temp_root / "temp"
            output_path = target_build_dir / "Resources/SourceComplianceInfo.json"
            metadata_path = target_temp_dir / "SourceComplianceOverrides.json"
            metadata_commit = "0123456789abcdef0123456789abcdef01234567"

            scripts_dir.mkdir(parents=True, exist_ok=True)
            cargo_dir.mkdir(parents=True, exist_ok=True)
            target_temp_dir.mkdir(parents=True, exist_ok=True)
            (scripts_dir / "generate_source_compliance_info.py").symlink_to(
                REPO_ROOT / "scripts/generate_source_compliance_info.py"
            )
            (cargo_dir / "Cargo.lock").write_text(
                """
[[package]]
name = "sequoia-openpgp"
version = "2.2.0"

[[package]]
name = "buffered-reader"
version = "1.4.0"
""",
                encoding="utf-8",
            )
            metadata_path.write_text(
                json.dumps(
                    {
                        "commit_sha": metadata_commit,
                        "stable_release_tag": "cypherair-v1.2.9-build4",
                        "stable_release_url": "https://github.com/cypherair/cypherair/releases/tag/cypherair-v1.2.9-build4",
                    }
                ),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env.update(
                {
                    "SRCROOT": str(srcroot),
                    "TARGET_BUILD_DIR": str(target_build_dir),
                    "TARGET_TEMP_DIR": str(target_temp_dir),
                    "UNLOCALIZED_RESOURCES_FOLDER_PATH": "Resources",
                    "MARKETING_VERSION": "1.2.9",
                    "CURRENT_PROJECT_VERSION": "4",
                    "SOURCE_COMPLIANCE_REQUIRE_STABLE_RELEASE": "YES",
                }
            )

            subprocess.run(
                ["bash", str(REPO_ROOT / "scripts/generate_source_compliance_build_phase.sh")],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["commitSHA"], metadata_commit)
            self.assertEqual(payload["stableReleaseTag"], "cypherair-v1.2.9-build4")

    def test_build_apple_arm64e_xcframework_manifest_backup_guard_is_static_valid(self) -> None:
        script_path = REPO_ROOT / "scripts/build_apple_arm64e_xcframework.sh"

        subprocess.run(
            ["bash", "-n", str(script_path)],
            check=True,
            text=True,
            capture_output=True,
        )

        script_text = script_path.read_text(encoding="utf-8")
        self.assertIn("MANIFEST_BACKUP_CREATED=0", script_text)
        self.assertIn('[ "$MANIFEST_BACKUP_CREATED" = "1" ]', script_text)


if __name__ == "__main__":
    unittest.main()
