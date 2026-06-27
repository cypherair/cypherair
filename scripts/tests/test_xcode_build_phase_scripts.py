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
    def test_source_compliance_phase_declares_sqlcipher_pin_input(self) -> None:
        project_text = (REPO_ROOT / "CypherAir.xcodeproj/project.pbxproj").read_text(encoding="utf-8")

        self.assertIn("Generate Source Compliance Info", project_text)
        self.assertIn("$(SRCROOT)/third_party/sqlcipher-xcframework.pin.json", project_text)

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
                            {"Type": "PSGroupSpecifier", "Title": "About CypherAir X"},
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
                            "displayName": "CypherAir X",
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
                            "id": "uniffi@0.31.2",
                            "displayName": "uniffi",
                            "version": "0.31.2",
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
            self.assertEqual(values_by_title["CypherAir X"], "GPL-3.0-or-later OR MPL-2.0")
            self.assertEqual(values_by_title["Sequoia OpenPGP"], "2.2.0 / LGPL-2.0-or-later")
            self.assertEqual(values_by_title["OpenSSL Rust Bindings"], "0.10.77 / Apache-2.0")
            self.assertEqual(values_by_title["OpenSSL Source"], "300.6.0+3.6.2 / MIT/Apache-2.0")
            self.assertEqual(values_by_title["UniFFI"], "0.31.2 / MPL-2.0")
            self.assertIn("Apple Swift", module.toolchain_summary(swift_version="", rust_version=""))
            self.assertNotIn("transitive-only", values_by_title)

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

    def test_source_compliance_phase_derives_from_xcode_cloud_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            srcroot = temp_root / "repo"
            scripts_dir = srcroot / "scripts"
            cargo_dir = srcroot / "pgp-mobile"
            target_build_dir = temp_root / "build"
            target_temp_dir = temp_root / "temp"
            output_path = target_build_dir / "Resources/SourceComplianceInfo.json"
            ci_commit = "0123456789abcdef0123456789abcdef01234567"
            ci_tag = "cypherair-v1.2.9-build4"

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

            # No SourceComplianceOverrides.json metadata file is written: Xcode
            # Cloud does not run the local scheme pre-action, so the values must
            # come from the CI_* environment.
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
                    "CI_XCODE_CLOUD": "TRUE",
                    "CI_TAG": ci_tag,
                    "CI_COMMIT": ci_commit,
                }
            )
            # Ensure no stray local override leaks in from the parent environment.
            for stale_key in (
                "SOURCE_COMPLIANCE_COMMIT_SHA",
                "SOURCE_COMPLIANCE_STABLE_RELEASE_TAG",
                "SOURCE_COMPLIANCE_STABLE_RELEASE_URL",
            ):
                env.pop(stale_key, None)

            subprocess.run(
                ["bash", str(REPO_ROOT / "scripts/generate_source_compliance_build_phase.sh")],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["commitSHA"], ci_commit)
            self.assertEqual(payload["stableReleaseTag"], ci_tag)
            self.assertEqual(
                payload["stableReleaseURL"],
                f"https://github.com/cypherair/cypherair/releases/tag/{ci_tag}",
            )
            self.assertTrue(payload["isStableReleaseBuild"])

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

    def test_build_apple_arm64e_xcframework_normalizes_generated_text(self) -> None:
        script_text = (REPO_ROOT / "scripts/build_apple_arm64e_xcframework.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("normalize_generated_text_file", script_text)
        self.assertIn(r"s/[ \t]+$//mg", script_text)
        self.assertIn(r"s/\n+\z/\n/", script_text)
        self.assertIn('normalize_generated_text_file "$GENERATED_BINDINGS_DIR/pgp_mobileFFI.h"', script_text)


if __name__ == "__main__":
    unittest.main()
