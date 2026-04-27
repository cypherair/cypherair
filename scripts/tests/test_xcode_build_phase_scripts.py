from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT


class XcodeBuildPhaseScriptTests(unittest.TestCase):
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
