from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT, load_script_module, run


module = load_script_module(
    "build_compliance_release_assets",
    "scripts/build_compliance_release_assets.py",
)


class BuildComplianceReleaseAssetsTests(unittest.TestCase):
    def test_external_binary_dependency_entry_records_sqlcipher_pin(self) -> None:
        entries = module.external_binary_dependency_entries(
            [REPO_ROOT / "third_party" / "sqlcipher-xcframework.pin.json"]
        )

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["name"], "SQLCipher.xcframework")
        self.assertEqual(entry["repository"], "cypherair/sqlcipher-xcframework")
        self.assertEqual(entry["releaseTag"], "sqlcipher-xcframework-v4.16.0-cypherair.1")
        self.assertEqual(entry["releaseChannel"], "stable")
        self.assertTrue(entry["releaseIsImmutable"])
        self.assertFalse(entry["releaseIsPrerelease"])
        self.assertFalse(entry["mirroredInCypherAirRelease"])
        self.assertEqual(entry["upstreamTag"], "v4.16.0")
        self.assertIn("SQLCipher.xcframework.zip", entry["assetHashes"])
        self.assertIn("ios-arm64_arm64e", entry["sliceHashes"])

    def test_source_bundle_uses_relative_vendor_path_and_supports_offline_metadata(self) -> None:
        commit_sha = run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT).stdout.strip()

        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            output_path = temp_dir / "CypherAir-source-bundle.tar.zst"
            extract_root = temp_dir / "extracted"

            module.build_source_bundle(output_path, commit_sha, "test-tag")

            extract_root.mkdir(parents=True, exist_ok=True)
            run(
                [
                    "sh",
                    "-c",
                    f"zstd -d -c {output_path} | bsdtar -xf - -C {extract_root}",
                ],
                cwd=REPO_ROOT,
            )

            bundle_root = extract_root / "CypherAir-source-bundle"
            config_path = bundle_root / ".cargo" / "config.toml"
            config_text = config_path.read_text(encoding="utf-8")

            self.assertIn('directory = "vendor"', config_text)
            self.assertNotIn("/var/folders/", config_text)

            run(
                [
                    "cargo",
                    "metadata",
                    "--offline",
                    "--locked",
                    "--manifest-path",
                    "pgp-mobile/Cargo.toml",
                    "--format-version",
                    "1",
                ],
                cwd=bundle_root,
            )


if __name__ == "__main__":
    unittest.main()
