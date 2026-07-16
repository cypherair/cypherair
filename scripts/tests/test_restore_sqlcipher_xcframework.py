from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT


class RestoreSQLCipherXCFrameworkTests(unittest.TestCase):
    def test_correct_hash_with_wrong_size_fails_before_extraction(self) -> None:
        script_path = REPO_ROOT / "scripts" / "restore_sqlcipher_xcframework.sh"
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            local_build = temp_dir / "local-build"
            work_dir = temp_dir / "work"
            fake_bin = temp_dir / "bin"
            local_build.mkdir()
            fake_bin.mkdir()

            assets = {
                "SQLCipher.xcframework.zip": b"correct digest but deliberately wrong pinned size",
                "SQLCipher.xcframework.sha256": b"unused in this early-failure test\n",
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
            pin_assets["SQLCipher.xcframework.zip"]["size"] = len(assets["SQLCipher.xcframework.zip"]) + 1

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
            fake_ditto.write_text(
                '#!/bin/sh\ntouch "$DITTO_MARKER"\nexit 99\n',
                encoding="utf-8",
            )
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
                ["bash", str(script_path), "--from-local-build", str(local_build)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                f"SQLCipher.xcframework.zip size {len(assets['SQLCipher.xcframework.zip'])} "
                f"!= expected {len(assets['SQLCipher.xcframework.zip']) + 1}",
                completed.stderr,
            )
            self.assertFalse(extraction_marker.exists())


if __name__ == "__main__":
    unittest.main()
