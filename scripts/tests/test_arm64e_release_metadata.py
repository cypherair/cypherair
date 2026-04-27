from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import load_script_module


module = load_script_module(
    "arm64e_release_metadata",
    "scripts/arm64e_release_metadata.py",
)


class Arm64eReleaseMetadataTests(unittest.TestCase):
    def test_parse_openssl_src_lock_extracts_branch_and_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            lock_path = Path(temp_dir_name) / "Cargo.lock"
            lock_path.write_text(
                """
[[package]]
name = "openssl-src"
version = "300.6.2+3.6.2"
source = "git+https://github.com/cypherair/openssl-src-rs?branch=carry%2Fapple-arm64e-openssl-fork#be17d9174a9223a0dfdcbbd9407fe079882214a0"
""",
                encoding="utf-8",
            )

            parsed = module.parse_openssl_src_lock(lock_path)

        self.assertEqual(parsed["repository"], "https://github.com/cypherair/openssl-src-rs")
        self.assertEqual(parsed["branch"], "carry/apple-arm64e-openssl-fork")
        self.assertEqual(
            parsed["resolvedCommit"],
            "be17d9174a9223a0dfdcbbd9407fe079882214a0",
        )

    def test_collect_dependency_chain_reports_stale_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            lock_path = Path(temp_dir_name) / "Cargo.lock"
            lock_path.write_text(
                """
[[package]]
name = "openssl-src"
version = "300.6.2+3.6.2"
source = "git+https://github.com/cypherair/openssl-src-rs?branch=carry%2Fapple-arm64e-openssl-fork#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
                encoding="utf-8",
            )

            with mock.patch.object(module, "remote_branch_head") as remote_branch_head:
                remote_branch_head.side_effect = [
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "d228bf84",
                ]
                with mock.patch.object(module, "openssl_submodule_pointer", return_value="d228bf84"):
                    chain = module.collect_dependency_chain(lock_path, "warn")

        self.assertFalse(chain["freshness"]["isFresh"])
        self.assertTrue(chain["freshness"]["lookupPerformed"])
        self.assertIn("Cargo.lock commit aaaaaaaaaa", chain["freshness"]["messages"][0])

    def test_collect_dependency_chain_skips_remote_lookups_when_freshness_off(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            lock_path = Path(temp_dir_name) / "Cargo.lock"
            lock_path.write_text(
                """
[[package]]
name = "openssl-src"
version = "300.6.2+3.6.2"
source = "git+https://github.com/cypherair/openssl-src-rs?branch=carry%2Fapple-arm64e-openssl-fork#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
                encoding="utf-8",
            )

            with mock.patch.object(
                module,
                "remote_branch_head",
                side_effect=AssertionError("remote lookup should not run"),
            ):
                with mock.patch.object(
                    module,
                    "openssl_submodule_pointer",
                    side_effect=AssertionError("submodule lookup should not run"),
                ):
                    chain = module.collect_dependency_chain(lock_path, "off")

        self.assertFalse(chain["freshness"]["lookupPerformed"])
        self.assertIsNone(chain["freshness"]["isFresh"])
        self.assertEqual(chain["freshness"]["messages"], [])
        self.assertIsNone(chain["opensslSrc"]["remoteBranchHead"])
        self.assertIsNone(chain["opensslSrc"]["isFresh"])
        self.assertIsNone(chain["openssl"]["submoduleCommit"])
        self.assertIsNone(chain["openssl"]["remoteBranchHead"])
        self.assertIsNone(chain["openssl"]["isFresh"])

    def test_collect_dependency_chain_errors_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            lock_path = Path(temp_dir_name) / "Cargo.lock"
            lock_path.write_text(
                """
[[package]]
name = "openssl-src"
version = "300.6.2+3.6.2"
source = "git+https://github.com/cypherair/openssl-src-rs?branch=carry%2Fapple-arm64e-openssl-fork#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
                encoding="utf-8",
            )

            with mock.patch.object(module, "remote_branch_head") as remote_branch_head:
                remote_branch_head.side_effect = [
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "d228bf84",
                ]
                with mock.patch.object(module, "openssl_submodule_pointer", return_value="d228bf84"):
                    with self.assertRaisesRegex(module.MetadataError, "Cargo.lock commit aaaaaaaaaa"):
                        module.collect_dependency_chain(lock_path, "error")


if __name__ == "__main__":
    unittest.main()
