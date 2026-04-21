from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import head_sha, init_repo_with_remote, load_script_module


module = load_script_module(
    "generate_source_compliance_info",
    "scripts/generate_source_compliance_info.py",
)


class GenerateSourceComplianceInfoTests(unittest.TestCase):
    def test_regular_build_allows_unknown_when_commit_is_missing(self) -> None:
        self.assertEqual(
            module.resolved_commit_sha("", require_stable_release=False),
            "unknown",
        )
        self.assertEqual(
            module.resolved_commit_sha("unknown", require_stable_release=False),
            "unknown",
        )

    def test_stable_required_build_resolves_head_for_empty_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            self.assertEqual(
                module.resolved_commit_sha(
                    "",
                    require_stable_release=True,
                    repo_root=repo_root,
                ),
                head_sha(repo_root),
            )

    def test_stable_required_build_resolves_head_for_unknown_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            self.assertEqual(
                module.resolved_commit_sha(
                    "unknown",
                    require_stable_release=True,
                    repo_root=repo_root,
                ),
                head_sha(repo_root),
            )

    def test_stable_required_build_fails_without_git_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            non_repo_root = Path(temp_dir_name)
            with self.assertRaisesRegex(RuntimeError, "exact git commit SHA"):
                module.resolved_commit_sha(
                    "",
                    require_stable_release=True,
                    repo_root=non_repo_root,
                )

    def test_resolved_metadata_value_prefers_explicit_value(self) -> None:
        self.assertEqual(
            module.resolved_metadata_value("explicit", "metadata"),
            "explicit",
        )

    def test_resolved_metadata_value_falls_back_to_metadata(self) -> None:
        self.assertEqual(
            module.resolved_metadata_value("", "metadata"),
            "metadata",
        )

    def test_load_source_compliance_metadata_reads_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            metadata_path = Path(temp_dir_name) / "metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "commit_sha": "abc123",
                        "stable_release_tag": "cypherair-v1.2.9-build4",
                        "stable_release_url": "https://github.com/cypherair/cypherair/releases/tag/cypherair-v1.2.9-build4",
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                module.load_source_compliance_metadata(metadata_path),
                {
                    "commit_sha": "abc123",
                    "stable_release_tag": "cypherair-v1.2.9-build4",
                    "stable_release_url": "https://github.com/cypherair/cypherair/releases/tag/cypherair-v1.2.9-build4",
                },
            )

    def test_stable_required_build_prefers_explicit_commit_over_metadata(self) -> None:
        self.assertEqual(
            module.resolved_commit_sha(
                "explicit-sha",
                require_stable_release=True,
                metadata_commit_sha="metadata-sha",
            ),
            "explicit-sha",
        )

    def test_stable_required_build_prefers_metadata_commit_over_git(self) -> None:
        with mock.patch.object(
            module,
            "resolve_git_head_commit",
            side_effect=AssertionError("git fallback should not run"),
        ):
            self.assertEqual(
                module.resolved_commit_sha(
                    "",
                    require_stable_release=True,
                    metadata_commit_sha="metadata-sha",
                ),
                "metadata-sha",
            )


if __name__ == "__main__":
    unittest.main()
