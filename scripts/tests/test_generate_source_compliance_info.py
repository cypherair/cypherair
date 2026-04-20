from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
