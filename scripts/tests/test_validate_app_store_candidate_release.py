from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import create_annotated_stable_tag, head_sha, init_repo_with_remote, load_script_module, run


module = load_script_module(
    "validate_app_store_candidate_release",
    "scripts/validate_app_store_candidate_release.py",
)


class ValidateAppStoreCandidateReleaseTests(unittest.TestCase):
    def test_clean_main_repo_matching_remote_tag_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                validated_tag = module.validate_candidate_release(
                    repo_root=repo_root,
                    marketing_version="1.2.9",
                    build_number="3",
                    repository_full_name="cypherair/cypherair",
                    require_stable_release=True,
                )
            self.assertEqual(validated_tag, release_tag)

    def test_non_main_branch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            run(["git", "checkout", "-b", "feature"], cwd=repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with self.assertRaisesRegex(module.CandidateValidationError, "main branch"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_tracked_worktree_changes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "tracked.txt").write_text("dirty\n", encoding="utf-8")
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with self.assertRaisesRegex(module.CandidateValidationError, "clean tracked worktree"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_staged_changes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "tracked.txt").write_text("staged\n", encoding="utf-8")
            run(["git", "add", "tracked.txt"], cwd=repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with self.assertRaisesRegex(module.CandidateValidationError, "clean tracked worktree"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_untracked_files_do_not_block_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "notes.txt").write_text("scratch\n", encoding="utf-8")
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                module.validate_candidate_release(
                    repo_root=repo_root,
                    marketing_version="1.2.9",
                    build_number="3",
                    repository_full_name="cypherair/cypherair",
                    require_stable_release=True,
                )

    def test_missing_release_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=False):
                with self.assertRaisesRegex(module.CandidateValidationError, "Missing GitHub stable release"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_missing_origin_remote_is_reported_as_candidate_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            repo_root = temp_root / "repo"
            upstream_root = temp_root / "upstream.git"

            run(["git", "init", "--bare", str(upstream_root)])
            run(["git", "init", "-b", "main", str(repo_root)])
            run(["git", "config", "user.name", "Codex Tests"], cwd=repo_root)
            run(["git", "config", "user.email", "codex-tests@example.com"], cwd=repo_root)

            tracked_file = repo_root / "tracked.txt"
            tracked_file.write_text("base\n", encoding="utf-8")
            run(["git", "add", "tracked.txt"], cwd=repo_root)
            run(["git", "commit", "-m", "Initial commit"], cwd=repo_root)
            run(["git", "remote", "add", "upstream", str(upstream_root)], cwd=repo_root)

            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with self.assertRaisesRegex(
                    module.CandidateValidationError,
                    r"Unable to resolve stable tag .* remote origin",
                ):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_head_mismatch_against_remote_tag_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "tracked.txt").write_text("new commit\n", encoding="utf-8")
            run(["git", "add", "tracked.txt"], cwd=repo_root)
            run(["git", "commit", "-m", "Advance head"], cwd=repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with self.assertRaisesRegex(module.CandidateValidationError, "must match the remote stable tag commit"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                    )

    def test_main_writes_candidate_release_metadata_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root, build_number="4")
            output_path = Path(temp_dir_name) / "SourceComplianceOverrides.json"
            args = argparse.Namespace(
                repo_root=repo_root,
                marketing_version="1.2.9",
                build_number="4",
                github_repository="cypherair/cypherair",
                output_metadata_file=output_path,
                require_stable_release="YES",
            )

            with mock.patch.object(module, "parse_args", return_value=args):
                with mock.patch.object(module, "stable_release_exists", return_value=True):
                    module.main()

            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                {
                    "commit_sha": head_sha(repo_root),
                    "stable_release_tag": "cypherair-v1.2.9-build4",
                    "stable_release_url": "https://github.com/cypherair/cypherair/releases/tag/cypherair-v1.2.9-build4",
                },
            )

    def test_main_does_not_write_metadata_when_validation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            run(["git", "checkout", "-b", "feature"], cwd=repo_root)
            output_path = Path(temp_dir_name) / "SourceComplianceOverrides.json"
            args = argparse.Namespace(
                repo_root=repo_root,
                marketing_version="1.2.9",
                build_number="4",
                github_repository="cypherair/cypherair",
                output_metadata_file=output_path,
                require_stable_release="YES",
            )

            with mock.patch.object(module, "parse_args", return_value=args):
                with self.assertRaises(SystemExit):
                    module.main()

            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
