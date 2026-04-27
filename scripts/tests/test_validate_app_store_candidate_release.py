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
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    validated_tag = module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                        require_arm64e_release_manifest=False,
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
                        require_arm64e_release_manifest=False,
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
                        require_arm64e_release_manifest=False,
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
                        require_arm64e_release_manifest=False,
                    )

    def test_untracked_files_do_not_block_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "notes.txt").write_text("scratch\n", encoding="utf-8")
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                        require_arm64e_release_manifest=False,
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
                        require_arm64e_release_manifest=False,
                    )

    def test_fork_origin_tag_mismatch_does_not_override_canonical_stable_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            repo_root, canonical_remote = init_repo_with_remote(temp_root)
            release_tag = create_annotated_stable_tag(repo_root)
            fork_remote = temp_root / "fork.git"
            fork_work = temp_root / "fork-work"

            run(["git", "init", "--bare", str(fork_remote)])
            run(["git", "init", "-b", "main", str(fork_work)])
            run(["git", "config", "user.name", "Codex Tests"], cwd=fork_work)
            run(["git", "config", "user.email", "codex-tests@example.com"], cwd=fork_work)
            (fork_work / "tracked.txt").write_text("fork\n", encoding="utf-8")
            run(["git", "add", "tracked.txt"], cwd=fork_work)
            run(["git", "commit", "-m", "Fork commit"], cwd=fork_work)
            run(["git", "tag", "-a", release_tag, "-m", "fork tag"], cwd=fork_work)
            run(["git", "remote", "add", "origin", str(fork_remote)], cwd=fork_work)
            run(["git", "push", "-u", "origin", "main"], cwd=fork_work)
            run(["git", "push", "origin", release_tag], cwd=fork_work)
            run(["git", "remote", "set-url", "origin", str(fork_remote)], cwd=repo_root)

            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    validated_tag = module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                        require_arm64e_release_manifest=False,
                    )
            self.assertEqual(validated_tag, release_tag)

    def test_head_mismatch_against_remote_tag_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            (repo_root / "tracked.txt").write_text("new commit\n", encoding="utf-8")
            run(["git", "add", "tracked.txt"], cwd=repo_root)
            run(["git", "commit", "-m", "Advance head"], cwd=repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    with self.assertRaisesRegex(module.CandidateValidationError, "must match the remote stable tag commit"):
                        module.validate_candidate_release(
                            repo_root=repo_root,
                            marketing_version="1.2.9",
                            build_number="3",
                            repository_full_name="cypherair/cypherair",
                            require_stable_release=True,
                            require_arm64e_release_manifest=False,
                        )

    def test_missing_canonical_stable_tag_fails_even_when_origin_has_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_root = Path(temp_dir_name)
            repo_root, _ = init_repo_with_remote(temp_root)
            create_annotated_stable_tag(repo_root)
            canonical_remote = temp_root / "canonical-without-tag.git"
            run(["git", "init", "--bare", str(canonical_remote)])

            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    with self.assertRaisesRegex(module.CandidateValidationError, "was not found on canonical repository"):
                        module.validate_candidate_release(
                            repo_root=repo_root,
                            marketing_version="1.2.9",
                            build_number="3",
                            repository_full_name="cypherair/cypherair",
                            require_stable_release=True,
                            require_arm64e_release_manifest=False,
                        )

    def test_arm64e_release_manifest_is_required_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(
                    module,
                    "validate_stable_release_arm64e_manifest",
                    side_effect=module.CandidateValidationError("missing arm64e manifest"),
                ):
                    with self.assertRaisesRegex(module.CandidateValidationError, "missing arm64e manifest"):
                        module.validate_candidate_release(
                            repo_root=repo_root,
                            marketing_version="1.2.9",
                            build_number="3",
                            repository_full_name="cypherair/cypherair",
                            require_stable_release=True,
                            require_arm64e_release_manifest=True,
                        )

    def test_valid_arm64e_manifest_payload_passes(self) -> None:
        payload = {
            "dependencyChain": {
                "opensslSrc": {"resolvedCommit": "be17d917"},
                "openssl": {"submoduleCommit": "d228bf84"},
            },
            "rustStage1": {"releaseTag": "rust-arm64e-stage1-test"},
            "xcframework": {
                "requiredSlicesPresent": True,
                "libraries": [
                    {"supportedPlatform": "ios", "supportedPlatformVariant": "", "supportedArchitectures": ["arm64", "arm64e"]},
                    {"supportedPlatform": "ios", "supportedPlatformVariant": "simulator", "supportedArchitectures": ["arm64"]},
                    {"supportedPlatform": "macos", "supportedPlatformVariant": "", "supportedArchitectures": ["arm64", "arm64e"]},
                    {"supportedPlatform": "xros", "supportedPlatformVariant": "", "supportedArchitectures": ["arm64", "arm64e"]},
                    {"supportedPlatform": "xros", "supportedPlatformVariant": "simulator", "supportedArchitectures": ["arm64"]},
                ],
            },
        }
        module.validate_arm64e_manifest_payload(payload)

    def test_main_writes_candidate_release_metadata_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root, build_number="4")
            output_path = Path(temp_dir_name) / "SourceComplianceOverrides.json"
            args = argparse.Namespace(
                repo_root=repo_root,
                marketing_version="1.2.9",
                build_number="4",
                github_repository="cypherair/cypherair",
                output_metadata_file=output_path,
                require_stable_release="YES",
                require_arm64e_release_manifest="NO",
            )

            with mock.patch.object(module, "parse_args", return_value=args):
                with mock.patch.object(module, "stable_release_exists", return_value=True):
                    with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
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
                require_arm64e_release_manifest="NO",
            )

            with mock.patch.object(module, "parse_args", return_value=args):
                with self.assertRaises(SystemExit):
                    module.main()

            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
