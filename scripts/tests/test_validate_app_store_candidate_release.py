from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import create_annotated_stable_tag, head_sha, init_repo_with_remote, load_script_module, run


stage1_module = load_script_module(
    "validate_arm64e_stage1_toolchain",
    "scripts/validate_arm64e_stage1_toolchain.py",
)
module = load_script_module(
    "validate_app_store_candidate_release",
    "scripts/validate_app_store_candidate_release.py",
)


def test_stage1_pin(release_tag: str) -> object:
    return stage1_module.Stage1ReleasePin(
        tag=release_tag,
        repository="cypherair/rust",
        source_ref="refs/heads/carry/test-stable-1.97",
        source_commit="a" * 40,
    )


def write_stage1_pin(repo_root: Path, release_tag: str) -> object:
    pin = test_stage1_pin(release_tag)
    pin_path = repo_root / "third_party" / "arm64e-stage1-toolchain.pin.json"
    pin_path.parent.mkdir(parents=True, exist_ok=True)
    pin_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "dependencyName": "rust-arm64e-stage1-toolchain",
                "repository": pin.repository,
                "release": {
                    "tag": pin.tag,
                    "sourceRef": pin.source_ref,
                    "commitSha": pin.source_commit,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return pin


def valid_rust_stage1_manifest(release_tag: str) -> dict[str, object]:
    host_triple = "aarch64-apple-darwin"
    pin = test_stage1_pin(release_tag)
    return {
        "schemaVersion": stage1_module.EXPECTED_SCHEMA_VERSION,
        "releaseTag": release_tag,
        "sourceRepository": pin.repository,
        "sourceRef": pin.source_ref,
        "sourceCommit": pin.source_commit,
        "checkedOutCommit": pin.source_commit,
        "stableBaseRelease": stage1_module.EXPECTED_STABLE_BASE_RELEASE,
        "stableBaseCommit": stage1_module.EXPECTED_STABLE_BASE_COMMIT,
        "requiresBuildStd": False,
        "hostTriple": host_triple,
        "includedHostStdTarget": host_triple,
        "includedPrebuiltStdTargets": [
            host_triple,
            *stage1_module.PROJECT_REQUIRED_ARM64E_TARGETS,
        ],
        "includedAppleArm64eTargets": list(
            stage1_module.PROJECT_REQUIRED_ARM64E_TARGETS
        ),
        "stage1RustcVersionVerbose": (
            "rustc 1.97.0\n"
            f"host: {host_triple}\n"
            f"LLVM version: {stage1_module.EXPECTED_LLVM_VERSION}"
        ),
        "packagedLlcVersionVerbose": (
            f"LLVM version {stage1_module.EXPECTED_LLVM_VERSION}"
        ),
        "llvmProvenance": {
            "sourceKind": stage1_module.EXPECTED_LLVM_SOURCE_KIND,
            "downloadCiLlvm": False,
            "gitlinkCommit": stage1_module.EXPECTED_LLVM_GITLINK_COMMIT,
            "checkedOutCommit": stage1_module.EXPECTED_LLVM_GITLINK_COMMIT,
            "sourceVersion": stage1_module.EXPECTED_LLVM_VERSION,
            "llvmConfigVersion": stage1_module.EXPECTED_LLVM_VERSION,
            "rustcReportedVersion": stage1_module.EXPECTED_LLVM_VERSION,
            "llcReportedVersion": stage1_module.EXPECTED_LLVM_VERSION,
            "packagedIdentityFile": (
                stage1_module.EXPECTED_LLVM_IDENTITY_RELATIVE_PATH
            ),
        },
        "asset": {"purpose": stage1_module.EXPECTED_ASSET_PURPOSE},
    }


def valid_arm64e_manifest(release_tag: str) -> dict[str, object]:
    return {
        "dependencyChain": {
            "opensslSrc": {"resolvedCommit": "be17d917"},
            "openssl": {"submoduleCommit": "d228bf84"},
        },
        "rustStage1": valid_rust_stage1_manifest(release_tag),
        "xcframework": {
            "requiredSlicesPresent": True,
            "libraries": [
                {
                    "supportedPlatform": "ios",
                    "supportedPlatformVariant": "",
                    "supportedArchitectures": ["arm64", "arm64e"],
                },
                {
                    "supportedPlatform": "ios",
                    "supportedPlatformVariant": "simulator",
                    "supportedArchitectures": ["arm64"],
                },
                {
                    "supportedPlatform": "macos",
                    "supportedPlatformVariant": "",
                    "supportedArchitectures": ["arm64", "arm64e"],
                },
                {
                    "supportedPlatform": "xros",
                    "supportedPlatformVariant": "",
                    "supportedArchitectures": ["arm64", "arm64e"],
                },
                {
                    "supportedPlatform": "xros",
                    "supportedPlatformVariant": "simulator",
                    "supportedArchitectures": ["arm64"],
                },
            ],
        },
    }


def replace_nested(payload: dict[str, object], path: tuple[str, ...], value: object) -> None:
    current = payload
    for key in path[:-1]:
        nested = current[key]
        if not isinstance(nested, dict):
            raise AssertionError(f"test fixture path is not an object: {path}")
        current = nested
    current[path[-1]] = value


class ValidateAppStoreCandidateReleaseTests(unittest.TestCase):
    def test_pinned_rust_stage1_release_cross_checks_machine_pin_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root = Path(temp_dir_name)
            pin = write_stage1_pin(
                repo_root,
                "rust-arm64e-stage1-stable197-test",
            )
            status_path = repo_root / "docs" / "ARM64E_STATUS.md"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(
                "- **Pinned prerelease tag:** `rust-arm64e-stage1-stable197-test`\n",
                encoding="utf-8",
            )

            self.assertEqual(
                module.pinned_rust_stage1_release(repo_root),
                pin,
            )

    def test_pinned_rust_stage1_release_tag_rejects_ambiguous_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root = Path(temp_dir_name)
            write_stage1_pin(repo_root, "rust-arm64e-stage1-stable197-test")
            status_path = repo_root / "docs" / "ARM64E_STATUS.md"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(
                "\n".join(
                    [
                        "- **Pinned prerelease tag:** `rust-arm64e-stage1-first`",
                        "- **Pinned prerelease tag:** `rust-arm64e-stage1-second`",
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                module.CandidateValidationError,
                "exactly one pinned Rust stage1",
            ):
                module.pinned_rust_stage1_release(repo_root)

    def test_pinned_rust_stage1_release_tag_rejects_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root = Path(temp_dir_name)
            write_stage1_pin(repo_root, "rust-arm64e-stage1-stable197-test")
            status_path = repo_root / "docs" / "ARM64E_STATUS.md"
            status_path.parent.mkdir(parents=True)
            status_path.write_bytes(b"\xff")

            with self.assertRaisesRegex(
                module.CandidateValidationError,
                "Unable to read canonical arm64e status",
            ):
                module.pinned_rust_stage1_release(repo_root)

    def test_pinned_rust_stage1_release_rejects_docs_machine_pin_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root = Path(temp_dir_name)
            write_stage1_pin(repo_root, "rust-arm64e-stage1-stable197-machine")
            status_path = repo_root / "docs" / "ARM64E_STATUS.md"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(
                "- **Pinned prerelease tag:** `rust-arm64e-stage1-stable197-docs`\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                module.CandidateValidationError,
                "status and Rust stage1 machine pin disagree",
            ):
                module.pinned_rust_stage1_release(repo_root)

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
                    "pinned_rust_stage1_release",
                    return_value=test_stage1_pin(
                        "rust-arm64e-stage1-stable197-test"
                    ),
                ):
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

    def test_candidate_passes_canonical_stage1_tag_to_manifest_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            stage1_tag = "rust-arm64e-stage1-stable197-canonical-test"
            stage1_pin = write_stage1_pin(repo_root, stage1_tag)
            status_path = repo_root / "docs" / "ARM64E_STATUS.md"
            status_path.parent.mkdir(parents=True)
            status_path.write_text(
                f"- **Pinned prerelease tag:** `{stage1_tag}`\n",
                encoding="utf-8",
            )

            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(
                    module,
                    "canonical_repository_url",
                    return_value=str(canonical_remote),
                ):
                    with mock.patch.object(
                        module,
                        "validate_stable_release_arm64e_manifest",
                    ) as validate_manifest:
                        validated_tag = module.validate_candidate_release(
                            repo_root=repo_root,
                            marketing_version="1.2.9",
                            build_number="3",
                            repository_full_name="cypherair/cypherair",
                            require_stable_release=True,
                            require_arm64e_release_manifest=True,
                        )

            self.assertEqual(validated_tag, release_tag)
            validate_manifest.assert_called_once_with(
                "cypherair/cypherair",
                release_tag,
                stage1_pin,
            )

    def test_valid_arm64e_manifest_payload_passes(self) -> None:
        release_tag = "rust-arm64e-stage1-stable197-test"
        module.validate_arm64e_manifest_payload(
            valid_arm64e_manifest(release_tag),
            test_stage1_pin(release_tag),
        )

    def test_arm64e_manifest_rejects_missing_rust_stage1_provenance(self) -> None:
        release_tag = "rust-arm64e-stage1-stable197-test"
        payload = valid_arm64e_manifest(release_tag)
        del payload["rustStage1"]

        with self.assertRaisesRegex(
            module.CandidateValidationError,
            "invalid Rust stage1 provenance",
        ):
            module.validate_arm64e_manifest_payload(
                payload,
                test_stage1_pin(release_tag),
            )

    def test_arm64e_manifest_rejects_weakened_or_mismatched_stage1_provenance(self) -> None:
        release_tag = "rust-arm64e-stage1-stable197-test"
        cases = (
            (("rustStage1", "schemaVersion"), 2),
            (("rustStage1", "releaseTag"), "rust-arm64e-stage1-other"),
            (("rustStage1", "sourceRepository"), "upstream/rust"),
            (("rustStage1", "sourceRef"), "carry/cypherair-arm64e-toolchain-stable-1.97"),
            (("rustStage1", "sourceCommit"), "0" * 40),
            (("rustStage1", "stableBaseCommit"), "0" * 40),
            (("rustStage1", "llvmProvenance", "sourceKind"), "download-ci-llvm"),
            (("rustStage1", "llvmProvenance", "downloadCiLlvm"), True),
            (("rustStage1", "llvmProvenance", "gitlinkCommit"), "0" * 40),
            (("rustStage1", "llvmProvenance", "checkedOutCommit"), "0" * 40),
            (("rustStage1", "llvmProvenance", "sourceVersion"), "22.1.8"),
            (("rustStage1", "llvmProvenance", "rustcReportedVersion"), "22.1.8"),
            (("rustStage1", "llvmProvenance", "llcReportedVersion"), "22.1.8"),
            (
                ("rustStage1", "llvmProvenance", "packagedIdentityFile"),
                "lib/rustlib/untrusted.json",
            ),
        )

        for path, weakened_value in cases:
            with self.subTest(path=path):
                payload = valid_arm64e_manifest(release_tag)
                replace_nested(payload, path, weakened_value)
                with self.assertRaisesRegex(
                    module.CandidateValidationError,
                    "invalid Rust stage1 provenance",
                ):
                    module.validate_arm64e_manifest_payload(
                        payload,
                        test_stage1_pin(release_tag),
                    )

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
                require_sqlcipher_release_pin="NO",
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
                require_sqlcipher_release_pin="NO",
            )

            with mock.patch.object(module, "parse_args", return_value=args):
                with self.assertRaises(SystemExit):
                    module.main()

            self.assertFalse(output_path.exists())


    def test_xcode_cloud_detached_head_matching_tag_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            run(["git", "checkout", release_tag], cwd=repo_root)
            ci_env = {
                "CI_XCODE_CLOUD": "TRUE",
                "CI_TAG": release_tag,
                "CI_COMMIT": head_sha(repo_root),
            }
            with mock.patch.dict(module.os.environ, ci_env):
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

    def test_sqlcipher_dependency_gate_runs_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            create_annotated_stable_tag(repo_root)
            with mock.patch.object(module, "stable_release_exists", return_value=True):
                with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                    with mock.patch.object(
                        module,
                        "validate_sqlcipher_dependency",
                        side_effect=module.CandidateValidationError("missing SQLCipher"),
                    ):
                        with self.assertRaisesRegex(module.CandidateValidationError, "missing SQLCipher"):
                            module.validate_candidate_release(
                                repo_root=repo_root,
                                marketing_version="1.2.9",
                                build_number="3",
                                repository_full_name="cypherair/cypherair",
                                require_stable_release=True,
                                require_arm64e_release_manifest=False,
                                require_sqlcipher_release_pin=True,
                            )

    def test_xcode_cloud_tag_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, canonical_remote = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            run(["git", "checkout", release_tag], cwd=repo_root)
            ci_env = {
                "CI_XCODE_CLOUD": "TRUE",
                "CI_TAG": "cypherair-v1.2.9-build999",
                "CI_COMMIT": head_sha(repo_root),
            }
            with mock.patch.dict(module.os.environ, ci_env):
                with mock.patch.object(module, "stable_release_exists", return_value=True):
                    with mock.patch.object(module, "canonical_repository_url", return_value=str(canonical_remote)):
                        with self.assertRaisesRegex(
                            module.CandidateValidationError,
                            "does not match the App Store candidate tag",
                        ):
                            module.validate_candidate_release(
                                repo_root=repo_root,
                                marketing_version="1.2.9",
                                build_number="3",
                                repository_full_name="cypherair/cypherair",
                                require_stable_release=True,
                                require_arm64e_release_manifest=False,
                            )

    def test_xcode_cloud_commit_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            run(["git", "checkout", release_tag], cwd=repo_root)
            ci_env = {
                "CI_XCODE_CLOUD": "TRUE",
                "CI_TAG": release_tag,
                "CI_COMMIT": "0" * 40,
            }
            with mock.patch.dict(module.os.environ, ci_env):
                with self.assertRaisesRegex(
                    module.CandidateValidationError,
                    "HEAD does not match CI_COMMIT",
                ):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                        require_arm64e_release_manifest=False,
                    )

    def test_local_detached_head_without_xcode_cloud_still_requires_main(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            repo_root, _ = init_repo_with_remote(Path(temp_dir_name))
            release_tag = create_annotated_stable_tag(repo_root)
            run(["git", "checkout", release_tag], cwd=repo_root)
            with mock.patch.dict(module.os.environ, {"CI_XCODE_CLOUD": ""}):
                with self.assertRaisesRegex(module.CandidateValidationError, "main branch"):
                    module.validate_candidate_release(
                        repo_root=repo_root,
                        marketing_version="1.2.9",
                        build_number="3",
                        repository_full_name="cypherair/cypherair",
                        require_stable_release=True,
                        require_arm64e_release_manifest=False,
                    )


if __name__ == "__main__":
    unittest.main()
