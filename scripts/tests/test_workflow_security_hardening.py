from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PINNED_STAGE1_RELEASE_TAG = "rust-arm64e-stage1-stable196-20260530T083949Z-ecc85bf-r26679152716-a1"


def read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def step_block(workflow_text: str, step_name: str) -> str:
    pattern = re.compile(
        rf"(?ms)^      - name: {re.escape(step_name)}\n"
        r".*?(?=^      - name: |^      - uses: |^  [A-Za-z0-9_-]+:|\Z)"
    )
    match = pattern.search(workflow_text)
    if match is None:
        raise AssertionError(f"Missing workflow step: {step_name}")
    return match.group(0)


def job_block(workflow_text: str, job_name: str) -> str:
    pattern = re.compile(rf"(?ms)^  {re.escape(job_name)}:\n.*?(?=^  [A-Za-z0-9_-]+:|\Z)")
    match = pattern.search(workflow_text)
    if match is None:
        raise AssertionError(f"Missing workflow job: {job_name}")
    return match.group(0)


class WorkflowSecurityHardeningTests(unittest.TestCase):
    workflows_with_xcframework_build = [
        ".github/workflows/stable-build-release.yml",
        ".github/workflows/xcframework-edge-release.yml",
        ".github/workflows/pr-checks.yml",
        ".github/workflows/nightly-full.yml",
    ]

    def test_stage1_release_tag_is_pinned_in_xcframework_workflows(self) -> None:
        for workflow in self.workflows_with_xcframework_build:
            with self.subTest(workflow=workflow):
                text = read(workflow)

                self.assertIn(f"ARM64E_STAGE1_RELEASE_TAG: {PINNED_STAGE1_RELEASE_TAG}", text)
                self.assertNotIn("ARM64E_STAGE1_RELEASE_TAG: latest", text)

    def test_xcframework_build_steps_do_not_receive_github_tokens(self) -> None:
        for workflow in self.workflows_with_xcframework_build:
            with self.subTest(workflow=workflow):
                block = step_block(read(workflow), "Build XCFramework and generated bindings")

                self.assertNotIn("GH_TOKEN:", block)
                self.assertNotIn("GITHUB_TOKEN:", block)
                self.assertIn('ARM64E_STAGE1_FORCE_DOWNLOAD: "0"', block)

    def test_stage1_download_is_separate_from_xcframework_build(self) -> None:
        for workflow in self.workflows_with_xcframework_build:
            with self.subTest(workflow=workflow):
                text = read(workflow)
                download = step_block(text, "Download arm64e stage1 toolchain")
                build = step_block(text, "Build XCFramework and generated bindings")

                self.assertLess(text.index(download), text.index(build))
                self.assertNotIn("./build-xcframework.sh --release", download)
                self.assertIn('scripts/download_arm64e_stage1_toolchain.sh "$RUNNER_TEMP/arm64e-stage1"', download)

    def test_stage1_download_steps_do_not_receive_github_tokens(self) -> None:
        for workflow in self.workflows_with_xcframework_build:
            with self.subTest(workflow=workflow):
                download = step_block(read(workflow), "Download arm64e stage1 toolchain")

                self.assertNotIn("GH_TOKEN:", download)
                self.assertNotIn("GITHUB_TOKEN:", download)

    def test_checkouts_do_not_persist_workflow_credentials(self) -> None:
        for workflow in self.workflows_with_xcframework_build:
            with self.subTest(workflow=workflow):
                text = read(workflow)
                checkout_steps = list(re.finditer(r"(?m)^      - uses: actions/checkout@", text))
                self.assertGreater(len(checkout_steps), 0)

                for index, match in enumerate(checkout_steps):
                    next_match = checkout_steps[index + 1] if index + 1 < len(checkout_steps) else None
                    end = next_match.start() if next_match else len(text)
                    block = text[match.start() : end]
                    self.assertIn("persist-credentials: false", block)

    def test_stable_workflow_dispatch_cannot_publish(self) -> None:
        text = read(".github/workflows/stable-build-release.yml")
        trigger_block = text.split("\npermissions:", 1)[0]

        self.assertNotIn("create_release:", trigger_block)
        self.assertNotIn("INPUT_CREATE_RELEASE", text)
        self.assertIn('CREATE_RELEASE="false"', text)
        self.assertIn("Validate publish source matches stable tag", text)
        self.assertIn('git rev-parse "refs/tags/$RELEASE_TAG^{commit}"', text)

    def test_stable_publish_revalidates_tag_commit_before_attestation(self) -> None:
        text = read(".github/workflows/stable-build-release.yml")
        publish_job = job_block(text, "publish-stable-release")
        revalidate = step_block(publish_job, "Revalidate stable tag before publishing")
        attestation = step_block(publish_job, "Generate artifact attestation")
        release = step_block(publish_job, "Create immutable stable release")

        self.assertLess(publish_job.index(revalidate), publish_job.index(attestation))
        self.assertLess(publish_job.index(revalidate), publish_job.index(release))
        self.assertIn('GITHUB_TOKEN: ${{ github.token }}', revalidate)
        self.assertIn('gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${RELEASE_TAG}"', revalidate)
        self.assertIn('gh api "repos/${GITHUB_REPOSITORY}/git/tags/${tag_object_sha}"', revalidate)
        self.assertIn('if [ "$tag_object_type" != "tag" ]; then', revalidate)
        self.assertIn("must be an annotated signed tag", revalidate)
        self.assertIn('verification.get("verified") is not True', revalidate)
        self.assertIn('verification.get("reason") != "valid"', revalidate)
        self.assertIn('signature.startswith("-----BEGIN SSH SIGNATURE-----")', revalidate)
        self.assertIn("tag_commit != commit_sha", revalidate)

    def test_edge_publish_is_audit_gated_and_write_scoped(self) -> None:
        text = read(".github/workflows/xcframework-edge-release.yml")
        build_job = job_block(text, "build-edge-release-assets")
        publish_job = job_block(text, "publish-edge-release")

        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("contents: write", build_job)
        self.assertIn("- rust-dependency-audit", publish_job)
        self.assertIn("- build-edge-release-assets", publish_job)
        self.assertIn("contents: write", publish_job)
        self.assertIn("id-token: write", publish_job)
        self.assertIn("attestations: write", publish_job)

    def test_edge_release_notes_and_metadata_escape_source_ref(self) -> None:
        text = read(".github/workflows/xcframework-edge-release.yml")

        self.assertIn("import shlex", text)
        self.assertIn("SOURCE_REF_SHELL", text)
        self.assertIn("json.dump(payload, handle, indent=2)", text)
        self.assertNotIn('--source-ref "$RELEASE_SOURCE_REF"', text)
        self.assertNotIn('"source_ref": "$RELEASE_SOURCE_REF"', text)

    def test_build_script_scrubs_github_tokens_from_build_subprocesses(self) -> None:
        text = read("scripts/build_apple_arm64e_xcframework.sh")

        self.assertIn("unset GH_TOKEN GITHUB_TOKEN", text)
        self.assertIn("download_arm64e_stage1_toolchain.sh", text)
        self.assertNotIn("gh release list", text)
        self.assertNotIn("gh release download", text)
        self.assertNotIn("run_with_github_token", text)
        self.assertRegex(text, r"env -u GH_TOKEN -u GITHUB_TOKEN \\\n\s+CARGO_TARGET_DIR=.*\\\n\s+cargo ")
        self.assertRegex(text, r"env -u GH_TOKEN -u GITHUB_TOKEN \\\n\s+xcodebuild -create-xcframework")
        self.assertRegex(text, r"env -u GH_TOKEN -u GITHUB_TOKEN \\\n\s+\"\$PYTHON_BIN\"")

    def test_build_script_uses_pinned_stage1_and_no_latest_discovery(self) -> None:
        text = read("scripts/build_apple_arm64e_xcframework.sh")

        self.assertIn(f'DEFAULT_ARM64E_STAGE1_RELEASE_TAG="{PINNED_STAGE1_RELEASE_TAG}"', text)
        self.assertIn("'latest' is not allowed", text)
        self.assertNotIn("latest_stage1_release_tag", text)
        self.assertNotIn("releases?per_page", text)
        self.assertNotIn("api.github.com/repos", text)

    def test_stage1_downloader_uses_pinned_direct_release_assets(self) -> None:
        text = read("scripts/download_arm64e_stage1_toolchain.sh")

        self.assertIn("unset GH_TOKEN GITHUB_TOKEN", text)
        self.assertIn(f'DEFAULT_ARM64E_STAGE1_RELEASE_TAG="{PINNED_STAGE1_RELEASE_TAG}"', text)
        self.assertIn("'latest' is not allowed", text)
        self.assertIn("/releases/download/${tag}", text)
        self.assertNotIn("GH_TOKEN=", text)
        self.assertNotIn("GITHUB_TOKEN=", text)
        self.assertNotIn("gh release list", text)
        self.assertNotIn("gh release download", text)
        self.assertNotIn("curl_github_api", text)
        self.assertNotIn("browser_download_url", text)
        self.assertNotIn("latest_stage1_release_tag", text)
        self.assertNotIn("releases?per_page", text)
        self.assertNotIn("api.github.com", text)

    def test_edge_metadata_step_exports_same_step_environment(self) -> None:
        text = read(".github/workflows/xcframework-edge-release.yml")
        package = step_block(text, "Package release assets")
        export_line = "export BUILT_AT XCODE_VERSION RUSTC_VERSION MARKETING_VERSION PROJECT_BUILD_NUMBER"

        self.assertIn(export_line, package)
        self.assertLess(package.index(export_line), package.index('python3 - "$RELEASE_METADATA"'))


if __name__ == "__main__":
    unittest.main()
