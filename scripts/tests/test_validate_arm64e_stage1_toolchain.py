from __future__ import annotations

import copy
import json
import shlex
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from support import load_script_module


module = load_script_module(
    "validate_arm64e_stage1_toolchain",
    "scripts/validate_arm64e_stage1_toolchain.py",
)


HOST = "aarch64-apple-darwin"
RELEASE_TAG = "rust-arm64e-stage1-stable197-corrected-test"
RELEASE_PIN = module.Stage1ReleasePin(
    tag=RELEASE_TAG,
    repository="cypherair/rust",
    source_ref="refs/heads/carry/test-stable-1.97",
    source_commit="a" * 40,
)


@dataclass
class Fixture:
    manifest_path: Path
    rustc_path: Path
    identity_path: Path
    llc_path: Path
    manifest: dict[str, object]
    identity: dict[str, object]


class ValidateArm64eStage1ToolchainTests(unittest.TestCase):
    def write_json(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def write_executable(self, path: Path, contents: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def make_fixture(
        self,
        root: Path,
        *,
        actual_rustc_llvm: str = module.EXPECTED_LLVM_VERSION,
        actual_llc_llvm: str = module.EXPECTED_LLVM_VERSION,
        include_llc: bool = True,
    ) -> Fixture:
        sysroot = root / "stage1-arm64e-patch"
        rustc_path = sysroot / "bin" / "rustc"
        llc_path = sysroot / "lib" / "rustlib" / HOST / "bin" / "llc"
        identity_path = sysroot / module.EXPECTED_LLVM_IDENTITY_RELATIVE_PATH
        manifest_path = root / "stage1.json"

        published_rustc_verbose = (
            "rustc 1.97.0-dev\n"
            "binary: rustc\n"
            "commit-hash: unknown\n"
            "commit-date: unknown\n"
            f"host: {HOST}\n"
            "release: 1.97.0-dev\n"
            f"LLVM version: {module.EXPECTED_LLVM_VERSION}"
        )
        actual_rustc_verbose = published_rustc_verbose.replace(
            f"LLVM version: {module.EXPECTED_LLVM_VERSION}",
            f"LLVM version: {actual_rustc_llvm}",
        )
        published_llc_verbose = (
            "LLVM (http://llvm.org/):\n"
            f"  LLVM version {module.EXPECTED_LLVM_VERSION}-rust-publisher\n"
            "  Optimized build.\n"
            "  Host CPU: publisher-cpu"
        )

        rustc_script = f"""#!/bin/sh
if [ "$1" = "-vV" ]; then
  cat <<'EOF'
{actual_rustc_verbose}
EOF
elif [ "$1" = "--print" ] && [ "$2" = "sysroot" ]; then
  printf '%s\n' {shlex.quote(str(sysroot))}
else
  exit 2
fi
"""
        self.write_executable(rustc_path, rustc_script)

        if include_llc:
            llc_script = f"""#!/bin/sh
cat <<'EOF'
LLVM (http://llvm.org/):
  LLVM version {actual_llc_llvm}-rust-consumer
  Optimized build.
  Host CPU: consumer-cpu
EOF
"""
            self.write_executable(llc_path, llc_script)

        llvm_provenance = {
            "sourceKind": module.EXPECTED_LLVM_SOURCE_KIND,
            "downloadCiLlvm": False,
            "gitlinkCommit": module.EXPECTED_LLVM_GITLINK_COMMIT,
            "checkedOutCommit": module.EXPECTED_LLVM_GITLINK_COMMIT,
            "sourceVersion": module.EXPECTED_LLVM_VERSION,
            "llvmConfigVersion": f"{module.EXPECTED_LLVM_VERSION}-rust-source",
            "rustcReportedVersion": module.EXPECTED_LLVM_VERSION,
            "llcReportedVersion": module.EXPECTED_LLVM_VERSION,
            "packagedIdentityFile": module.EXPECTED_LLVM_IDENTITY_RELATIVE_PATH,
        }
        manifest: dict[str, object] = {
            "schemaVersion": module.EXPECTED_SCHEMA_VERSION,
            "releaseTag": RELEASE_TAG,
            "sourceRepository": RELEASE_PIN.repository,
            "sourceRef": RELEASE_PIN.source_ref,
            "sourceCommit": RELEASE_PIN.source_commit,
            "checkedOutCommit": RELEASE_PIN.source_commit,
            "stableBaseRelease": module.EXPECTED_STABLE_BASE_RELEASE,
            "stableBaseCommit": module.EXPECTED_STABLE_BASE_COMMIT,
            "requiresBuildStd": False,
            "hostTriple": HOST,
            "includedHostStdTarget": HOST,
            "stage1RustcVersionVerbose": published_rustc_verbose,
            "packagedLlcVersionVerbose": published_llc_verbose,
            "llvmProvenance": llvm_provenance,
            "asset": {"purpose": module.EXPECTED_ASSET_PURPOSE},
            "includedPrebuiltStdTargets": [HOST, *module.PROJECT_REQUIRED_ARM64E_TARGETS],
            "includedAppleArm64eTargets": list(module.PROJECT_REQUIRED_ARM64E_TARGETS),
        }
        identity: dict[str, object] = {
            "schemaVersion": 1,
            "sourceKind": module.EXPECTED_LLVM_SOURCE_KIND,
            "downloadCiLlvm": False,
            "gitlinkCommit": module.EXPECTED_LLVM_GITLINK_COMMIT,
            "checkedOutCommit": module.EXPECTED_LLVM_GITLINK_COMMIT,
            "sourceVersion": module.EXPECTED_LLVM_VERSION,
            "llvmConfigVersion": llvm_provenance["llvmConfigVersion"],
            "hostTriple": HOST,
            "tools": {
                "rustc": {
                    "llvmVersion": module.EXPECTED_LLVM_VERSION,
                    "versionVerbose": published_rustc_verbose,
                },
                "llc": {
                    "llvmVersion": module.EXPECTED_LLVM_VERSION,
                    "versionVerbose": published_llc_verbose,
                },
            },
        }
        self.write_json(manifest_path, manifest)
        self.write_json(identity_path, identity)
        return Fixture(manifest_path, rustc_path, identity_path, llc_path, manifest, identity)

    def validate(self, fixture: Fixture) -> None:
        module.validate_stage1_toolchain(
            fixture.manifest_path,
            fixture.rustc_path,
            RELEASE_PIN,
            module.PROJECT_REQUIRED_ARM64E_TARGETS,
        )

    def test_machine_pin_supplies_release_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pin_path = Path(temp_dir) / "pin.json"
            self.write_json(
                pin_path,
                {
                    "schemaVersion": 1,
                    "dependencyName": "rust-arm64e-stage1-toolchain",
                    "repository": RELEASE_PIN.repository,
                    "release": {
                        "tag": RELEASE_PIN.tag,
                        "sourceRef": RELEASE_PIN.source_ref,
                        "commitSha": RELEASE_PIN.source_commit,
                    },
                },
            )

            self.assertEqual(module.load_stage1_release_pin(pin_path), RELEASE_PIN)

    def test_machine_pin_rejects_noncanonical_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pin_path = Path(temp_dir) / "pin.json"
            self.write_json(
                pin_path,
                {
                    "schemaVersion": 1,
                    "dependencyName": "rust-arm64e-stage1-toolchain",
                    "repository": RELEASE_PIN.repository,
                    "release": {
                        "tag": RELEASE_PIN.tag,
                        "sourceRef": "carry/test-stable-1.97",
                        "commitSha": "not-a-commit",
                    },
                },
            )

            with self.assertRaisesRegex(module.Stage1ValidationError, "sourceRef"):
                module.load_stage1_release_pin(pin_path)

    def test_valid_toolchain_passes_without_comparing_runtime_llc_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            self.validate(fixture)

    def test_old_schema2_ci_llvm_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            payload = copy.deepcopy(fixture.manifest)
            payload["schemaVersion"] = 2
            payload["stage1RustcVersionVerbose"] = str(payload["stage1RustcVersionVerbose"]).replace(
                module.EXPECTED_LLVM_VERSION, "22.1.8"
            )
            payload.pop("llvmProvenance")
            self.write_json(fixture.manifest_path, payload)

            with self.assertRaisesRegex(module.Stage1ValidationError, "schemaVersion"):
                self.validate(fixture)

    def test_non_stable197_release_tag_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            unexpected_tag = "rust-arm64e-stage1-nightly-test"
            unexpected_pin = module.Stage1ReleasePin(
                tag=unexpected_tag,
                repository=RELEASE_PIN.repository,
                source_ref=RELEASE_PIN.source_ref,
                source_commit=RELEASE_PIN.source_commit,
            )
            payload = copy.deepcopy(fixture.manifest)
            payload["releaseTag"] = unexpected_tag

            with self.assertRaisesRegex(module.Stage1ValidationError, "must start with"):
                module.validate_stage1_manifest_payload(payload, unexpected_pin)

    def test_invalid_utf8_manifest_uses_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            fixture.manifest_path.write_bytes(b"\xff")

            with self.assertRaisesRegex(module.Stage1ValidationError, "unable to read"):
                self.validate(fixture)

    def test_invalid_outer_manifest_is_rejected_before_rustc_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = self.make_fixture(root)
            marker = root / "rustc-executed"
            self.write_executable(
                fixture.rustc_path,
                f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 99\n",
            )
            payload = copy.deepcopy(fixture.manifest)
            payload["schemaVersion"] = 2
            self.write_json(fixture.manifest_path, payload)

            with self.assertRaisesRegex(module.Stage1ValidationError, "schemaVersion"):
                self.validate(fixture)
            self.assertFalse(marker.exists())

    def test_invalid_inner_identity_is_rejected_before_rustc_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = self.make_fixture(root)
            marker = root / "rustc-executed"
            self.write_executable(
                fixture.rustc_path,
                f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 99\n",
            )
            identity = copy.deepcopy(fixture.identity)
            identity["gitlinkCommit"] = "0" * 40
            self.write_json(fixture.identity_path, identity)

            with self.assertRaisesRegex(module.Stage1ValidationError, "identity gitlinkCommit"):
                self.validate(fixture)
            self.assertFalse(marker.exists())

    def test_missing_or_wrong_outer_provenance_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            cases = (
                ("missing provenance", lambda value: value.pop("llvmProvenance"), "llvmProvenance"),
                (
                    "CI LLVM enabled",
                    lambda value: value["llvmProvenance"].__setitem__("downloadCiLlvm", True),
                    "downloadCiLlvm",
                ),
                (
                    "wrong gitlink",
                    lambda value: value["llvmProvenance"].__setitem__("gitlinkCommit", "0" * 40),
                    "gitlinkCommit",
                ),
                (
                    "wrong LLVM version",
                    lambda value: value["llvmProvenance"].__setitem__("sourceVersion", "22.1.8"),
                    "sourceVersion",
                ),
                (
                    "wrong Rust source",
                    lambda value: value.__setitem__("sourceCommit", "0" * 40),
                    "sourceCommit",
                ),
            )
            for label, mutate, message in cases:
                with self.subTest(label=label):
                    payload = copy.deepcopy(fixture.manifest)
                    mutate(payload)
                    self.write_json(fixture.manifest_path, payload)
                    with self.assertRaisesRegex(module.Stage1ValidationError, message):
                        self.validate(fixture)

    def test_bare_source_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            payload = copy.deepcopy(fixture.manifest)
            payload["sourceRef"] = RELEASE_PIN.source_ref.removeprefix("refs/heads/")
            self.write_json(fixture.manifest_path, payload)

            with self.assertRaisesRegex(module.Stage1ValidationError, "sourceRef"):
                self.validate(fixture)

    def test_outer_inner_identity_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            identity = copy.deepcopy(fixture.identity)
            identity["gitlinkCommit"] = "0" * 40
            self.write_json(fixture.identity_path, identity)

            with self.assertRaisesRegex(module.Stage1ValidationError, "identity gitlinkCommit"):
                self.validate(fixture)

    def test_actual_rustc_llvm_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir), actual_rustc_llvm="22.1.8")

            with self.assertRaisesRegex(module.Stage1ValidationError, "actual rustc -vV"):
                self.validate(fixture)

    def test_actual_llc_llvm_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir), actual_llc_llvm="22.1.8")

            with self.assertRaisesRegex(module.Stage1ValidationError, "actual llc LLVM version"):
                self.validate(fixture)

    def test_missing_packaged_llc_fails_without_path_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir), include_llc=False)

            with self.assertRaisesRegex(module.Stage1ValidationError, "packaged llc is missing"):
                self.validate(fixture)

    def test_wrong_host_or_identity_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            cases = (
                ("host", "hostTriple", "x86_64-apple-darwin", "HostStdTarget"),
                (
                    "path",
                    "packagedIdentityFile",
                    "../arm64e-stage1-llvm-provenance.json",
                    "packagedIdentityFile",
                ),
            )
            for label, key, value, message in cases:
                with self.subTest(label=label):
                    payload = copy.deepcopy(fixture.manifest)
                    if key == "packagedIdentityFile":
                        payload["llvmProvenance"][key] = value
                    else:
                        payload[key] = value
                    self.write_json(fixture.manifest_path, payload)
                    with self.assertRaisesRegex(module.Stage1ValidationError, message):
                        self.validate(fixture)

    def test_required_target_must_be_declared(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            payload = copy.deepcopy(fixture.manifest)
            payload["includedAppleArm64eTargets"].remove("arm64e-apple-visionos")
            self.write_json(fixture.manifest_path, payload)

            with self.assertRaisesRegex(module.Stage1ValidationError, "arm64e-apple-visionos"):
                self.validate(fixture)


if __name__ == "__main__":
    unittest.main()
