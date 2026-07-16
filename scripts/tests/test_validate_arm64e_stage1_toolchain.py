from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import subprocess
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
ASSET_BASE = f"{module.EXPECTED_ASSET_PREFIX}-{HOST}"
TAR_ASSET_NAME = f"{ASSET_BASE}.tar.zst"
SHA256_ASSET_NAME = f"{ASSET_BASE}.sha256"
MANIFEST_ASSET_NAME = f"{ASSET_BASE}.json"
TAR_ASSET_SIZE = 12345
RELEASE_PIN = module.Stage1ReleasePin(
    tag=RELEASE_TAG,
    repository="cypherair/rust",
    source_ref="refs/heads/carry/test-stable-1.97",
    source_commit="a" * 40,
    assets={
        TAR_ASSET_NAME: module.Stage1AssetPin(sha256="b" * 64, size=TAR_ASSET_SIZE),
        SHA256_ASSET_NAME: module.Stage1AssetPin(sha256="c" * 64, size=118),
        MANIFEST_ASSET_NAME: module.Stage1AssetPin(sha256="d" * 64, size=4024),
    },
)


def serialized_assets(pin: object = RELEASE_PIN) -> dict[str, dict[str, object]]:
    return {
        name: {"sha256": asset.sha256, "size": asset.size}
        for name, asset in pin.assets.items()
    }


def serialized_pin(pin: object = RELEASE_PIN) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "dependencyName": "rust-arm64e-stage1-toolchain",
        "repository": pin.repository,
        "release": {
            "tag": pin.tag,
            "sourceRef": pin.source_ref,
            "commitSha": pin.source_commit,
        },
        "assets": serialized_assets(pin),
    }


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
            "asset": {
                "purpose": module.EXPECTED_ASSET_PURPOSE,
                "fileName": TAR_ASSET_NAME,
                "sha256FileName": SHA256_ASSET_NAME,
                "sizeBytes": TAR_ASSET_SIZE,
            },
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
                serialized_pin(),
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
                    "assets": serialized_assets(),
                },
            )

            with self.assertRaisesRegex(module.Stage1ValidationError, "sourceRef"):
                module.load_stage1_release_pin(pin_path)

    def test_machine_pin_requires_valid_asset_metadata(self) -> None:
        cases = (
            ("missing assets", lambda value: value.pop("assets"), "pin assets"),
            ("empty assets", lambda value: value.__setitem__("assets", {}), "must not be empty"),
            (
                "invalid hash",
                lambda value: value["assets"][TAR_ASSET_NAME].__setitem__("sha256", "not-a-hash"),
                "sha256",
            ),
            (
                "missing size",
                lambda value: value["assets"][TAR_ASSET_NAME].pop("size"),
                "size",
            ),
            (
                "string size",
                lambda value: value["assets"][TAR_ASSET_NAME].__setitem__("size", "12345"),
                "size",
            ),
            (
                "boolean size",
                lambda value: value["assets"][TAR_ASSET_NAME].__setitem__("size", True),
                "size",
            ),
            (
                "zero size",
                lambda value: value["assets"][TAR_ASSET_NAME].__setitem__("size", 0),
                "size",
            ),
            (
                "negative size",
                lambda value: value["assets"][TAR_ASSET_NAME].__setitem__("size", -1),
                "size",
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            pin_path = Path(temp_dir) / "pin.json"
            for label, mutate, message in cases:
                with self.subTest(label=label):
                    payload = serialized_pin()
                    mutate(payload)
                    self.write_json(pin_path, payload)
                    with self.assertRaisesRegex(module.Stage1ValidationError, message):
                        module.load_stage1_release_pin(pin_path)

    def test_invalid_asset_contract_is_rejected_before_rustc_executes(self) -> None:
        cases = (
            (
                "wrong archive name",
                lambda value: value["asset"].__setitem__("fileName", "wrong.tar.zst"),
                "asset.fileName",
            ),
            (
                "wrong checksum name",
                lambda value: value["asset"].__setitem__("sha256FileName", "wrong.sha256"),
                "asset.sha256FileName",
            ),
            (
                "wrong byte size",
                lambda value: value["asset"].__setitem__("sizeBytes", TAR_ASSET_SIZE + 1),
                "asset.sizeBytes",
            ),
            (
                "boolean byte size",
                lambda value: value["asset"].__setitem__("sizeBytes", True),
                "asset.sizeBytes",
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = self.make_fixture(root)
            marker = root / "rustc-executed"
            self.write_executable(
                fixture.rustc_path,
                f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 99\n",
            )
            for label, mutate, message in cases:
                with self.subTest(label=label):
                    payload = copy.deepcopy(fixture.manifest)
                    mutate(payload)
                    self.write_json(fixture.manifest_path, payload)
                    with self.assertRaisesRegex(module.Stage1ValidationError, message):
                        self.validate(fixture)
                    self.assertFalse(marker.exists())

    def test_manifest_requires_all_host_assets_in_machine_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = self.make_fixture(Path(temp_dir))
            for missing_name in (TAR_ASSET_NAME, SHA256_ASSET_NAME, MANIFEST_ASSET_NAME):
                with self.subTest(missing_name=missing_name):
                    assets = dict(RELEASE_PIN.assets)
                    del assets[missing_name]
                    incomplete_pin = module.Stage1ReleasePin(
                        tag=RELEASE_PIN.tag,
                        repository=RELEASE_PIN.repository,
                        source_ref=RELEASE_PIN.source_ref,
                        source_commit=RELEASE_PIN.source_commit,
                        assets=assets,
                    )
                    with self.assertRaisesRegex(
                        module.Stage1ValidationError,
                        "missing required host asset",
                    ):
                        module.validate_stage1_manifest_payload(
                            fixture.manifest,
                            incomplete_pin,
                        )

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
                assets=RELEASE_PIN.assets,
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

    def test_plain_build_ignores_implicit_rustup_stage1_link(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "scripts" / "build_apple_arm64e_xcframework.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            linked_rustc = root / "stage1-arm64e-patch" / "bin" / "rustc"
            rustc_marker = root / "linked-rustc-executed"

            self.write_executable(
                linked_rustc,
                f"#!/bin/sh\ntouch {shlex.quote(str(rustc_marker))}\n",
            )
            self.write_executable(
                fake_bin / "rustup",
                f"""#!/bin/sh
if [ "$1" = "toolchain" ] && [ "$2" = "list" ]; then
  printf '%s\\n' 'stable-aarch64-apple-darwin (active, default)'
  printf '%s\\n' 'stage1-arm64e-patch'
  exit 0
fi
if [ "$1" = "which" ] && [ "$2" = "--toolchain" ] && [ "$3" = "stage1-arm64e-patch" ]; then
  printf '%s\\n' {shlex.quote(str(linked_rustc))}
  exit 0
fi
exit 1
""",
            )
            for command in ("cargo", "curl", "lipo", "xcodebuild", "bsdtar", "zstd"):
                self.write_executable(fake_bin / command, "#!/bin/sh\nexit 0\n")

            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["ARM64E_STAGE1_RELEASE_TAG"] = "latest"
            environment["ARM64E_STAGE1_FORCE_DOWNLOAD"] = "0"
            for name in (
                "LOCAL_ARM64E_TOOLCHAIN",
                "ARM64E_RUSTC",
                "ARM64E_STAGE1_DIR",
                "ARM64E_RUST_STAGE1_MANIFEST",
            ):
                environment.pop(name, None)

            completed = subprocess.run(
                ["bash", str(script_path), "--release"],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("'latest' is not allowed", completed.stderr)
            self.assertNotIn("ARM64E_RUST_STAGE1_MANIFEST is required", completed.stderr)
            self.assertFalse(rustc_marker.exists())

    def test_downloader_rejects_correct_hash_with_wrong_size_before_extraction(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "scripts" / "download_arm64e_stage1_toolchain.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            release_dir = root / "release"
            fake_bin = root / "bin"
            release_dir.mkdir()
            fake_bin.mkdir()
            extraction_marker = root / "extraction-attempted"

            tar_bytes = b"valid archive bytes for a size-gate regression"
            tar_digest = hashlib.sha256(tar_bytes).hexdigest()
            release_assets = {
                TAR_ASSET_NAME: tar_bytes,
                SHA256_ASSET_NAME: f"{tar_digest}  {TAR_ASSET_NAME}\n".encode(),
                MANIFEST_ASSET_NAME: b"{}\n",
            }
            pin_assets: dict[str, dict[str, object]] = {}
            for asset_name, contents in release_assets.items():
                asset_path = release_dir / asset_name
                asset_path.write_bytes(contents)
                pin_assets[asset_name] = {
                    "sha256": hashlib.sha256(contents).hexdigest(),
                    "size": len(contents),
                }
            pin_assets[TAR_ASSET_NAME]["size"] = len(tar_bytes) + 1

            pin_path = root / "pin.json"
            pin_payload = serialized_pin()
            pin_payload["assets"] = pin_assets
            self.write_json(pin_path, pin_payload)

            self.write_executable(
                fake_bin / "rustc",
                f"#!/bin/sh\nprintf '%s\\n' 'host: {HOST}'\n",
            )
            self.write_executable(
                fake_bin / "curl",
                """#!/bin/sh
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
cp "$FAKE_RELEASE_DIR/${url##*/}" "$output"
""",
            )
            for command in ("zstd", "bsdtar"):
                self.write_executable(
                    fake_bin / command,
                    f"#!/bin/sh\ntouch {shlex.quote(str(extraction_marker))}\nexit 99\n",
                )

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "FAKE_RELEASE_DIR": str(release_dir),
                    "ARM64E_STAGE1_PIN_FILE": str(pin_path),
                    "ARM64E_STAGE1_RELEASE_TAG": RELEASE_PIN.tag,
                    "ARM64E_RUST_REPOSITORY": RELEASE_PIN.repository,
                }
            )
            environment.pop("GITHUB_ENV", None)
            environment.pop("GITHUB_OUTPUT", None)
            completed = subprocess.run(
                ["bash", str(script_path), str(root / "output")],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                f"{TAR_ASSET_NAME} size {len(tar_bytes)} != pinned {len(tar_bytes) + 1}",
                completed.stderr,
            )
            self.assertFalse(extraction_marker.exists())

    def test_authenticated_verifier_rejects_wrong_size_before_asset_attestation(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        script_path = repo_root / "scripts" / "verify_arm64e_stage1_release.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            download_dir = root / "download"
            fake_bin = root / "bin"
            download_dir.mkdir()
            fake_bin.mkdir()
            gh_log = root / "gh.log"

            asset_bytes = b"correct digest but deliberately wrong pinned size"
            asset_path = download_dir / TAR_ASSET_NAME
            asset_path.write_bytes(asset_bytes)
            pin_path = root / "pin.json"
            pin_payload = serialized_pin()
            pin_payload["release"].update(
                {
                    "isPrerelease": True,
                    "signerWorkflow": "cypherair/rust/.github/workflows/test.yml",
                }
            )
            pin_payload["assets"] = {
                TAR_ASSET_NAME: {
                    "sha256": hashlib.sha256(asset_bytes).hexdigest(),
                    "size": len(asset_bytes) + 1,
                }
            }
            self.write_json(pin_path, pin_payload)

            release_json = json.dumps(
                {
                    "tagName": RELEASE_PIN.tag,
                    "isDraft": False,
                    "isPrerelease": True,
                    "isImmutable": True,
                    "targetCommitish": RELEASE_PIN.source_commit,
                    "url": f"https://github.com/{RELEASE_PIN.repository}/releases/tag/{RELEASE_PIN.tag}",
                }
            )
            self.write_executable(
                fake_bin / "gh",
                f"""#!/bin/sh
printf '%s\\n' "$*" >> "$GH_LOG"
if [ "$1" = "release" ] && [ "$2" = "view" ]; then
  cat <<'EOF'
{release_json}
EOF
fi
exit 0
""",
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "GH_LOG": str(gh_log),
                    "ARM64E_STAGE1_PIN_FILE": str(pin_path),
                }
            )
            completed = subprocess.run(
                ["bash", str(script_path), str(download_dir)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                f"{TAR_ASSET_NAME} size {len(asset_bytes)} != pinned {len(asset_bytes) + 1}",
                completed.stderr,
            )
            gh_commands = gh_log.read_text(encoding="utf-8")
            self.assertNotIn("release verify-asset", gh_commands)
            self.assertNotIn("attestation verify", gh_commands)


if __name__ == "__main__":
    unittest.main()
