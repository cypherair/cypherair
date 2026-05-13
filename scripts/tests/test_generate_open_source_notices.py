from __future__ import annotations

import tempfile
import unittest
import importlib.util
import sys
from pathlib import Path

from support import REPO_ROOT


def load_generate_open_source_notices_module():
    module_path = REPO_ROOT / "scripts/generate_open_source_notices.py"
    spec = importlib.util.spec_from_file_location("generate_open_source_notices", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = load_generate_open_source_notices_module()


class GenerateOpenSourceNoticesTests(unittest.TestCase):
    def test_reachable_packages_unions_filtered_platform_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            crate_root = Path(temp_dir_name)
            metadata_ios = self.metadata(
                crate_root=crate_root,
                dependency_ids=["apple-dep 1.0.0", "proc-macro-dep 1.0.0", "build-only-dep 1.0.0"],
                dependency_kinds={
                    "apple-dep 1.0.0": [{"kind": None}],
                    "proc-macro-dep 1.0.0": [{"kind": None}],
                    "build-only-dep 1.0.0": [{"kind": "build"}],
                },
            )
            metadata_macos = self.metadata(
                crate_root=crate_root,
                dependency_ids=["mac-dep 1.0.0"],
                dependency_kinds={"mac-dep 1.0.0": [{"kind": None}]},
            )

            packages = module.reachable_packages([metadata_ios, metadata_macos])
            ids = {package.id for package in packages}
            direct_ids = {package.id for package in packages if package.is_direct_dependency}

            self.assertEqual(
                ids,
                {
                    "apple-dep@1.0.0",
                    "mac-dep@1.0.0",
                    "openssl-src@300.6.0+3.6.2",
                },
            )
            self.assertEqual(direct_ids, {"apple-dep@1.0.0", "mac-dep@1.0.0"})

    def test_apple_notice_targets_exclude_non_apple_platforms(self) -> None:
        self.assertIn("aarch64-apple-ios", module.APPLE_NOTICE_TARGETS)
        self.assertIn("aarch64-apple-visionos", module.APPLE_NOTICE_TARGETS)
        self.assertNotIn("wasm32-unknown-unknown", module.APPLE_NOTICE_TARGETS)
        self.assertNotIn("x86_64-pc-windows-msvc", module.APPLE_NOTICE_TARGETS)

    def metadata(
        self,
        *,
        crate_root: Path,
        dependency_ids: list[str],
        dependency_kinds: dict[str, list[dict]],
    ) -> dict:
        packages = [
            self.package(crate_root, "root", "pgp-mobile", "0.1.0", dependencies=dependency_ids),
            self.package(crate_root, "apple-dep 1.0.0", "apple-dep", "1.0.0"),
            self.package(crate_root, "mac-dep 1.0.0", "mac-dep", "1.0.0"),
            self.package(crate_root, "build-only-dep 1.0.0", "build-only-dep", "1.0.0"),
            self.package(
                crate_root,
                "proc-macro-dep 1.0.0",
                "proc-macro-dep",
                "1.0.0",
                target_kind="proc-macro",
            ),
            self.package(crate_root, "unused-dep 1.0.0", "unused-dep", "1.0.0"),
            self.package(crate_root, "openssl-src 300.6.0+3.6.2", "openssl-src", "300.6.0+3.6.2"),
        ]
        return {
            "packages": packages,
            "resolve": {
                "nodes": [
                    {
                        "id": "root",
                        "deps": [
                            {
                                "pkg": dependency_id,
                                "dep_kinds": dependency_kinds[dependency_id],
                            }
                            for dependency_id in dependency_ids
                        ],
                    },
                    *[{"id": package["id"], "deps": []} for package in packages if package["id"] != "root"],
                ]
            },
        }

    def package(
        self,
        crate_root: Path,
        package_id: str,
        name: str,
        version: str,
        *,
        dependencies: list[str] | None = None,
        target_kind: str = "lib",
    ) -> dict:
        dependency_names = [dependency_id.rsplit(" ", 1)[0] for dependency_id in dependencies or []]
        return {
            "id": package_id,
            "name": name,
            "version": version,
            "license": "MIT",
            "repository": f"https://github.com/example/{name}",
            "manifest_path": str(crate_root / name / "Cargo.toml"),
            "targets": [{"kind": [target_kind]}],
            "dependencies": [
                {
                    "name": dependency_name,
                    "kind": None,
                }
                for dependency_name in dependency_names
            ],
        }


if __name__ == "__main__":
    unittest.main()
