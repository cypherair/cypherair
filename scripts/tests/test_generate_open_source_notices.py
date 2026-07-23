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

    def test_reachable_packages_marks_only_resolved_direct_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            crate_root = Path(temp_dir_name)
            metadata = self.metadata(
                crate_root=crate_root,
                dependency_ids=["base64 0.23.0", "apple-dep 1.0.0"],
                dependency_kinds={
                    "base64 0.23.0": [{"kind": None}],
                    "apple-dep 1.0.0": [{"kind": None}],
                },
            )
            metadata["packages"].extend(
                [
                    self.package(crate_root, "base64 0.23.0", "base64", "0.23.0"),
                    self.package(crate_root, "base64 0.22.1", "base64", "0.22.1"),
                ]
            )
            apple_node = next(
                node for node in metadata["resolve"]["nodes"] if node["id"] == "apple-dep 1.0.0"
            )
            apple_node["deps"] = [
                {
                    "pkg": "base64 0.22.1",
                    "dep_kinds": [{"kind": None}],
                }
            ]
            metadata["resolve"]["nodes"].extend(
                [
                    {"id": "base64 0.23.0", "deps": []},
                    {"id": "base64 0.22.1", "deps": []},
                ]
            )

            packages = module.reachable_packages([metadata])
            direct_by_id = {package.id: package.is_direct_dependency for package in packages}

            self.assertTrue(direct_by_id["base64@0.23.0"])
            self.assertFalse(direct_by_id["base64@0.22.1"])

    def test_apple_notice_targets_exclude_non_apple_platforms(self) -> None:
        self.assertIn("aarch64-apple-ios", module.APPLE_NOTICE_TARGETS)
        self.assertIn("aarch64-apple-visionos", module.APPLE_NOTICE_TARGETS)
        self.assertNotIn("wasm32-unknown-unknown", module.APPLE_NOTICE_TARGETS)
        self.assertNotIn("x86_64-pc-windows-msvc", module.APPLE_NOTICE_TARGETS)

    def test_combine_license_texts_strips_trailing_whitespace(self) -> None:
        combined = module.combine_license_texts(
            [
                ("LICENSE-A", "alpha  \n\nbeta\t\n"),
                ("LICENSE-B", "gamma  "),
            ]
        )

        for line in combined.splitlines():
            self.assertEqual(line, line.rstrip(" \t"))
        self.assertIn("alpha\n\nbeta\n", combined)
        self.assertIn("gamma\n", combined)
        self.assertTrue(combined.endswith("\n"))

    def test_external_sqlcipher_notices_are_project_file_records(self) -> None:
        notices = module.build_notice_manifest([], {})
        sqlcipher = next(notice for notice in notices if notice["id"] == "sqlcipher@4.17.0")
        sqlite = next(notice for notice in notices if notice["id"] == "sqlite@3.53.3")

        self.assertEqual(sqlcipher["licenseName"], "BSD-3-Clause")
        self.assertEqual(sqlcipher["licenseSourceKind"], "projectFile")
        self.assertEqual(sqlcipher["licenseFileResourceName"], "SQLCipher-4.17.0.txt")
        self.assertTrue(sqlcipher["isDirectDependency"])
        self.assertEqual(sqlite["licenseName"], "Public Domain")
        self.assertEqual(sqlite["licenseSourceKind"], "projectFile")
        self.assertEqual(sqlite["licenseFileResourceName"], "SQLite-3.53.3.txt")
        self.assertTrue(sqlite["isDirectDependency"])

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
