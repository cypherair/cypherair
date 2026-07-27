from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import REPO_ROOT, load_script_module


module = load_script_module("xcframework_source_fingerprint", "scripts/xcframework_source_fingerprint.py")


class XCFrameworkSourceFingerprintTests(unittest.TestCase):
    def make_repo(self, root: Path) -> tuple[Path, Path]:
        crate = root / "pgp-mobile"
        (crate / "src").mkdir(parents=True)
        (crate / "tests").mkdir()
        (crate / "src" / "lib.rs").write_text("pub fn encrypt() {}\n", encoding="utf-8")
        (crate / "src" / "keys" ).mkdir()
        (crate / "src" / "keys" / "mod.rs").write_text("pub fn generate() {}\n", encoding="utf-8")
        (crate / "src" / "keys" / "tests.rs").write_text("#[test] fn t() {}\n", encoding="utf-8")
        (crate / "Cargo.toml").write_text('[package]\nname = "pgp-mobile"\n', encoding="utf-8")
        (crate / "Cargo.lock").write_text('[[package]]\nname = "pgp-mobile"\n', encoding="utf-8")
        (crate / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
        (crate / "uniffi-bindgen.rs").write_text("fn main() {}\n", encoding="utf-8")
        (crate / "tests" / "roundtrip.rs").write_text("#[test] fn t() {}\n", encoding="utf-8")

        (root / "build-xcframework.sh").write_text("#!/bin/bash\nexec build\n", encoding="utf-8")
        (root / "scripts").mkdir()
        (root / "scripts/build_apple_arm64e_xcframework.sh").write_text(
            "#!/bin/bash\nset -euo pipefail\n", encoding="utf-8"
        )
        (root / "third_party").mkdir()
        (root / "third_party/arm64e-stage1-toolchain.pin.json").write_text(
            '{"tag": "rust-arm64e-stage1-stable197"}\n', encoding="utf-8"
        )

        xcframework = root / "PgpMobile.xcframework"
        (xcframework / "macos-arm64_arm64e").mkdir(parents=True)
        (xcframework / "ios-arm64_arm64e").mkdir()
        (xcframework / "Info.plist").write_text("<plist/>\n", encoding="utf-8")
        (xcframework / "macos-arm64_arm64e" / module.SLICE_LIBRARY_NAME).write_bytes(b"macos slice")
        (xcframework / "ios-arm64_arm64e" / module.SLICE_LIBRARY_NAME).write_bytes(b"ios slice")
        return root, xcframework

    def test_written_fingerprint_matches_a_fresh_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))

            destination = module.write_fingerprint(root, xcframework)
            self.assertTrue(destination.is_file())

            payload = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(payload["schemaVersion"], module.SCHEMA_VERSION)
            self.assertIn("pgp-mobile/src/lib.rs", payload["files"])
            self.assertIn("pgp-mobile/Cargo.lock", payload["files"])

            module.check_fingerprint(root, xcframework)

    def test_edited_crate_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (root / "pgp-mobile/src/lib.rs").write_text("pub fn encrypt() { todo!() }\n", encoding="utf-8")

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("stale", str(raised.exception))
            self.assertIn("pgp-mobile/src/lib.rs", str(raised.exception))
            self.assertIn(module.SYNC_COMMAND, str(raised.exception))

    def test_deleted_crate_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (root / "pgp-mobile/src/keys/mod.rs").unlink()

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("pgp-mobile/src/keys/mod.rs", str(raised.exception))
            self.assertIn(module.SYNC_COMMAND, str(raised.exception))

    def test_added_crate_source_appears_in_the_regenerated_input_list(self) -> None:
        # --check re-hashes only what was recorded, because the Xcode build
        # phase is sandboxed and cannot walk the crate. A file added without a
        # sync surfaces as a diff in the tracked input list instead, and in
        # practice it also edits an existing module file, which the hashes catch.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)
            before = (root / module.INPUT_LIST_NAME).read_text(encoding="utf-8")

            (root / "pgp-mobile/src/pqc.rs").write_text("pub fn ml_kem() {}\n", encoding="utf-8")
            module.write_fingerprint(root, xcframework)
            after = (root / module.INPUT_LIST_NAME).read_text(encoding="utf-8")

            self.assertNotEqual(before, after)
            self.assertIn("$(SRCROOT)/pgp-mobile/src/pqc.rs", after)

    def test_every_file_the_check_reads_is_declared_to_the_sandbox(self) -> None:
        # The build phase may read only what the input list declares, so an
        # undeclared read is a denied read and a broken build.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            opened: list[Path] = []
            original = module._hash_file

            def recording_hash(path: Path) -> str:
                opened.append(Path(path))
                return original(path)

            with mock.patch.object(module, "_hash_file", recording_hash):
                module.check_fingerprint(root, xcframework)

            declared = {
                line.strip().replace("$(SRCROOT)/", "")
                for line in (root / module.INPUT_LIST_NAME).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
            self.assertTrue(opened)
            undeclared = [
                path.relative_to(root).as_posix()
                for path in opened
                if path.relative_to(root).as_posix() not in declared
            ]
            self.assertEqual(undeclared, [])

    def test_check_never_walks_the_tree(self) -> None:
        # Directory enumeration is denied under the build sandbox: declaring a
        # directory grants readdir on it, not subpath reads. Any walk here would
        # mean the phase fails on a machine where the check is meant to pass.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            def refuse(*args, **kwargs):
                raise AssertionError("check_fingerprint must not enumerate directories")

            with mock.patch.object(Path, "rglob", refuse), mock.patch.object(
                Path, "glob", refuse
            ), mock.patch.object(os, "walk", refuse), mock.patch.object(os, "listdir", refuse):
                module.check_fingerprint(root, xcframework)

    def test_changed_cargo_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (root / "pgp-mobile/Cargo.lock").write_text(
                '[[package]]\nname = "pgp-mobile"\nversion = "0.2.0"\n', encoding="utf-8"
            )

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("pgp-mobile/Cargo.lock", str(raised.exception))

    def test_rust_test_only_edits_do_not_require_a_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (root / "pgp-mobile/tests/roundtrip.rs").write_text(
                "#[test] fn t() { assert!(true) }\n", encoding="utf-8"
            )
            # `mod tests` files inside src are #[cfg(test)] only and never reach
            # the packaged staticlib.
            (root / "pgp-mobile/src/keys/tests.rs").write_text(
                "#[test] fn t() { assert!(true) }\n", encoding="utf-8"
            )

            module.check_fingerprint(root, xcframework)

    def test_non_rust_files_under_src_are_not_inputs(self) -> None:
        # A stray .DS_Store must not break every build, nor land a gitignored
        # path in the tracked input list.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            (root / "pgp-mobile/src/.DS_Store").write_bytes(b"\x00\x01finder junk")
            (root / "pgp-mobile/src/notes.md").write_text("scratch\n", encoding="utf-8")

            module.write_fingerprint(root, xcframework)
            recorded = json.loads(
                module.fingerprint_path(xcframework).read_text(encoding="utf-8")
            )["files"]
            listed = (root / module.INPUT_LIST_NAME).read_text(encoding="utf-8")

            self.assertNotIn("pgp-mobile/src/.DS_Store", recorded)
            self.assertNotIn("pgp-mobile/src/notes.md", recorded)
            self.assertNotIn(".DS_Store", listed)
            self.assertNotIn("notes.md", listed)

            (root / "pgp-mobile/src/.DS_Store").write_bytes(b"\x00\x02finder moved a window")
            module.check_fingerprint(root, xcframework)

    def test_build_script_change_requires_a_rebuild(self) -> None:
        # The build scripts and the compiler pin decide how identical sources
        # are compiled and packaged.
        for relative in (
            "build-xcframework.sh",
            "scripts/build_apple_arm64e_xcframework.sh",
            "third_party/arm64e-stage1-toolchain.pin.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp_dir_name:
                root, xcframework = self.make_repo(Path(temp_dir_name))
                module.write_fingerprint(root, xcframework)

                path = root / relative
                path.write_text(path.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

                with self.assertRaises(module.FingerprintError) as raised:
                    module.check_fingerprint(root, xcframework)
                self.assertIn(relative, str(raised.exception))

    def test_slice_bytes_must_match_the_fingerprint(self) -> None:
        # Binds the fingerprint to the artifact: source hashes alone would still
        # pass if the slices came from a different build.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (xcframework / "macos-arm64_arm64e" / module.SLICE_LIBRARY_NAME).write_bytes(
                b"slice from another build"
            )

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            message = str(raised.exception)
            self.assertIn("does not match its own fingerprint", message)
            self.assertIn("macos-arm64_arm64e/libpgp_mobile.a", message)

    def test_missing_slice_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            (xcframework / "ios-arm64_arm64e" / module.SLICE_LIBRARY_NAME).unlink()

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("slice is missing", str(raised.exception))

    def test_fingerprint_without_slices_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            destination = module.write_fingerprint(root, xcframework)

            payload = json.loads(destination.read_text(encoding="utf-8"))
            payload.pop("slices")
            destination.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("records no XCFramework slices", str(raised.exception))

    def test_missing_fingerprint_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn(module.FINGERPRINT_NAME, str(raised.exception))
            self.assertIn(module.SYNC_COMMAND, str(raised.exception))

    def test_malformed_fingerprint_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.fingerprint_path(xcframework).write_text("{not json", encoding="utf-8")

            with self.assertRaises(module.FingerprintError):
                module.check_fingerprint(root, xcframework)

    def test_missing_xcframework_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            (xcframework / "Info.plist").unlink()

            with self.assertRaises(module.FingerprintError) as raised:
                module.check_fingerprint(root, xcframework)
            self.assertIn("missing", str(raised.exception))

    def test_missing_crate_input_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            (root / "pgp-mobile/build.rs").unlink()

            with self.assertRaises(module.FingerprintError) as raised:
                module.write_fingerprint(root, xcframework)
            self.assertIn("pgp-mobile/build.rs", str(raised.exception))

    def test_repository_inputs_resolve(self) -> None:
        # The declared inputs must exist in the real crate, or the gate would
        # fail closed on every build for the wrong reason.
        relative = {
            path.relative_to(REPO_ROOT).as_posix() for path in module.collect_input_files(REPO_ROOT)
        }
        for name in module.INPUT_FILES:
            self.assertIn(name, relative)
        self.assertTrue(any(name.startswith("pgp-mobile/src/") for name in relative))


if __name__ == "__main__":
    unittest.main()
