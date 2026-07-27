from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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
        (crate / "Cargo.toml").write_text('[package]\nname = "pgp-mobile"\n', encoding="utf-8")
        (crate / "Cargo.lock").write_text('[[package]]\nname = "pgp-mobile"\n', encoding="utf-8")
        (crate / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
        (crate / "uniffi-bindgen.rs").write_text("fn main() {}\n", encoding="utf-8")
        (crate / "tests" / "roundtrip.rs").write_text("#[test] fn t() {}\n", encoding="utf-8")

        xcframework = root / "PgpMobile.xcframework"
        xcframework.mkdir()
        (xcframework / "Info.plist").write_text("<plist/>\n", encoding="utf-8")
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

    def test_input_list_declares_every_recorded_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            destination = module.write_fingerprint(root, xcframework)

            recorded = json.loads(destination.read_text(encoding="utf-8"))["files"]
            listed = {
                line.strip()
                for line in (root / module.INPUT_LIST_NAME).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
            self.assertEqual(listed, {f"$(SRCROOT)/{name}" for name in recorded})

    def test_check_does_not_walk_the_crate(self) -> None:
        # Reading an undeclared path is what the build sandbox denies, so the
        # check must touch nothing beyond the recorded input list.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root, xcframework = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root, xcframework)

            opened: list[str] = []
            original = module._hash_file

            def recording_hash(path: Path) -> str:
                opened.append(Path(path).as_posix())
                return original(path)

            module._hash_file = recording_hash
            try:
                module.check_fingerprint(root, xcframework)
            finally:
                module._hash_file = original

            recorded = json.loads(
                module.fingerprint_path(xcframework).read_text(encoding="utf-8")
            )["files"]
            self.assertEqual(
                sorted(opened),
                sorted((root / name).as_posix() for name in recorded),
            )

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

            module.check_fingerprint(root, xcframework)

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
