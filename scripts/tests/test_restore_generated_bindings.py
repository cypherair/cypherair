from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT


SCRIPT_RELATIVE_PATH = "scripts/restore_generated_bindings.sh"
CARRIED_DIR_NAME = "cypherair-generated-bindings"
CARRIED_BINDINGS = {
    "Sources/PgpMobile/pgp_mobile.swift": "public func encrypt() {}\n",
    "bindings/module.modulemap": "module PgpMobileFFI {}\n",
    "bindings/pgp_mobileFFI.h": "void pgp_mobile_encrypt(void);\n",
}


class RestoreGeneratedBindingsTests(unittest.TestCase):
    def make_checkout(self, root: Path, carried: dict[str, str] | None = None) -> Path:
        """A checkout holding the real script and an artifact that carries bindings.

        The script resolves the repository from its own location, so a copy in a
        temporary tree exercises the shipped bytes against a disposable root.
        """
        (root / "scripts").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / SCRIPT_RELATIVE_PATH, root / SCRIPT_RELATIVE_PATH)

        if carried is None:
            carried = CARRIED_BINDINGS
        for relative, contents in carried.items():
            path = root / "PgpMobile.xcframework" / CARRIED_DIR_NAME / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root

    def restore(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(root / SCRIPT_RELATIVE_PATH)],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_places_every_carried_binding_at_its_mirrored_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name))

            result = self.restore(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            for relative, contents in CARRIED_BINDINGS.items():
                self.assertEqual((root / relative).read_text(encoding="utf-8"), contents)
                self.assertIn(f"placed: {relative}", result.stdout)

    def test_unchanged_bindings_are_not_rewritten(self) -> None:
        # A rewritten-but-identical file costs the next Xcode build a full
        # recompile of everything downstream of the FFI surface.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name))
            self.restore(root)
            placed = root / "Sources/PgpMobile/pgp_mobile.swift"
            before = placed.stat().st_mtime_ns

            result = self.restore(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("unchanged: Sources/PgpMobile/pgp_mobile.swift", result.stdout)
            self.assertEqual(placed.stat().st_mtime_ns, before)

    def test_a_changed_carried_binding_is_placed_again(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name))
            self.restore(root)

            carried = (
                root
                / "PgpMobile.xcframework"
                / CARRIED_DIR_NAME
                / "bindings/pgp_mobileFFI.h"
            )
            carried.write_text("void pgp_mobile_encrypt(int);\n", encoding="utf-8")

            result = self.restore(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("placed: bindings/pgp_mobileFFI.h", result.stdout)
            self.assertEqual(
                (root / "bindings/pgp_mobileFFI.h").read_text(encoding="utf-8"),
                "void pgp_mobile_encrypt(int);\n",
            )

    def test_missing_carry_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name))
            shutil.rmtree(root / "PgpMobile.xcframework" / CARRIED_DIR_NAME)

            result = self.restore(root)

            self.assertEqual(result.returncode, 1)
            self.assertIn("carries no generated bindings", result.stderr)
            # The remedy has to be right in both worlds: checkouts that build the
            # crate, and the release paths that only ever restore the artifact.
            self.assertIn("./build-xcframework.sh --release", result.stderr)
            self.assertIn("obtain a current", result.stderr)
            self.assertFalse((root / "Sources/PgpMobile/pgp_mobile.swift").exists())

    def test_empty_carry_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name), carried={})
            (root / "PgpMobile.xcframework" / CARRIED_DIR_NAME).mkdir(parents=True)

            result = self.restore(root)

            self.assertEqual(result.returncode, 1)
            self.assertIn("carries no generated bindings", result.stderr)

    def test_missing_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_checkout(Path(temp_dir_name))
            shutil.rmtree(root / "PgpMobile.xcframework")

            result = self.restore(root)

            self.assertEqual(result.returncode, 1)
            self.assertIn("carries no generated bindings", result.stderr)


if __name__ == "__main__":
    unittest.main()
