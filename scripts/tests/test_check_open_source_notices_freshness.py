from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT, load_script_module


module = load_script_module(
    "check_open_source_notices_freshness", "scripts/check_open_source_notices_freshness.py"
)


CARGO_LOCK = """\
version = 4

[[package]]
name = "pgp-mobile"
version = "0.1.0"

[[package]]
name = "sequoia-openpgp"
version = "2.4.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "zeroize"
version = "1.8.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


class CheckOpenSourceNoticesFreshnessTests(unittest.TestCase):
    def make_repo(self, root: Path, notices: list[dict] | None = None) -> Path:
        (root / "scripts").mkdir()
        (root / "scripts/generate_open_source_notices.py").symlink_to(
            REPO_ROOT / "scripts/generate_open_source_notices.py"
        )
        (root / "third_party").mkdir()
        (root / "third_party/sqlcipher-xcframework.pin.json").write_text(
            '{"release": {"tag": "sqlcipher-xcframework-v4.17.0-cypherair.1"}}\n', encoding="utf-8"
        )
        (root / "pgp-mobile").mkdir()
        (root / module.CARGO_LOCK).write_text(CARGO_LOCK, encoding="utf-8")
        (root / "pgp-mobile/Cargo.toml").write_text(
            '[package]\nname = "pgp-mobile"\n\n[features]\ndefault = []\n', encoding="utf-8"
        )

        notices_dir = root / module.NOTICES_DIR
        notices_dir.mkdir(parents=True)
        records = notices if notices is not None else self.default_notices()
        for record in records:
            (notices_dir / record["licenseFileResourceName"]).write_text("license\n", encoding="utf-8")
        (root / module.NOTICES_FILE).write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        return root

    def default_notices(self) -> list[dict]:
        return [
            {
                "id": "cypherair",
                "kind": "app",
                "licenseFileResourceName": "CypherAir-DUAL-LICENSE.txt",
            },
            {
                "id": "sequoia-openpgp@2.4.1",
                "kind": "thirdParty",
                "licenseFileResourceName": "sequoia-openpgp-2.4.1.txt",
            },
            {
                "id": "zeroize@1.8.2",
                "kind": "thirdParty",
                "licenseFileResourceName": "zeroize-1.8.2.txt",
            },
            {
                "id": "sqlcipher@4.17.0",
                "kind": "thirdParty",
                "licenseFileResourceName": "SQLCipher-4.17.0.txt",
            },
            {
                "id": "sqlite@3.53.3",
                "kind": "thirdParty",
                "licenseFileResourceName": "SQLite-3.53.3.txt",
            },
        ]

    def test_recorded_fingerprint_matches_a_fresh_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)
            module.check(root)

    def test_external_records_do_not_need_a_cargo_package(self) -> None:
        # SQLCipher and SQLite are injected by the generator, not resolved by
        # cargo; the gate must not demand them in Cargo.lock.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)
            module.check(root)

    def test_changed_cargo_lock_fails_with_the_regenerate_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)

            (root / module.CARGO_LOCK).write_text(
                CARGO_LOCK.replace('version = "1.8.2"', 'version = "1.8.3"'), encoding="utf-8"
            )

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            message = str(raised.exception)
            self.assertIn(module.CARGO_LOCK, message)
            self.assertIn(module.REGENERATE_COMMAND, message)

    def test_every_generation_input_is_gated(self) -> None:
        # A feature change, a SQLCipher pin bump, or a generator edit all change
        # what the notices should say, and none of them touch Cargo.lock.
        for relative in (
            "pgp-mobile/Cargo.toml",
            "third_party/sqlcipher-xcframework.pin.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp_dir_name:
                root = self.make_repo(Path(temp_dir_name))
                module.write_fingerprint(root)

                path = root / relative
                path.write_text(path.read_text(encoding="utf-8") + "\n# bumped\n", encoding="utf-8")

                with self.assertRaises(module.NoticesFreshnessError) as raised:
                    module.check(root)
                self.assertIn(relative, str(raised.exception))

    def test_generator_edit_is_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)

            # Replace the symlink with an edited copy of the generator.
            generator = root / "scripts/generate_open_source_notices.py"
            source = (REPO_ROOT / "scripts/generate_open_source_notices.py").read_text(encoding="utf-8")
            generator.unlink()
            generator.write_text(source + "\n# edited\n", encoding="utf-8")

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn("scripts/generate_open_source_notices.py", str(raised.exception))

    def test_tampered_license_text_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)

            (root / module.NOTICES_DIR / "zeroize-1.8.2.txt").write_text("", encoding="utf-8")

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn("zeroize-1.8.2.txt", str(raised.exception))

    def test_fingerprint_from_the_previous_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)

            path = root / module.FINGERPRINT_FILE
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload.pop("generationInputs")
            payload.pop("licenseTexts")
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn("predates this gate", str(raised.exception))

    def test_hand_edited_notices_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)

            notices = json.loads((root / module.NOTICES_FILE).read_text(encoding="utf-8"))
            notices[1]["id"] = "sequoia-openpgp@2.4.0"
            (root / module.NOTICES_FILE).write_text(json.dumps(notices, indent=2) + "\n", encoding="utf-8")

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn(module.NOTICES_FILE, str(raised.exception))

    def test_notice_missing_from_cargo_lock_is_reported(self) -> None:
        # Re-recording the fingerprint over a stale manifest must not launder
        # a dependency the lock file no longer resolves.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            notices = json.loads((root / module.NOTICES_FILE).read_text(encoding="utf-8"))
            notices[2]["id"] = "zeroize@1.7.0"
            (root / module.NOTICES_FILE).write_text(json.dumps(notices, indent=2) + "\n", encoding="utf-8")
            module.write_fingerprint(root)

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn("zeroize@1.7.0", str(raised.exception))

    def test_missing_license_text_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            module.write_fingerprint(root)
            (root / module.NOTICES_DIR / "zeroize-1.8.2.txt").unlink()

            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn("zeroize-1.8.2.txt", str(raised.exception))

    def test_missing_fingerprint_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name))
            with self.assertRaises(module.NoticesFreshnessError) as raised:
                module.check(root)
            self.assertIn(module.FINGERPRINT_FILE, str(raised.exception))

    def test_repository_notices_resolve_against_cargo_lock(self) -> None:
        packages = module.cargo_lock_packages(
            (REPO_ROOT / module.CARGO_LOCK).read_text(encoding="utf-8")
        )
        external = module.external_notice_ids(REPO_ROOT)
        unresolved = [
            notice["id"]
            for notice in module.load_notices(REPO_ROOT)
            if notice.get("kind") == "thirdParty"
            and notice["id"] not in external
            and notice["id"] not in packages
        ]
        self.assertEqual(unresolved, [])


if __name__ == "__main__":
    unittest.main()
