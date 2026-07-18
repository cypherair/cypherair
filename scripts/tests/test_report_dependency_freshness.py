from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from support import load_script_module

freshness = load_script_module(
    "report_dependency_freshness", "scripts/report_dependency_freshness.py"
)


CARGO_DRY_RUN_OUTPUT = """\
    Updating crates.io index
     Locking 3 packages to latest compatible versions
    Updating anstream v0.6.19 -> v0.6.21
    Updating cc v1.2.29 -> v1.2.33
      Adding brand-new v0.1.0
    Removing gone v0.9.0
    Updating serde v1.0.219 -> v1.0.226
note: pass `--verbose` to see 2 unchanged dependencies behind latest
warning: not updating lockfile due to dry run
"""


WORKFLOW_A = """\
jobs:
  one:
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - uses: ./local/composite-action
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
"""

WORKFLOW_B = """\
jobs:
  two:
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - name: attest
        uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0
      - uses: actions/setup-node@v4
"""


CARGO_TOML = """\
[dependencies]
sequoia-openpgp = { version = "=2.4.1", default-features = false, features = [
    "compression",
    "crypto-openssl",
] }
uniffi = { version = "0.32", features = ["build"] }
"""

CARGO_LOCK = """\
[[package]]
name = "ctor"
version = "1.0.9"
source = "git+https://github.com/cypherair/linktime?branch=carry%2Fapple-ctor-1.0.9#1aa46c01a33b30f3e979e4d5c0a414a2fcc56ecf"
dependencies = []

[[package]]
name = "openssl-src"
version = "300.6.1+3.6.3"
source = "git+https://github.com/cypherair/openssl-src-rs?branch=carry%2Fapple-arm64e-openssl-fork#1aea076d67ee701d3e9b9ad68177203881542868"
dependencies = []

[[package]]
name = "uniffi_core"
version = "0.32.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "uniffi"
version = "0.32.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

SQLCIPHER_PIN = {
    "repository": "cypherair/sqlcipher-xcframework",
    "release": {"tag": "sqlcipher-xcframework-v4.17.0-cypherair.1"},
}

STAGE1_PIN = {
    "dependencyName": "rust-arm64e-stage1-toolchain",
    "repository": "cypherair/rust",
    "release": {
        "tag": "rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1",
        "publishedAt": "2026-07-15T08:07:10Z",
    },
}

STAGE1_RELEASES = [
    {"tag_name": "some-other-release", "published_at": "2026-07-16T00:00:00Z"},
    {
        "tag_name": "rust-arm64e-stage1-stable197-20260701T000000Z-aaaaaaa-r1-a1",
        "published_at": "2026-07-01T00:00:00Z",
    },
    {
        "tag_name": "rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1",
        "published_at": "2026-07-15T08:07:10Z",
    },
    {
        "tag_name": "rust-arm64e-stage1-draft",
        "published_at": "2026-07-17T00:00:00Z",
        "draft": True,
    },
]


class ParserTests(unittest.TestCase):
    def test_parse_cargo_update_dry_run_counts_only_updating_rows(self) -> None:
        updates = freshness.parse_cargo_update_dry_run(CARGO_DRY_RUN_OUTPUT)

        self.assertEqual(
            [update["name"] for update in updates], ["anstream", "cc", "serde"]
        )
        self.assertEqual(updates[0], {"name": "anstream", "from": "0.6.19", "to": "0.6.21"})

    def test_parse_workflow_action_pins_dedupes_and_keeps_comment(self) -> None:
        pins = freshness.parse_workflow_action_pins({"a.yml": WORKFLOW_A, "b.yml": WORKFLOW_B})

        by_action = {pin["action"]: pin for pin in pins}
        self.assertEqual(
            sorted(by_action), ["actions/attest", "actions/checkout", "actions/upload-artifact"]
        )
        self.assertEqual(by_action["actions/checkout"]["files"], ["a.yml", "b.yml"])
        self.assertEqual(by_action["actions/attest"]["comment"], "v4.2.0")
        self.assertEqual(
            by_action["actions/upload-artifact"]["sha"],
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        )
        # Tag-pinned and local-composite `uses:` never reach the report.
        self.assertNotIn("actions/setup-node", by_action)

    def test_parse_exact_pin_reads_multiline_dependency_tables(self) -> None:
        self.assertEqual(freshness.parse_exact_pin(CARGO_TOML, "sequoia-openpgp"), "2.4.1")
        with self.assertRaises(ValueError):
            freshness.parse_exact_pin(CARGO_TOML, "uniffi")

    def test_parse_locked_version_requires_exact_package_name(self) -> None:
        self.assertEqual(freshness.parse_locked_version(CARGO_LOCK, "uniffi"), "0.32.0")
        with self.assertRaises(ValueError):
            freshness.parse_locked_version(CARGO_LOCK, "uniffi_bindgen")

    def test_latest_stage1_release_filters_prefix_and_drafts(self) -> None:
        latest = freshness.latest_stage1_release(STAGE1_RELEASES)

        self.assertIsNotNone(latest)
        self.assertEqual(
            latest["tag_name"],
            "rust-arm64e-stage1-stable197-20260715T051054Z-c405db8-r29390775624-a1",
        )
        self.assertIsNone(freshness.latest_stage1_release([{"tag_name": "unrelated"}]))

    def test_versions_equal_or_newer(self) -> None:
        self.assertTrue(freshness.versions_equal_or_newer("2.4.1", "2.4.1"))
        self.assertTrue(freshness.versions_equal_or_newer("2.4.1", "2.4.0"))
        self.assertFalse(freshness.versions_equal_or_newer("2.4.0", "2.4.1"))
        self.assertFalse(freshness.versions_equal_or_newer("0.31.2", "0.32.0"))


class ReportTests(unittest.TestCase):
    def make_repo_root(self, root: Path) -> Path:
        (root / "pgp-mobile").mkdir()
        (root / "pgp-mobile" / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
        (root / "pgp-mobile" / "Cargo.lock").write_text(CARGO_LOCK, encoding="utf-8")
        (root / "third_party").mkdir()
        (root / "third_party" / "sqlcipher-xcframework.pin.json").write_text(
            json.dumps(SQLCIPHER_PIN), encoding="utf-8"
        )
        (root / "third_party" / "arm64e-stage1-toolchain.pin.json").write_text(
            json.dumps(STAGE1_PIN), encoding="utf-8"
        )
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "a.yml").write_text(WORKFLOW_A, encoding="utf-8")
        return root

    def make_fetchers(self) -> "freshness.Fetchers":
        checkout_sha = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
        upload_new_sha = "b" * 40

        return freshness.Fetchers(
            crates_latest={"sequoia-openpgp": "2.4.1", "uniffi": "0.33.0"}.__getitem__,
            latest_release=lambda repository: {
                "cypherair/sqlcipher-xcframework": {
                    "tag_name": "sqlcipher-xcframework-v4.17.0-cypherair.1"
                },
                "actions/checkout": {"tag_name": "v7.0.0"},
                "actions/upload-artifact": {"tag_name": "v7.1.0"},
            }[repository],
            releases=lambda repository: STAGE1_RELEASES,
            tag_commit=lambda repository, tag: {
                ("actions/checkout", "v7.0.0"): checkout_sha,
                ("actions/upload-artifact", "v7.1.0"): upload_new_sha,
            }[(repository, tag)],
            branch_head=lambda repository, branch: {
                "https://github.com/cypherair/openssl-src-rs": "1aea076d67ee701d3e9b9ad68177203881542868",
                "https://github.com/cypherair/linktime": "f" * 40,
            }[repository],
            cargo_dry_run=lambda repo_root: CARGO_DRY_RUN_OUTPUT,
        )

    def test_build_report_classifies_current_update_and_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self.make_repo_root(Path(temp_dir))
            report = freshness.build_report(repo_root, self.make_fetchers())

        by_name = {entry["name"]: entry for entry in report["entries"]}

        self.assertEqual(by_name["cargo update --dry-run"]["status"], "update-available")
        self.assertIn("3 compatible updates", by_name["cargo update --dry-run"]["latest"])
        self.assertEqual(by_name["sequoia-openpgp (crates.io)"]["status"], "current")
        self.assertEqual(by_name["uniffi (crates.io)"]["status"], "update-available")
        self.assertEqual(
            by_name["SQLCipher.xcframework (cypherair/sqlcipher-xcframework)"]["status"],
            "current",
        )
        self.assertEqual(by_name["arm64e stage1 toolchain (cypherair/rust)"]["status"], "current")
        self.assertEqual(
            by_name["openssl-src carry (cypherair/openssl-src-rs)"]["status"], "current"
        )
        self.assertEqual(by_name["ctor carry (cypherair/linktime)"]["status"], "drift")
        self.assertEqual(by_name["actions/checkout (a.yml)"]["status"], "current")
        self.assertEqual(by_name["actions/upload-artifact (a.yml)"]["status"], "update-available")
        self.assertEqual(report["summary"]["unavailable"], 0)

    def test_render_text_lists_sections_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self.make_repo_root(Path(temp_dir))
            report = freshness.build_report(repo_root, self.make_fetchers())

        text = freshness.render_text(report)

        self.assertIn("CypherAir dependency freshness report", text)
        self.assertIn("Exact pins vs upstream latest", text)
        self.assertIn("Owned-fork carry refs (report-only)", text)
        self.assertIn("Pinned GitHub Actions", text)
        self.assertIn("Summary:", text)
        self.assertIn("[drift] ctor carry (cypherair/linktime)", text)

    def test_failing_fetchers_and_missing_files_never_fail_the_run(self) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise RuntimeError("network unavailable")

        fetchers = freshness.Fetchers(
            crates_latest=boom,
            latest_release=boom,
            releases=boom,
            tag_commit=boom,
            branch_head=boom,
            cargo_dry_run=boom,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            empty_root = Path(temp_dir)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = freshness.main(["--json"], repo_root=empty_root, fetchers=fetchers)

        self.assertEqual(exit_code, 0)
        report = json.loads(stdout.getvalue())
        self.assertGreater(report["summary"]["unavailable"], 0)
        self.assertEqual(report["summary"]["current"], 0)
        for entry in report["entries"]:
            self.assertEqual(entry["status"], "unavailable")

    def test_main_text_mode_exits_zero_with_populated_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = self.make_repo_root(Path(temp_dir))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = freshness.main([], repo_root=repo_root, fetchers=self.make_fetchers())

        self.assertEqual(exit_code, 0)
        self.assertIn("Summary:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
