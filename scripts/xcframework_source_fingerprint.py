#!/usr/bin/env python3
"""Record and verify which pgp-mobile sources produced PgpMobile.xcframework.

The Xcode "Check PgpMobile XCFramework" build phase used to check only that the
artifact exists. Existence says nothing about currency: editing pgp-mobile/src
and rebuilding the app silently links yesterday's static library and yesterday's
generated UniFFI bindings.

This script closes that hole with a fingerprint of the crate inputs that feed
the artifact. scripts/build_apple_arm64e_xcframework.sh writes the fingerprint
at the end of a successful build (--write); the Xcode build phase and CI verify
it (--check).

The fingerprint lives *inside* the bundle
(PgpMobile.xcframework/cypherair-source-fingerprint.json) so it travels through
every path the artifact already takes -- `ditto -c -k` of the bundle, the CI
artifact upload, the edge release asset, and the Xcode Cloud release consumer --
without any new asset plumbing. A restored-from-zip artifact therefore keeps
proving its provenance against the checkout it is being linked into.

--write also refreshes PgpMobileSourceInputs.xcfilelist, the tracked list of
crate inputs the Xcode build phase declares. Script build phases run under
ENABLE_USER_SCRIPT_SANDBOXING, which permits reading only declared inputs, so
--check re-hashes exactly the files the fingerprint recorded and never walks the
tree. A crate file added without re-running the sync therefore shows up as a
diff in the tracked input list rather than as a silent pass -- and in practice
it also edits an existing module file, which the hashes catch directly.

Both modes fail closed: a missing fingerprint, an unreadable fingerprint, a
missing input file, or any content change is an error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
FINGERPRINT_NAME = "cypherair-source-fingerprint.json"
INPUT_LIST_NAME = "PgpMobileSourceInputs.xcfilelist"
SYNC_COMMAND = "./build-xcframework.sh --release"
SCHEMA_VERSION = 1

# Inputs that determine the compiled library and the generated UniFFI bindings.
# pgp-mobile/tests and pgp-mobile/examples are deliberately excluded: they never
# reach the packaged artifact, and including them would force a 40-minute
# rebuild for test-only edits (see .claude/skills/rust-sync).
INPUT_DIRECTORIES = ("pgp-mobile/src",)
INPUT_FILES = (
    "pgp-mobile/Cargo.toml",
    "pgp-mobile/Cargo.lock",
    "pgp-mobile/build.rs",
    "pgp-mobile/uniffi-bindgen.rs",
)


class FingerprintError(RuntimeError):
    """A fingerprint could not be computed, read, or matched."""


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_input_files(repo_root: Path) -> list[Path]:
    """Return the crate input files, sorted by repository-relative path."""
    collected: list[Path] = []

    for relative in INPUT_DIRECTORIES:
        directory = repo_root / relative
        if not directory.is_dir():
            raise FingerprintError(f"crate input directory is missing: {relative}")
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_symlink():
                collected.append(path)

    for relative in INPUT_FILES:
        path = repo_root / relative
        if not path.is_file():
            raise FingerprintError(f"crate input file is missing: {relative}")
        collected.append(path)

    return sorted(collected, key=lambda path: path.relative_to(repo_root).as_posix())


def aggregate_digest(entries: dict[str, str]) -> str:
    """Fold a path -> file digest map into one order-independent digest."""
    aggregate = hashlib.sha256()
    for relative in sorted(entries):
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(entries[relative].encode("ascii"))
        aggregate.update(b"\0")
    return aggregate.hexdigest()


def hash_relative_paths(repo_root: Path, relative_paths: list[str]) -> dict[str, str]:
    """Hash an explicit path list. Used by --check, which must not walk."""
    entries: dict[str, str] = {}
    for relative in relative_paths:
        path = repo_root / relative
        if not path.is_file():
            raise FingerprintError(
                f"recorded crate input is missing from this checkout: {relative}\n"
                f"       Run the XCFramework sync: {SYNC_COMMAND}"
            )
        try:
            entries[relative] = _hash_file(path)
        except OSError as error:
            raise FingerprintError(f"unable to read crate input {relative}: {error}") from error
    return entries


def compute_fingerprint(repo_root: Path) -> dict:
    """Hash every crate input into a stable, path-ordered digest."""
    relative_paths = [
        path.relative_to(repo_root).as_posix() for path in collect_input_files(repo_root)
    ]
    entries = hash_relative_paths(repo_root, relative_paths)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": "scripts/xcframework_source_fingerprint.py",
        "syncCommand": SYNC_COMMAND,
        "sourceDigest": aggregate_digest(entries),
        "fileCount": len(entries),
        "files": entries,
    }


def fingerprint_path(xcframework: Path) -> Path:
    return xcframework / FINGERPRINT_NAME


def render_input_list(entries: dict[str, str]) -> str:
    """The Xcode input list that lets the sandboxed build phase read the crate."""
    header = (
        "# Generated by scripts/xcframework_source_fingerprint.py --write.\n"
        "# Declares the pgp-mobile inputs the sandboxed \"Check PgpMobile XCFramework\"\n"
        f"# build phase is allowed to read. Refreshed by {SYNC_COMMAND}; commit it with\n"
        "# the generated bindings.\n"
    )
    return header + "".join(f"$(SRCROOT)/{relative}\n" for relative in sorted(entries))


def write_fingerprint(repo_root: Path, xcframework: Path) -> Path:
    if not xcframework.is_dir():
        raise FingerprintError(f"XCFramework is missing: {xcframework}")

    payload = compute_fingerprint(repo_root)
    destination = fingerprint_path(xcframework)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (repo_root / INPUT_LIST_NAME).write_text(render_input_list(payload["files"]), encoding="utf-8")
    return destination


def _load_recorded(destination: Path) -> dict:
    if not destination.is_file():
        raise FingerprintError(
            f"{destination.parent.name} has no source fingerprint ({FINGERPRINT_NAME}).\n"
            f"       The artifact predates this gate or was assembled by hand.\n"
            f"       Run the XCFramework sync: {SYNC_COMMAND}"
        )
    try:
        recorded = json.loads(destination.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise FingerprintError(f"source fingerprint is unreadable: {destination} ({error})") from error
    if not isinstance(recorded, dict) or not isinstance(recorded.get("sourceDigest"), str):
        raise FingerprintError(f"source fingerprint is malformed: {destination}")
    return recorded


def check_fingerprint(repo_root: Path, xcframework: Path) -> None:
    if not (xcframework / "Info.plist").is_file():
        raise FingerprintError(
            f"PgpMobile.xcframework is missing. Run the XCFramework sync: {SYNC_COMMAND}"
        )

    recorded = _load_recorded(fingerprint_path(xcframework))
    recorded_files = recorded.get("files")
    if not isinstance(recorded_files, dict) or not recorded_files:
        raise FingerprintError(
            f"source fingerprint records no crate inputs: {fingerprint_path(xcframework)}"
        )

    # Re-hash exactly what was recorded. The Xcode build phase runs sandboxed
    # and may only read the inputs it declares, so this must not walk the tree.
    current_files = hash_relative_paths(repo_root, sorted(recorded_files))

    if recorded["sourceDigest"] == aggregate_digest(current_files):
        return

    details = [
        relative
        for relative in sorted(recorded_files)
        if recorded_files[relative] != current_files.get(relative)
    ]
    listed = "\n".join(f"         - {relative}" for relative in details[:20])
    if len(details) > 20:
        listed += f"\n         - ... and {len(details) - 20} more"

    raise FingerprintError(
        "PgpMobile.xcframework is stale: it was built from different pgp-mobile sources\n"
        "       than this checkout. The linked static library and the generated UniFFI\n"
        "       bindings do not match the crate.\n"
        f"       Run the XCFramework sync: {SYNC_COMMAND}\n"
        f"       Changed crate inputs ({len(details)}):\n{listed}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="record the fingerprint into the XCFramework")
    mode.add_argument("--check", action="store_true", help="verify the recorded fingerprint against the crate")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--xcframework",
        type=Path,
        default=None,
        help="path to PgpMobile.xcframework (defaults to <repo-root>/PgpMobile.xcframework)",
    )
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    xcframework = (args.xcframework or (repo_root / "PgpMobile.xcframework")).resolve()

    try:
        if args.write:
            destination = write_fingerprint(repo_root, xcframework)
            print(f"recorded XCFramework source fingerprint: {destination}")
        else:
            check_fingerprint(repo_root, xcframework)
            print("PgpMobile.xcframework matches the pgp-mobile sources in this checkout")
    except FingerprintError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
