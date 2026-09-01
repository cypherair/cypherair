#!/usr/bin/env python3
"""Record and verify which pgp-mobile sources produced PgpMobile.xcframework.

Existence says nothing about currency: without this gate, editing pgp-mobile/src
and rebuilding the app links yesterday's static library and compiles yesterday's
generated UniFFI bindings. The gate is a fingerprint of the crate inputs that
feed the artifact, bound to the packaged library bytes and the generated
bindings those inputs produced.
scripts/build_apple_arm64e_xcframework.sh writes the fingerprint at the end of a
successful build (--write); the Xcode build phase and CI verify it (--check).

The fingerprint lives *inside* the bundle
(PgpMobile.xcframework/cypherair-source-fingerprint.json) so it travels through
every path the artifact already takes -- `ditto -c -k` of the bundle, the CI
artifact upload, the edge release asset, and the Xcode Cloud release consumer --
without any new asset plumbing. A restored-from-zip artifact therefore keeps
proving its provenance against the checkout it is being linked into.

The generated bindings ride in the bundle too, under cypherair-generated-bindings/
at the repository-relative paths they are placed at. --check verifies both ends
of that copy: the bundle still carries the bindings it recorded, and the
working-tree copies the app compiles are those exact bytes. An unplaced restore,
a bundle from another build, and a hand-edit to the generated Swift are all
build failures rather than a silently wrong FFI surface.

--write also refreshes PgpMobileSourceInputs.xcfilelist, the list of everything
--check reads. Script build phases run under ENABLE_USER_SCRIPT_SANDBOXING,
which permits reading only declared inputs, so --check re-hashes exactly what
the fingerprint recorded and never walks the tree. The list is tracked at the
repository root because Xcode resolves it while building the dependency graph,
before any build phase runs -- a list inside the ignored bundle would replace
the phase's own missing-artifact guidance with a file-list load failure. A crate
file added without re-running the sync is still caught, because adding one also
edits an existing module file, and the hashes catch that directly.

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
CARRIED_BINDINGS_DIR = "cypherair-generated-bindings"
SYNC_COMMAND = "./build-xcframework.sh --release"
RESTORE_COMMAND = "scripts/restore_generated_bindings.sh"
SCHEMA_VERSION = 2

# Inputs that determine the compiled library and the generated UniFFI bindings.
# pgp-mobile/tests and pgp-mobile/examples are deliberately excluded: they never
# reach the packaged artifact, and including them would force a rebuild for
# test-only edits (see docs/BUILD.md §6).
#
# Only *.rs is collected from the source directories. Anything else there is not
# a compilation input, and hashing it would let a stray .DS_Store both break
# every build and land gitignored junk in the tracked input list.
INPUT_DIRECTORIES = ("pgp-mobile/src",)
INPUT_SUFFIX = ".rs"
# `mod tests` files are compiled only under #[cfg(test)] and never reach the
# packaged staticlib, so they are excluded for the same reason as
# pgp-mobile/tests.
EXCLUDED_INPUT_NAMES = ("tests.rs",)
INPUT_FILES = (
    "pgp-mobile/Cargo.toml",
    "pgp-mobile/Cargo.lock",
    "pgp-mobile/build.rs",
    "pgp-mobile/uniffi-bindgen.rs",
    # The build scripts and the pinned compiler decide how the crate is
    # compiled and packaged, so a change to any of them can produce a different
    # artifact from identical crate sources.
    "build-xcframework.sh",
    "scripts/build_apple_arm64e_xcframework.sh",
    "third_party/arm64e-stage1-toolchain.pin.json",
)
SLICE_LIBRARY_NAME = "libpgp_mobile.a"


class FingerprintError(RuntimeError):
    """A fingerprint could not be computed, read, or matched."""


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_or_none(path: Path) -> str | None:
    """The digest, or None when the file is absent or unreadable.

    Both cases mean the same thing to a comparison against a recorded digest --
    this content is not there -- and collapsing them keeps every caller
    fail-closed without a second error path.
    """
    if not path.is_file():
        return None
    try:
        return _hash_file(path)
    except OSError:
        return None


def collect_input_files(repo_root: Path) -> list[Path]:
    """Return the crate input files, sorted by repository-relative path."""
    collected: list[Path] = []

    for relative in INPUT_DIRECTORIES:
        directory = repo_root / relative
        if not directory.is_dir():
            raise FingerprintError(f"crate input directory is missing: {relative}")
        for path in directory.rglob(f"*{INPUT_SUFFIX}"):
            if not path.is_file() or path.is_symlink():
                continue
            if path.name in EXCLUDED_INPUT_NAMES:
                continue
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


def collect_slice_libraries(xcframework: Path) -> list[Path]:
    """Every per-platform static library inside the bundle."""
    return sorted(
        path
        for path in xcframework.glob(f"*/{SLICE_LIBRARY_NAME}")
        if path.is_file() and not path.is_symlink()
    )


def hash_slice_libraries(xcframework: Path, relative_paths: list[str] | None = None) -> dict[str, str]:
    """Hash the slices, so the fingerprint is bound to the bytes it describes."""
    if relative_paths is None:
        paths = collect_slice_libraries(xcframework)
    else:
        paths = [xcframework / relative for relative in relative_paths]

    entries: dict[str, str] = {}
    for path in paths:
        if not path.is_file():
            raise FingerprintError(
                f"XCFramework slice is missing: {path.name} "
                f"({path.relative_to(xcframework.parent).as_posix()})\n"
                f"       Run the XCFramework sync: {SYNC_COMMAND}"
            )
        try:
            entries[path.relative_to(xcframework).as_posix()] = _hash_file(path)
        except OSError as error:
            raise FingerprintError(f"unable to read XCFramework slice {path.name}: {error}") from error
    return entries


def carried_bindings_dir(xcframework: Path) -> Path:
    return xcframework / CARRIED_BINDINGS_DIR


def hash_carried_bindings(xcframework: Path) -> dict[str, str]:
    """Hash the generated bindings the bundle carries.

    The carry layout mirrors the checkout, so a carried path *is* the path the
    binding is placed at. That is what lets --check and the restore script agree
    on every destination without either of them naming a file.
    """
    directory = carried_bindings_dir(xcframework)
    if not directory.is_dir():
        raise FingerprintError(
            f"XCFramework carries no generated bindings ({CARRIED_BINDINGS_DIR}/): {xcframework}"
        )

    entries: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            entries[path.relative_to(directory).as_posix()] = _hash_file(path)
        except OSError as error:
            raise FingerprintError(f"unable to read carried binding {path.name}: {error}") from error

    if not entries:
        raise FingerprintError(
            f"XCFramework carries no generated bindings ({CARRIED_BINDINGS_DIR}/ is empty): {xcframework}"
        )
    return entries


def compute_fingerprint(repo_root: Path, xcframework: Path) -> dict:
    """Hash every crate input, packaged slice, and carried binding."""
    relative_paths = [
        path.relative_to(repo_root).as_posix() for path in collect_input_files(repo_root)
    ]
    entries = hash_relative_paths(repo_root, relative_paths)
    slices = hash_slice_libraries(xcframework)
    if not slices:
        raise FingerprintError(
            f"XCFramework contains no {SLICE_LIBRARY_NAME} slices: {xcframework}"
        )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": "scripts/xcframework_source_fingerprint.py",
        "syncCommand": SYNC_COMMAND,
        "sourceDigest": aggregate_digest(entries),
        "fileCount": len(entries),
        "files": entries,
        "artifactDigest": aggregate_digest(slices),
        "slices": slices,
        "bindings": hash_carried_bindings(xcframework),
    }


def fingerprint_path(xcframework: Path) -> Path:
    return xcframework / FINGERPRINT_NAME


def render_input_list(
    entries: dict[str, str], slices: dict[str, str], bindings: dict[str, str]
) -> str:
    """The Xcode input list that lets the sandboxed build phase read its inputs.

    Script build phases run under ENABLE_USER_SCRIPT_SANDBOXING and may read
    only declared inputs, and declaring a directory grants readdir rather than
    subpath access -- so every file --check re-hashes has to appear here by
    name: the crate inputs, the packaged slices, and both ends of every carried
    binding.
    """
    header = (
        "# Generated by scripts/xcframework_source_fingerprint.py --write.\n"
        "# Declares everything the sandboxed \"Check PgpMobile XCFramework\"\n"
        "# build phase is allowed to read.\n"
        f"# Refreshed by {SYNC_COMMAND}; commit it when it changes.\n"
    )
    lines = [f"$(SRCROOT)/{relative}\n" for relative in sorted(entries)]
    lines += [f"$(SRCROOT)/PgpMobile.xcframework/{relative}\n" for relative in sorted(slices)]
    lines += [
        f"$(SRCROOT)/PgpMobile.xcframework/{CARRIED_BINDINGS_DIR}/{relative}\n"
        for relative in sorted(bindings)
    ]
    lines += [f"$(SRCROOT)/{relative}\n" for relative in sorted(bindings)]
    return header + "".join(lines)


def write_fingerprint(repo_root: Path, xcframework: Path) -> Path:
    if not xcframework.is_dir():
        raise FingerprintError(f"XCFramework is missing: {xcframework}")

    payload = compute_fingerprint(repo_root, xcframework)
    destination = fingerprint_path(xcframework)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (repo_root / INPUT_LIST_NAME).write_text(
        render_input_list(payload["files"], payload["slices"], payload["bindings"]),
        encoding="utf-8",
    )
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


def check_recorded_slices(recorded: dict, xcframework: Path) -> None:
    """The fingerprint must describe the bytes it ships next to.

    Without this, a valid-looking fingerprint could sit beside slices from a
    different build -- copied in, restored from an older release, or left over
    from a partial sync -- and the source hashes alone would still pass.
    """
    recorded_slices = recorded.get("slices")
    if not isinstance(recorded_slices, dict) or not recorded_slices:
        raise FingerprintError(
            f"source fingerprint records no XCFramework slices: {fingerprint_path(xcframework)}\n"
            f"       The artifact predates this gate. Run the XCFramework sync: {SYNC_COMMAND}"
        )

    current_slices = hash_slice_libraries(xcframework, sorted(recorded_slices))
    if recorded.get("artifactDigest") == aggregate_digest(current_slices):
        return

    changed = [
        relative
        for relative in sorted(recorded_slices)
        if recorded_slices[relative] != current_slices.get(relative)
    ]
    listed = "\n".join(f"         - {relative}" for relative in changed)
    raise FingerprintError(
        "PgpMobile.xcframework does not match its own fingerprint: the recorded\n"
        "       source digest describes different library bytes than the ones in the\n"
        "       bundle, so the fingerprint cannot vouch for this artifact.\n"
        f"       Run the XCFramework sync: {SYNC_COMMAND}\n"
        f"       Mismatched slices ({len(changed)}):\n{listed}"
    )


def check_recorded_bindings(recorded: dict, repo_root: Path, xcframework: Path) -> None:
    """Both ends of the binding copy must be the bytes the build recorded.

    The slice hashes say nothing about the FFI surface the app compiles, so
    without this a bundle carrying someone else's bindings, a checkout that
    never ran the restore, and a hand-edit to the generated Swift all reach the
    compiler unnoticed.
    """
    recorded_bindings = recorded.get("bindings")
    if not isinstance(recorded_bindings, dict) or not recorded_bindings:
        raise FingerprintError(
            f"source fingerprint records no generated bindings: {fingerprint_path(xcframework)}\n"
            f"       The artifact predates this gate. Run the XCFramework sync: {SYNC_COMMAND}"
        )

    carried_root = carried_bindings_dir(xcframework)
    stale_carried: list[str] = []
    unplaced: list[str] = []
    for relative in sorted(recorded_bindings):
        recorded_digest = recorded_bindings[relative]
        if _digest_or_none(carried_root / relative) != recorded_digest:
            stale_carried.append(relative)
        elif _digest_or_none(repo_root / relative) != recorded_digest:
            unplaced.append(relative)

    if stale_carried:
        listed = "\n".join(
            f"         - {CARRIED_BINDINGS_DIR}/{relative}" for relative in stale_carried
        )
        raise FingerprintError(
            "PgpMobile.xcframework does not carry the generated bindings its own\n"
            "       fingerprint records, so it cannot vouch for the FFI surface the app\n"
            "       would compile.\n"
            f"       Run the XCFramework sync: {SYNC_COMMAND}\n"
            f"       Missing or changed ({len(stale_carried)}):\n{listed}"
        )

    if unplaced:
        listed = "\n".join(f"         - {relative}" for relative in unplaced)
        raise FingerprintError(
            "The generated bindings in this checkout are not the ones PgpMobile.xcframework\n"
            "       carries, so the app would compile an FFI surface the artifact never\n"
            "       produced. They are build output; never hand-edit them.\n"
            f"       Place the carried bindings: {RESTORE_COMMAND}\n"
            f"       Missing or changed ({len(unplaced)}):\n{listed}"
        )


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
    check_recorded_slices(recorded, xcframework)

    if recorded["sourceDigest"] != aggregate_digest(current_files):
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

    # Last, because everything above fails with the same remedy: only once the
    # artifact is proven current does an unplaced or edited binding become the
    # most specific thing wrong.
    check_recorded_bindings(recorded, repo_root, xcframework)


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
