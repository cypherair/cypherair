#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = ROOT / "third_party" / "sqlcipher-xcframework.pin.json"
SOURCE_REPOSITORY = "https://github.com/sqlcipher/sqlcipher.git"
SOURCE_TAG = "v4.16.0"
SOURCE_COMMIT = "e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc"
EXPECTED_CIPHER_VERSION_PREFIX = "4.16.0"
EXPECTED_SQLITE_VERSION = "3.53.1"
RELEASE_METADATA_NAME = "SQLCipher.xcframework.release.json"
EXPECTED_ASSET_NAMES = [
    "SQLCipher.xcframework.zip",
    "SQLCipher.xcframework.sha256",
    "SQLCipher.arm64e-build-manifest.json",
    "SQLCipher-PrivacyInfo.xcprivacy",
    RELEASE_METADATA_NAME,
]

REQUIRED_HEADERS = ["SQLCipher.h", "sqlite3.h", "sqlite3ext.h", "sqlite3session.h"]
REQUIRED_FRAMEWORK_FILES = ["Info.plist", "Modules/module.modulemap", "PrivacyInfo.xcprivacy"]
EXPECTED_CFLAGS = [
    "-DNDEBUG",
    "-DSQLCIPHER_CRYPTO_CC",
    "-DSQLITE_HAS_CODEC",
    "-DSQLITE_TEMP_STORE=2",
    "-DSQLITE_THREADSAFE=1",
    "-DSQLITE_EXTRA_INIT=sqlcipher_extra_init",
    "-DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",
]
EXPECTED_LINK_FRAMEWORKS = ["Security", "CoreFoundation", "Foundation"]
EXPECTED_PRIVACY_ACCESSED_APIS = {
    "NSPrivacyAccessedAPICategoryDiskSpace": ["E174.1"],
    "NSPrivacyAccessedAPICategoryFileTimestamp": ["C617.1", "3B52.1"],
}


class ValidationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate CypherAir's pinned SQLCipher XCFramework input.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--release-assets", type=Path)
    parser.add_argument("--pin-file", type=Path, default=PIN_PATH)
    parser.add_argument("--skip-release-assets", action="store_true")
    parser.add_argument("--skip-smoke", action="store_true")
    return parser.parse_args()


def run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def format_error_detail(error: Exception) -> str:
    if not isinstance(error, subprocess.CalledProcessError):
        return str(error)

    details = [str(error)]
    for label, value in (("stdout", error.stdout), ("stderr", error.stderr)):
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        text = str(value or "").strip()
        if text:
            details.append(f"{label}:\n{text}")
    return "\n".join(details)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path) -> None:
    if not path.is_file():
        raise ValidationError(f"required SQLCipher file is missing: {path}")


def load_json(path: Path) -> dict:
    require_file(path)
    return json.loads(path.read_text(encoding="utf-8"))


def load_plist(path: Path) -> dict:
    require_file(path)
    with path.open("rb") as handle:
        return plistlib.load(handle)


def load_pin(path: Path) -> dict:
    pin = load_json(path)
    if not isinstance(pin, dict):
        raise ValidationError("SQLCipher pin file must contain a JSON object")
    return pin


def validate_pin(pin: dict) -> None:
    if pin.get("schemaVersion") != 1:
        raise ValidationError("SQLCipher pin schemaVersion must be 1")
    if pin.get("dependencyName") != "SQLCipher.xcframework":
        raise ValidationError("SQLCipher pin dependencyName mismatch")
    if pin.get("repository") != "cypherair/sqlcipher-xcframework":
        raise ValidationError("SQLCipher pin repository mismatch")

    release = pin.get("release") or {}
    tag = str(release.get("tag") or "")
    if not tag or tag == "latest" or "experiment" in tag:
        raise ValidationError(f"SQLCipher pin must use an exact stable release tag, got {tag!r}")
    if release.get("channel") != "stable":
        raise ValidationError("SQLCipher pin release channel must be stable")
    if release.get("isImmutable") is not True:
        raise ValidationError("SQLCipher pin must require an immutable release")
    if release.get("isPrerelease") is not False:
        raise ValidationError("SQLCipher pin must not target a prerelease")
    if release.get("sourceRef") != f"refs/tags/{tag}":
        raise ValidationError("SQLCipher pin sourceRef must match the release tag")
    if not str(release.get("commitSha") or ""):
        raise ValidationError("SQLCipher pin release commitSha is missing")
    if release.get("signerWorkflow") != "cypherair/sqlcipher-xcframework/.github/workflows/stable-release.yml":
        raise ValidationError("SQLCipher pin signerWorkflow mismatch")

    upstream = pin.get("upstream") or {}
    if upstream.get("repository") != SOURCE_REPOSITORY:
        raise ValidationError("SQLCipher pin upstream repository mismatch")
    if upstream.get("tag") != SOURCE_TAG:
        raise ValidationError("SQLCipher pin upstream tag mismatch")
    if upstream.get("commit") != SOURCE_COMMIT:
        raise ValidationError("SQLCipher pin upstream commit mismatch")
    if upstream.get("sqliteVersion") != EXPECTED_SQLITE_VERSION:
        raise ValidationError("SQLCipher pin SQLite version mismatch")

    assets = pin.get("assets")
    if not isinstance(assets, dict) or list(assets) != EXPECTED_ASSET_NAMES:
        raise ValidationError(f"SQLCipher pin assets must be {EXPECTED_ASSET_NAMES!r}")
    for asset_name, entry in assets.items():
        if not isinstance(entry, dict) or not str(entry.get("sha256") or ""):
            raise ValidationError(f"SQLCipher pin asset {asset_name} is missing sha256")

    slices = pin.get("slices")
    if not isinstance(slices, dict):
        raise ValidationError("SQLCipher pin slices must be a JSON object")
    required_slice_archs = {
        "ios-arm64_arm64e": ["arm64", "arm64e"],
        "macos-arm64_arm64e": ["arm64", "arm64e"],
        "xros-arm64_arm64e": ["arm64", "arm64e"],
        "ios-arm64-simulator": ["arm64"],
        "xros-arm64-simulator": ["arm64"],
    }
    if set(slices) != set(required_slice_archs):
        raise ValidationError(f"SQLCipher pin slices mismatch: {sorted(slices)}")
    for identifier, expected_archs in required_slice_archs.items():
        entry = slices[identifier]
        if entry.get("architectures") != expected_archs:
            raise ValidationError(f"SQLCipher pin slice {identifier} architecture mismatch")
        if not str(entry.get("sha256") or ""):
            raise ValidationError(f"SQLCipher pin slice {identifier} is missing sha256")


def asset_sha(pin: dict, name: str) -> str:
    return str(((pin.get("assets") or {}).get(name) or {}).get("sha256") or "")


def validate_release_assets(assets: Path, pin: dict) -> None:
    zip_path = assets / "SQLCipher.xcframework.zip"
    checksum_path = assets / "SQLCipher.xcframework.sha256"
    manifest_path = assets / "SQLCipher.arm64e-build-manifest.json"
    privacy_path = assets / "SQLCipher-PrivacyInfo.xcprivacy"
    metadata_path = assets / RELEASE_METADATA_NAME
    for path in (zip_path, checksum_path, manifest_path, privacy_path, metadata_path):
        require_file(path)

    expect_sha(zip_path, asset_sha(pin, "SQLCipher.xcframework.zip"))
    expect_sha(checksum_path, asset_sha(pin, "SQLCipher.xcframework.sha256"))
    expect_sha(manifest_path, asset_sha(pin, "SQLCipher.arm64e-build-manifest.json"))
    expect_sha(privacy_path, asset_sha(pin, "SQLCipher-PrivacyInfo.xcprivacy"))
    expect_sha(metadata_path, asset_sha(pin, RELEASE_METADATA_NAME))

    checksum_text = checksum_path.read_text(encoding="utf-8").strip()
    expected_checksum_text = f"{asset_sha(pin, 'SQLCipher.xcframework.zip')}  SQLCipher.xcframework.zip"
    if checksum_text != expected_checksum_text:
        raise ValidationError(f"unexpected SQLCipher checksum file content: {checksum_text!r}")


def expect_sha(path: Path, expected: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise ValidationError(f"{path.name} sha256 {actual} != expected {expected}")


def validate_release_metadata(path: Path, pin: dict) -> None:
    metadata = load_json(path)
    release = pin["release"]
    upstream = pin["upstream"]
    expected = {
        "release_tag": release["tag"],
        "release_url": release["url"],
        "commit_sha": release["commitSha"],
        "source_ref": release["sourceRef"],
        "release_channel": "stable",
        "signer_workflow": release["signerWorkflow"],
        "sqlcipher_source_repository": upstream["repository"],
        "sqlcipher_source_tag": upstream["tag"],
        "sqlcipher_source_commit": upstream["commit"],
    }
    for key, expected_value in expected.items():
        actual = metadata.get(key)
        if actual != expected_value:
            raise ValidationError(f"release metadata {key} {actual!r} != {expected_value!r}")

    assets = metadata.get("assets")
    if assets != EXPECTED_ASSET_NAMES:
        raise ValidationError(f"release metadata assets {assets!r} != {EXPECTED_ASSET_NAMES!r}")


def validate_manifest(path: Path, privacy_path: Path, pin: dict) -> dict:
    manifest = load_json(path)
    checks = {
        "schemaVersion": 1,
        "status": "stable",
        "artifactName": "SQLCipher.xcframework",
        "packageShape": "static-framework-xcframework",
    }
    for key, expected in checks.items():
        actual = manifest.get(key)
        if actual != expected:
            raise ValidationError(f"manifest {key} {actual!r} != {expected!r}")

    source = manifest.get("source") or {}
    upstream = pin["upstream"]
    if source.get("repository") != upstream["repository"]:
        raise ValidationError("manifest source repository mismatch")
    if source.get("tag") != upstream["tag"]:
        raise ValidationError("manifest source tag mismatch")
    if source.get("resolvedCommit") != upstream["commit"]:
        raise ValidationError("manifest source commit mismatch")
    if source.get("versionFile") != upstream["sqliteVersion"]:
        raise ValidationError("manifest SQLite version mismatch")

    build = manifest.get("build") or {}
    if build.get("cflags") != EXPECTED_CFLAGS:
        raise ValidationError(f"manifest cflags mismatch: {build.get('cflags')!r}")
    if build.get("linkFrameworks") != EXPECTED_LINK_FRAMEWORKS:
        raise ValidationError(f"manifest link frameworks mismatch: {build.get('linkFrameworks')!r}")

    artifacts = manifest.get("artifacts") or {}
    zip_artifact = artifacts.get("xcframeworkZip") or {}
    if zip_artifact.get("sha256") != asset_sha(pin, "SQLCipher.xcframework.zip"):
        raise ValidationError("manifest zip sha mismatch")
    checksum_artifact = artifacts.get("checksumFile") or {}
    if checksum_artifact.get("sha256") != asset_sha(pin, "SQLCipher.xcframework.sha256"):
        raise ValidationError("manifest checksum-file sha mismatch")
    privacy_artifact = artifacts.get("privacyManifest") or {}
    if privacy_artifact.get("sha256") != asset_sha(pin, "SQLCipher-PrivacyInfo.xcprivacy"):
        raise ValidationError("manifest privacy sha mismatch")

    validation = manifest.get("validation") or {}
    if validation.get("compileOptions") != ["SQLITE_HAS_CODEC", "SQLITE_TEMP_STORE=2"]:
        raise ValidationError("manifest compile option validation mismatch")
    smoke = validation.get("smokeTest") or {}
    if smoke.get("status") != "passed":
        raise ValidationError("manifest smoke test did not pass")

    validate_framework_privacy_payload(load_plist(privacy_path))
    validate_framework_privacy_payload(privacy_artifact.get("payload") or {})
    return manifest


def validate_privacy_payload(payload: dict) -> dict:
    if payload.get("NSPrivacyTracking") is not False:
        raise ValidationError("privacy manifest must declare NSPrivacyTracking=false")
    if payload.get("NSPrivacyTrackingDomains") != []:
        raise ValidationError("privacy manifest must not declare tracking domains")
    if payload.get("NSPrivacyCollectedDataTypes") != []:
        raise ValidationError("privacy manifest must not declare collected data")

    accessed = payload.get("NSPrivacyAccessedAPITypes")
    if not isinstance(accessed, list):
        raise ValidationError("privacy manifest accessed API list is missing")
    return {
        str(entry.get("NSPrivacyAccessedAPIType")): list(entry.get("NSPrivacyAccessedAPITypeReasons") or [])
        for entry in accessed
    }


def validate_framework_privacy_payload(payload: dict) -> None:
    normalized = validate_privacy_payload(payload)
    if normalized != EXPECTED_PRIVACY_ACCESSED_APIS:
        raise ValidationError(f"privacy accessed API declarations {normalized!r} != {EXPECTED_PRIVACY_ACCESSED_APIS!r}")


def validate_app_privacy_manifest(root: Path) -> None:
    # Static linking attributes SQLCipher's required-reason API use to the
    # app binary, so the app manifest must cover every category and reason
    # SQLCipher declares. The app legitimately declares additional categories
    # for its own API use (e.g. UserDefaults / CA92.1), so this is a coverage
    # check, not the exact-match contract applied to the framework manifest.
    app_privacy = root / "Sources" / "Resources" / "PrivacyInfo.xcprivacy"
    payload = load_plist(app_privacy)
    normalized = validate_privacy_payload(payload)
    for category, reasons in EXPECTED_PRIVACY_ACCESSED_APIS.items():
        declared = normalized.get(category)
        if declared is None:
            raise ValidationError(f"app privacy manifest is missing SQLCipher category {category}")
        missing = [reason for reason in reasons if reason not in declared]
        if missing:
            raise ValidationError(
                f"app privacy manifest category {category} is missing SQLCipher reasons {missing!r}"
            )


def validate_xcframework(root: Path, manifest: dict, pin: dict) -> None:
    xcframework = root / "SQLCipher.xcframework"
    info_path = xcframework / "Info.plist"
    if not info_path.is_file():
        raise ValidationError(
            f"SQLCipher.xcframework is missing. Run scripts/restore_sqlcipher_xcframework.sh before Xcode builds: {info_path}"
        )

    info = load_plist(info_path)
    libraries = info.get("AvailableLibraries")
    if not isinstance(libraries, list):
        raise ValidationError("SQLCipher.xcframework Info.plist lacks AvailableLibraries")
    by_identifier = {str(entry.get("LibraryIdentifier")): entry for entry in libraries}
    expected_libraries = pin["slices"]
    if set(by_identifier) != set(expected_libraries):
        raise ValidationError(f"unexpected SQLCipher slices: {sorted(by_identifier)}")

    manifest_libraries = {
        str(entry.get("identifier")): entry
        for entry in ((manifest.get("xcframework") or {}).get("libraries") or [])
    }

    for identifier, expected in expected_libraries.items():
        entry = by_identifier[identifier]
        if entry.get("SupportedPlatform") != expected["platform"]:
            raise ValidationError(f"{identifier}: platform mismatch")
        if (entry.get("SupportedPlatformVariant") or None) != expected["variant"]:
            raise ValidationError(f"{identifier}: variant mismatch")
        if list(entry.get("SupportedArchitectures") or []) != expected["architectures"]:
            raise ValidationError(f"{identifier}: architecture mismatch")
        if entry.get("LibraryPath") != "SQLCipher.framework" or entry.get("BinaryPath") != "SQLCipher.framework/SQLCipher":
            raise ValidationError(f"{identifier}: expected SQLCipher.framework")
        if entry.get("HeadersPath") is not None:
            raise ValidationError(f"{identifier}: framework-shaped slices must not expose HeadersPath")

        framework = xcframework / identifier / "SQLCipher.framework"
        library = framework / "SQLCipher"
        require_file(library)
        archs = run(["lipo", "-archs", str(library)]).split()
        if archs != expected["architectures"]:
            raise ValidationError(f"{identifier}: lipo archs {archs!r} != {expected['architectures']!r}")
        expect_sha(library, expected["sha256"])

        manifest_entry = manifest_libraries.get(identifier)
        if not manifest_entry:
            raise ValidationError(f"{identifier}: missing from manifest libraries")
        if manifest_entry.get("sha256") != expected["sha256"]:
            raise ValidationError(f"{identifier}: manifest library sha mismatch")
        if manifest_entry.get("libraryPath") != "SQLCipher.framework":
            raise ValidationError(f"{identifier}: manifest libraryPath mismatch")
        if manifest_entry.get("binaryPath") != "SQLCipher.framework/SQLCipher":
            raise ValidationError(f"{identifier}: manifest binaryPath mismatch")

        for required in REQUIRED_FRAMEWORK_FILES:
            require_file(framework / required)
        framework_info = load_plist(framework / "Info.plist")
        if framework_info.get("CFBundlePackageType") != "FMWK":
            raise ValidationError(f"{identifier}: SQLCipher.framework Info.plist must declare CFBundlePackageType=FMWK")
        if framework_info.get("CFBundleExecutable") != "SQLCipher":
            raise ValidationError(f"{identifier}: SQLCipher.framework Info.plist must declare CFBundleExecutable=SQLCipher")
        modulemap = (framework / "Modules" / "module.modulemap").read_text(encoding="utf-8")
        if "framework module SQLCipher" not in modulemap or 'umbrella header "SQLCipher.h"' not in modulemap:
            raise ValidationError(f"{identifier}: module.modulemap does not declare framework module SQLCipher")

        headers = framework / "Headers"
        for header in REQUIRED_HEADERS:
            require_file(headers / header)
        sqlcipher_header = (headers / "SQLCipher.h").read_text(encoding="utf-8")
        if "#define SQLITE_HAS_CODEC" not in sqlcipher_header:
            raise ValidationError(f"{identifier}: SQLCipher.h must expose SQLITE_HAS_CODEC before sqlite3.h")


def smoke_test(root: Path) -> None:
    host = platform.machine()
    if host not in {"arm64", "arm64e"}:
        print(f"warning: skipping SQLCipher smoke test on unsupported host architecture {host}", file=sys.stderr)
        return

    framework_parent = root / "SQLCipher.xcframework" / "macos-arm64_arm64e"
    source = r'''
#include <SQLCipher/SQLCipher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int capture(void *ctx, int argc, char **argv, char **col) {
  (void)argc;
  (void)col;
  snprintf((char *)ctx, 256, "%s", (argv && argv[0]) ? argv[0] : "");
  return 0;
}

static int exec_sql(sqlite3 *db, const char *sql) {
  char *errmsg = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite rc=%d\n", rc);
    sqlite3_free(errmsg);
  }
  return rc;
}

static int query_value(sqlite3 *db, const char *sql, char *value, size_t value_len) {
  char *errmsg = NULL;
  value[0] = '\0';
  int rc = sqlite3_exec(db, sql, capture, value, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite rc=%d\n", rc);
    sqlite3_free(errmsg);
    return rc;
  }
  return value[0] == '\0' ? SQLITE_ERROR : SQLITE_OK;
}

static int apply_key(sqlite3 *db, unsigned char key[32]) {
  static const char hex[] = "0123456789abcdef";
  char key_spec[68] = {0};
  key_spec[0] = 'x';
  key_spec[1] = '\'';
  for (int i = 0; i < 32; i++) {
    key_spec[2 + (i * 2)] = hex[(key[i] >> 4) & 0x0f];
    key_spec[3 + (i * 2)] = hex[key[i] & 0x0f];
  }
  key_spec[66] = '\'';
  int rc = sqlite3_key_v2(db, "main", key_spec, 67);
  memset(key_spec, 0, sizeof(key_spec));
  return rc;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const char *path = argv[1];
  unsigned char good_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
  };
  unsigned char bad_key[32] = {
    31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  };
  sqlite3 *db = NULL;
  char value[256] = {0};

  if (sqlite3_open(":memory:", &db) != SQLITE_OK) return 10;
  if (query_value(db, "PRAGMA cipher_version;", value, sizeof(value)) != SQLITE_OK) return 11;
  if (strncmp(value, "4.16.0", 6) != 0 || strstr(value, "community") == NULL) return 12;
  sqlite3_close(db);

  if (!sqlite3_compileoption_used("SQLITE_HAS_CODEC")) return 13;
  if (!sqlite3_compileoption_used("SQLITE_TEMP_STORE=2")) return 14;

  remove(path);
  if (sqlite3_open(path, &db) != SQLITE_OK) return 20;
  if (apply_key(db, good_key) != SQLITE_OK) return 21;
  if (exec_sql(db, "CREATE TABLE t(v TEXT);") != SQLITE_OK) return 22;
  if (exec_sql(db, "INSERT INTO t VALUES('hello');") != SQLITE_OK) return 23;
  sqlite3_close(db);

  if (sqlite3_open(path, &db) != SQLITE_OK) return 30;
  if (apply_key(db, good_key) != SQLITE_OK) return 31;
  if (query_value(db, "SELECT v FROM t;", value, sizeof(value)) != SQLITE_OK) return 32;
  if (strcmp(value, "hello") != 0) return 33;
  sqlite3_close(db);

  if (sqlite3_open(path, &db) != SQLITE_OK) return 40;
  if (apply_key(db, bad_key) != SQLITE_OK) return 41;
  int wrong_key_rc = query_value(db, "SELECT v FROM t;", value, sizeof(value));
  sqlite3_close(db);
  remove(path);
  if (wrong_key_rc == SQLITE_OK) return 42;

  return 0;
}
'''

    with tempfile.TemporaryDirectory() as temp_name:
        temp_dir = Path(temp_name)
        source_path = temp_dir / "sqlcipher_smoke.c"
        binary_path = temp_dir / "sqlcipher_smoke"
        database_path = temp_dir / "encrypted.db"
        source_path.write_text(source, encoding="utf-8")
        run(
            [
                "xcrun",
                "clang",
                "-arch",
                "arm64",
                str(source_path),
                "-DSQLITE_HAS_CODEC",
                "-F",
                str(framework_parent),
                "-framework",
                "SQLCipher",
                "-framework",
                "Security",
                "-framework",
                "CoreFoundation",
                "-framework",
                "Foundation",
                "-o",
                str(binary_path),
            ]
        )
        linkage = run(["otool", "-L", str(binary_path)])
        if "libsqlite3" in linkage:
            raise ValidationError("SQLCipher smoke binary linked system libsqlite3")
        if "SQLCipher.framework" in linkage:
            raise ValidationError("SQLCipher smoke binary linked SQLCipher dynamically; expected static framework linkage")
        run([str(binary_path), str(database_path)])


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    manifest_path = root / "SQLCipher.arm64e-build-manifest.json"
    privacy_path = root / "SQLCipher-PrivacyInfo.xcprivacy"
    metadata_path = root / RELEASE_METADATA_NAME

    try:
        pin = load_pin(args.pin_file.resolve())
        validate_pin(pin)
        validate_release_metadata(metadata_path, pin)
        manifest = validate_manifest(manifest_path, privacy_path, pin)
        validate_xcframework(root, manifest, pin)
        validate_app_privacy_manifest(root)
        if args.release_assets and not args.skip_release_assets:
            validate_release_assets(args.release_assets, pin)
        if not args.skip_smoke:
            smoke_test(root)
    except (KeyError, TypeError, ValidationError, subprocess.CalledProcessError, json.JSONDecodeError, plistlib.InvalidFileException) as error:
        print(f"error: SQLCipher XCFramework validation failed: {format_error_detail(error)}", file=sys.stderr)
        return 1

    print("SQLCipher XCFramework validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
