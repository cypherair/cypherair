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


RELEASE_TAG = "sqlcipher-xcframework-experiment-20260626T224724Z-61d7f56-r28269517779-a1"
RELEASE_COMMIT = "61d7f56baa687a19270c93f85b3663adc22fa9f2"
SOURCE_REPOSITORY = "https://github.com/sqlcipher/sqlcipher.git"
SOURCE_TAG = "v4.16.0"
SOURCE_COMMIT = "e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc"
EXPECTED_ZIP_SHA = "22bd894ded5bdde119c87f81809b9b99a19dcd7afdf9410858a7fc34555ee20d"
EXPECTED_CHECKSUM_SHA = "89a62d5427c86bf2ef285d7278d3b708ab3986070730b3faf4f3b484a31c8440"
EXPECTED_MANIFEST_SHA = "8f85c82c2d1cd420404f3efe5b4a853edeb9ca4659b73e212a6146acb72c1276"
EXPECTED_PRIVACY_SHA = "9362796ba800a7b4169834eff8bde990866f40114ff7baac002b8bae543e8dd1"
EXPECTED_METADATA_SHA = "5a296e5f8503ad99d02a8e324ef723968df5f485f2a390bf77962683bf144b9b"
EXPECTED_CIPHER_VERSION_PREFIX = "4.16.0"
EXPECTED_SQLITE_VERSION = "3.53.1"

EXPECTED_LIBRARIES = {
    "ios-arm64_arm64e": {
        "platform": "ios",
        "variant": None,
        "architectures": ["arm64", "arm64e"],
        "sha256": "e4aae045539ec8326ebea4d1024653b300b5e1f31d2ec08c9a6b99c682bf61e9",
    },
    "macos-arm64_arm64e": {
        "platform": "macos",
        "variant": None,
        "architectures": ["arm64", "arm64e"],
        "sha256": "45066377d3f01693037ad99cb886562ad7047004f168871e7e4c3c9f6491289f",
    },
    "xros-arm64_arm64e": {
        "platform": "xros",
        "variant": None,
        "architectures": ["arm64", "arm64e"],
        "sha256": "5d3f4386888a77c027c534c55ad7e2f19a08ea93e39ce93c6a357ad5da75cf82",
    },
    "ios-arm64-simulator": {
        "platform": "ios",
        "variant": "simulator",
        "architectures": ["arm64"],
        "sha256": "c52cead9dbe42b58ce55d6b591db8ec70da56cf8cf4a65e75ed5408c4a23d43b",
    },
    "xros-arm64-simulator": {
        "platform": "xros",
        "variant": "simulator",
        "architectures": ["arm64"],
        "sha256": "c7aa5f9beaf310e1701a1ec3d4ca74213bddb787b2e4063a7b650e8787c9ed06",
    },
}

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
    parser.add_argument("--skip-release-assets", action="store_true")
    parser.add_argument("--skip-smoke", action="store_true")
    return parser.parse_args()


def run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


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


def validate_release_assets(assets: Path) -> None:
    zip_path = assets / "SQLCipher.xcframework.zip"
    checksum_path = assets / "SQLCipher.xcframework.sha256"
    manifest_path = assets / "SQLCipher.arm64e-build-manifest.json"
    privacy_path = assets / "SQLCipher-PrivacyInfo.xcprivacy"
    metadata_path = assets / "sqlcipher-xcframework-experiment.json"
    for path in (zip_path, checksum_path, manifest_path, privacy_path, metadata_path):
        require_file(path)

    expect_sha(zip_path, EXPECTED_ZIP_SHA)
    expect_sha(checksum_path, EXPECTED_CHECKSUM_SHA)
    expect_sha(manifest_path, EXPECTED_MANIFEST_SHA)
    expect_sha(privacy_path, EXPECTED_PRIVACY_SHA)
    expect_sha(metadata_path, EXPECTED_METADATA_SHA)

    checksum_text = checksum_path.read_text(encoding="utf-8").strip()
    expected_checksum_text = f"{EXPECTED_ZIP_SHA}  SQLCipher.xcframework.zip"
    if checksum_text != expected_checksum_text:
        raise ValidationError(f"unexpected SQLCipher checksum file content: {checksum_text!r}")


def expect_sha(path: Path, expected: str) -> None:
    actual = sha256(path)
    if actual != expected:
        raise ValidationError(f"{path.name} sha256 {actual} != expected {expected}")


def validate_release_metadata(path: Path) -> None:
    metadata = load_json(path)
    expected = {
        "release_tag": RELEASE_TAG,
        "commit_sha": RELEASE_COMMIT,
        "source_ref": "refs/heads/main",
        "release_channel": "experiment",
        "sqlcipher_source_repository": SOURCE_REPOSITORY,
        "sqlcipher_source_tag": SOURCE_TAG,
        "sqlcipher_source_commit": SOURCE_COMMIT,
    }
    for key, expected_value in expected.items():
        actual = metadata.get(key)
        if actual != expected_value:
            raise ValidationError(f"release metadata {key} {actual!r} != {expected_value!r}")

    assets = metadata.get("assets")
    expected_assets = [
        "SQLCipher.xcframework.zip",
        "SQLCipher.xcframework.sha256",
        "SQLCipher.arm64e-build-manifest.json",
        "SQLCipher-PrivacyInfo.xcprivacy",
        "sqlcipher-xcframework-experiment.json",
    ]
    if assets != expected_assets:
        raise ValidationError(f"release metadata assets {assets!r} != {expected_assets!r}")


def validate_manifest(path: Path, privacy_path: Path) -> dict:
    manifest = load_json(path)
    checks = {
        "schemaVersion": 1,
        "status": "experimental",
        "artifactName": "SQLCipher.xcframework",
        "packageShape": "static-framework-xcframework",
    }
    for key, expected in checks.items():
        actual = manifest.get(key)
        if actual != expected:
            raise ValidationError(f"manifest {key} {actual!r} != {expected!r}")

    source = manifest.get("source") or {}
    if source.get("repository") != SOURCE_REPOSITORY:
        raise ValidationError("manifest source repository mismatch")
    if source.get("tag") != SOURCE_TAG:
        raise ValidationError("manifest source tag mismatch")
    if source.get("resolvedCommit") != SOURCE_COMMIT:
        raise ValidationError("manifest source commit mismatch")
    if source.get("versionFile") != EXPECTED_SQLITE_VERSION:
        raise ValidationError("manifest SQLite version mismatch")

    build = manifest.get("build") or {}
    if build.get("cflags") != EXPECTED_CFLAGS:
        raise ValidationError(f"manifest cflags mismatch: {build.get('cflags')!r}")
    if build.get("linkFrameworks") != EXPECTED_LINK_FRAMEWORKS:
        raise ValidationError(f"manifest link frameworks mismatch: {build.get('linkFrameworks')!r}")

    artifacts = manifest.get("artifacts") or {}
    zip_artifact = artifacts.get("xcframeworkZip") or {}
    if zip_artifact.get("sha256") != EXPECTED_ZIP_SHA:
        raise ValidationError("manifest zip sha mismatch")
    checksum_artifact = artifacts.get("checksumFile") or {}
    if checksum_artifact.get("sha256") != EXPECTED_CHECKSUM_SHA:
        raise ValidationError("manifest checksum-file sha mismatch")
    privacy_artifact = artifacts.get("privacyManifest") or {}
    if privacy_artifact.get("sha256") != EXPECTED_PRIVACY_SHA:
        raise ValidationError("manifest privacy sha mismatch")

    validation = manifest.get("validation") or {}
    if validation.get("compileOptions") != ["SQLITE_HAS_CODEC", "SQLITE_TEMP_STORE=2"]:
        raise ValidationError("manifest compile option validation mismatch")
    smoke = validation.get("smokeTest") or {}
    if smoke.get("status") != "passed":
        raise ValidationError("manifest smoke test did not pass")

    validate_privacy_payload(load_plist(privacy_path))
    validate_privacy_payload(privacy_artifact.get("payload") or {})
    return manifest


def validate_privacy_payload(payload: dict) -> None:
    if payload.get("NSPrivacyTracking") is not False:
        raise ValidationError("privacy manifest must declare NSPrivacyTracking=false")
    if payload.get("NSPrivacyTrackingDomains") != []:
        raise ValidationError("privacy manifest must not declare tracking domains")
    if payload.get("NSPrivacyCollectedDataTypes") != []:
        raise ValidationError("privacy manifest must not declare collected data")

    accessed = payload.get("NSPrivacyAccessedAPITypes")
    if not isinstance(accessed, list):
        raise ValidationError("privacy manifest accessed API list is missing")
    normalized = {
        str(entry.get("NSPrivacyAccessedAPIType")): list(entry.get("NSPrivacyAccessedAPITypeReasons") or [])
        for entry in accessed
    }
    if normalized != EXPECTED_PRIVACY_ACCESSED_APIS:
        raise ValidationError(f"privacy accessed API declarations {normalized!r} != {EXPECTED_PRIVACY_ACCESSED_APIS!r}")


def validate_app_privacy_manifest(root: Path) -> None:
    app_privacy = root / "Sources" / "Resources" / "PrivacyInfo.xcprivacy"
    payload = load_plist(app_privacy)
    validate_privacy_payload(payload)


def validate_xcframework(root: Path, manifest: dict) -> None:
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
    if set(by_identifier) != set(EXPECTED_LIBRARIES):
        raise ValidationError(f"unexpected SQLCipher slices: {sorted(by_identifier)}")

    manifest_libraries = {
        str(entry.get("identifier")): entry
        for entry in ((manifest.get("xcframework") or {}).get("libraries") or [])
    }

    for identifier, expected in EXPECTED_LIBRARIES.items():
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
  return sqlite3_key(db, key, 32);
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
    metadata_path = root / "sqlcipher-xcframework-experiment.json"

    try:
        validate_release_metadata(metadata_path)
        manifest = validate_manifest(manifest_path, privacy_path)
        validate_xcframework(root, manifest)
        validate_app_privacy_manifest(root)
        if args.release_assets and not args.skip_release_assets:
            validate_release_assets(args.release_assets)
        if not args.skip_smoke:
            smoke_test(root)
    except (ValidationError, subprocess.CalledProcessError, json.JSONDecodeError, plistlib.InvalidFileException) as error:
        print(f"error: SQLCipher XCFramework validation failed: {error}", file=sys.stderr)
        return 1

    print("SQLCipher XCFramework validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
