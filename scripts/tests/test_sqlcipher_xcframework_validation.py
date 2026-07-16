from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from support import load_script_module


module = load_script_module("validate_sqlcipher_xcframework", "scripts/validate_sqlcipher_xcframework.py")


class SQLCipherXCFrameworkValidationTests(unittest.TestCase):
    def test_pin_release_is_stable_immutable_and_exactly_pinned(self) -> None:
        pin = module.load_pin(module.PIN_PATH)
        module.validate_pin(pin)

        release = pin["release"]
        self.assertEqual(
            release["tag"],
            "sqlcipher-xcframework-v4.17.0-cypherair.1",
        )
        self.assertNotEqual(release["tag"], "latest")
        self.assertEqual(release["channel"], "stable")
        self.assertTrue(release["isImmutable"])
        self.assertFalse(release["isPrerelease"])
        self.assertEqual(release["runId"], "29501460869")
        self.assertEqual(
            release["signerWorkflow"],
            "cypherair/sqlcipher-xcframework/.github/workflows/stable-release.yml",
        )
        self.assertEqual(
            pin["upstream"]["commit"],
            "810db22f575ee7cf94ea96a3e91622b5fcece3dc",
        )
        self.assertEqual(
            pin["assets"]["SQLCipher.xcframework.zip"]["sha256"],
            "51b0c197d4c06461fd3484a7a8577731eba6ef49c77272bd76db703431d3c4da",
        )
        self.assertEqual(pin["assets"]["SQLCipher.xcframework.zip"]["size"], 5681989)

    def test_pin_rejects_invalid_asset_sizes(self) -> None:
        pin = module.load_pin(module.PIN_PATH)
        missing_size = copy.deepcopy(pin)
        missing_size["assets"]["SQLCipher.xcframework.zip"].pop("size")
        with self.assertRaisesRegex(module.ValidationError, "positive integer size"):
            module.validate_pin(missing_size)

        for invalid_size in (True, 0, -1, "5681989"):
            with self.subTest(invalid_size=invalid_size):
                candidate = copy.deepcopy(pin)
                candidate["assets"]["SQLCipher.xcframework.zip"]["size"] = invalid_size
                with self.assertRaisesRegex(module.ValidationError, "positive integer size"):
                    module.validate_pin(candidate)

    def test_release_asset_size_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            asset = Path(temp_dir_name) / "asset.bin"
            asset.write_bytes(b"abc")
            module.expect_size(asset, 3)
            with self.assertRaisesRegex(module.ValidationError, "size 3 != expected 4"):
                module.expect_size(asset, 4)

    def test_expected_slices_require_device_arm64e(self) -> None:
        slices = module.load_pin(module.PIN_PATH)["slices"]
        self.assertEqual(
            slices["ios-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            slices["macos-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            slices["xros-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            slices["ios-arm64-simulator"]["architectures"],
            ["arm64"],
        )

    def test_expected_compile_and_privacy_contracts_are_fixed(self) -> None:
        self.assertEqual(module.EXPECTED_FRAMEWORK_VERSION, "4.17.0")
        self.assertEqual(module.EXPECTED_CIPHER_RUNTIME_VERSION, "4.17.0 community")
        self.assertEqual(module.EXPECTED_SQLITE_VERSION, "3.53.3")
        self.assertEqual(module.REQUIRED_FRAMEWORK_FILES, ["Info.plist", "Modules/module.modulemap", "PrivacyInfo.xcprivacy"])
        self.assertNotIn("module.modulemap", module.REQUIRED_HEADERS)
        self.assertIn("-DSQLITE_HAS_CODEC", module.EXPECTED_CFLAGS)
        self.assertIn("-DSQLCIPHER_CRYPTO_CC", module.EXPECTED_CFLAGS)
        self.assertEqual(
            module.EXPECTED_LINK_FRAMEWORKS,
            ["Security", "CoreFoundation", "Foundation"],
        )
        self.assertEqual(
            module.EXPECTED_PRIVACY_ACCESSED_APIS,
            {
                "NSPrivacyAccessedAPICategoryDiskSpace": ["E174.1"],
                "NSPrivacyAccessedAPICategoryFileTimestamp": ["C617.1", "3B52.1"],
            },
        )


if __name__ == "__main__":
    unittest.main()
