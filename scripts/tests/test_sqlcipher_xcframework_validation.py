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
        self.assertNotEqual(release["tag"], "latest")
        self.assertTrue(release["tag"].startswith("sqlcipher-xcframework-v"))
        self.assertEqual(release["channel"], "stable")
        self.assertTrue(release["isImmutable"])
        self.assertFalse(release["isPrerelease"])
        self.assertEqual(
            release["signerWorkflow"],
            "cypherair/sqlcipher-xcframework/.github/workflows/stable-release.yml",
        )

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
        self.assertEqual(
            module.EXPECTED_PRIVACY_ACCESSED_APIS,
            {
                "NSPrivacyAccessedAPICategoryDiskSpace": ["E174.1"],
                "NSPrivacyAccessedAPICategoryFileTimestamp": ["C617.1", "3B52.1"],
            },
        )


if __name__ == "__main__":
    unittest.main()
