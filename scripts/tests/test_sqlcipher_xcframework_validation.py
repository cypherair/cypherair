from __future__ import annotations

import unittest

from support import load_script_module


module = load_script_module("validate_sqlcipher_xcframework", "scripts/validate_sqlcipher_xcframework.py")


class SQLCipherXCFrameworkValidationTests(unittest.TestCase):
    def test_expected_release_is_exactly_pinned(self) -> None:
        self.assertEqual(
            module.RELEASE_TAG,
            "sqlcipher-xcframework-experiment-20260626T224724Z-61d7f56-r28269517779-a1",
        )
        self.assertNotEqual(module.RELEASE_TAG, "latest")
        self.assertEqual(
            module.SOURCE_COMMIT,
            "e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc",
        )
        self.assertEqual(
            module.EXPECTED_ZIP_SHA,
            "22bd894ded5bdde119c87f81809b9b99a19dcd7afdf9410858a7fc34555ee20d",
        )

    def test_expected_slices_require_device_arm64e(self) -> None:
        self.assertEqual(
            module.EXPECTED_LIBRARIES["ios-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            module.EXPECTED_LIBRARIES["macos-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            module.EXPECTED_LIBRARIES["xros-arm64_arm64e"]["architectures"],
            ["arm64", "arm64e"],
        )
        self.assertEqual(
            module.EXPECTED_LIBRARIES["ios-arm64-simulator"]["architectures"],
            ["arm64"],
        )

    def test_expected_compile_and_privacy_contracts_are_fixed(self) -> None:
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
