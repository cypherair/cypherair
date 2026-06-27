from __future__ import annotations

import unittest

from support import load_script_module


module = load_script_module("validate_sqlcipher_xcframework", "scripts/validate_sqlcipher_xcframework.py")


class SQLCipherXCFrameworkValidationTests(unittest.TestCase):
    def test_pin_release_is_stable_immutable_and_exactly_pinned(self) -> None:
        pin = module.load_pin(module.PIN_PATH)
        module.validate_pin(pin)

        release = pin["release"]
        self.assertEqual(
            release["tag"],
            "sqlcipher-xcframework-v4.16.0-cypherair.1",
        )
        self.assertNotEqual(release["tag"], "latest")
        self.assertEqual(release["channel"], "stable")
        self.assertTrue(release["isImmutable"])
        self.assertFalse(release["isPrerelease"])
        self.assertEqual(
            release["signerWorkflow"],
            "cypherair/sqlcipher-xcframework/.github/workflows/stable-release.yml",
        )
        self.assertEqual(
            pin["upstream"]["commit"],
            "e2a6040f2ae5cfff2b3e08eb3320007d93cdf3fc",
        )
        self.assertEqual(
            pin["assets"]["SQLCipher.xcframework.zip"]["sha256"],
            "3544554bcf947fb9329f2ab083cd42f0c7ae9179e98b7f36f26859e2c573062e",
        )

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
