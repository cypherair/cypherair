from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import REPO_ROOT, load_script_module


module = load_script_module("check_device_test_skip_list", "scripts/check_device_test_skip_list.py")


PLAN_TEMPLATE = {
    "configurations": [{"id": "A", "name": "Configuration 1", "options": {}}],
    "defaultOptions": {},
    "testTargets": [
        {
            "skippedTests": [],
            "target": {
                "containerPath": "container:CypherAir.xcodeproj",
                "identifier": "8561964DF0A7E2575A3799D6",
                "name": "CypherAirTests",
            },
        }
    ],
    "version": 1,
}


class CheckDeviceTestSkipListTests(unittest.TestCase):
    def make_repo(
        self,
        root: Path,
        sources: dict[str, str],
        skipped: list[str],
        other_test_sources: dict[str, str] | None = None,
    ) -> Path:
        directory = root / module.DEVICE_TESTS_DIR
        directory.mkdir(parents=True)
        for name, contents in sources.items():
            (directory / name).write_text(contents, encoding="utf-8")

        for relative, contents in (other_test_sources or {}).items():
            path = root / module.TESTS_DIR / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")

        plan = json.loads(json.dumps(PLAN_TEMPLATE))
        plan["testTargets"][0]["skippedTests"] = skipped
        (root / module.TEST_PLAN).write_text(json.dumps(plan, indent=2), encoding="utf-8")
        return root

    def test_listed_class_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecureEnclaveTests.swift": (
                        "import XCTest\n"
                        "final class DeviceSecureEnclaveTests: XCTestCase {\n"
                        "    func testWrapsKey() throws {}\n"
                        "}\n"
                    )
                },
                ["DeviceSecureEnclaveTests"],
            )
            module.check(root)

    def test_unlisted_class_fails_with_its_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecureEnclaveTests.swift": (
                        "import XCTest\n"
                        "final class DeviceSecureEnclaveTests: XCTestCase {\n"
                        "    func testWrapsKey() throws {}\n"
                        "}\n"
                    ),
                    "DeviceNewBiometricTests.swift": (
                        "import XCTest\n"
                        "final class DeviceNewBiometricTests: XCTestCase {\n"
                        "    func testPromptsOnce() async throws {}\n"
                        "}\n"
                    ),
                },
                ["DeviceSecureEnclaveTests"],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            message = str(raised.exception)
            self.assertIn("DeviceNewBiometricTests", message)
            self.assertNotIn("DeviceSecureEnclaveTests\n", message.split("skippedTests")[-1])

    def test_subclass_of_local_base_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecurityTestCase.swift": (
                        "import XCTest\n"
                        "class DeviceSecurityTestCase: XCTestCase {\n"
                        "    func makeSubject() {}\n"
                        "}\n"
                    ),
                    "SecureEnclaveCustodyDeviceTestCase.swift": (
                        "class SecureEnclaveCustodyDeviceTestCase: DeviceSecurityTestCase {\n"
                        "    func reset() {}\n"
                        "}\n"
                    ),
                    "DeviceCustodyTests.swift": (
                        "final class DeviceCustodyTests: SecureEnclaveCustodyDeviceTestCase {\n"
                        "    func testDecrypts() throws {}\n"
                        "}\n"
                    ),
                },
                [],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceCustodyTests", str(raised.exception))

    def test_base_class_without_test_methods_is_exempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecurityTestCase.swift": (
                        "import XCTest\n"
                        "class DeviceSecurityTestCase: XCTestCase {\n"
                        "    func requireSecureEnclave() throws {}\n"
                        "}\n"
                    ),
                    "DeviceMIETests.swift": (
                        "final class DeviceMIETests: DeviceSecurityTestCase {\n"
                        "    func testTaggingEnabled() {}\n"
                        "}\n"
                    ),
                },
                ["DeviceMIETests"],
            )
            module.check(root)

    def test_base_class_that_declares_a_test_becomes_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecurityTestCase.swift": (
                        "import XCTest\n"
                        "class DeviceSecurityTestCase: XCTestCase {\n"
                        "    func testSharedInvariant() {}\n"
                        "}\n"
                    ),
                    "DeviceMIETests.swift": (
                        "final class DeviceMIETests: DeviceSecurityTestCase {\n"
                        "    func testTaggingEnabled() {}\n"
                        "}\n"
                    ),
                },
                ["DeviceMIETests"],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceSecurityTestCase", str(raised.exception))

    def test_method_level_skip_does_not_satisfy_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecureEnclaveTests.swift": (
                        "import XCTest\n"
                        "final class DeviceSecureEnclaveTests: XCTestCase {\n"
                        "    func testWrapsKey() throws {}\n"
                        "    func testUnwrapsKey() throws {}\n"
                        "}\n"
                    )
                },
                ["DeviceSecureEnclaveTests/testWrapsKey()"],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceSecureEnclaveTests", str(raised.exception))

    def test_helper_without_test_methods_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecureEnclaveTests.swift": (
                        "import XCTest\n"
                        "final class DeviceSecureEnclaveTests: XCTestCase {\n"
                        "    func testWrapsKey() throws {}\n"
                        "}\n"
                        "\n"
                        "private final class UnusedUnwrapper: SoftwareSecretCertificateUnwrapping, "
                        "@unchecked Sendable {\n"
                        "    func unwrapPrivateKey() {}\n"
                        "}\n"
                    )
                },
                ["DeviceSecureEnclaveTests"],
            )
            module.check(root)
            self.assertEqual(module.required_class_names(root), ["DeviceSecureEnclaveTests"])

    def test_base_declared_outside_the_device_directory_still_resolves(self) -> None:
        # Reproduces the fail-open: four XCTestCase bases live elsewhere under
        # Tests/, and a device class extending one used to pass unnoticed.
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceProtectedDataTests.swift": (
                        "final class DeviceProtectedDataTests: ProtectedDataFrameworkTestCase {\n"
                        "    func testOpensDomain() async throws {}\n"
                        "}\n"
                    )
                },
                [],
                other_test_sources={
                    "ServiceTests/ProtectedDataFrameworkTestSupport.swift": (
                        "import XCTest\n"
                        "class ProtectedDataFrameworkTestCase: XCTestCase {\n"
                        "    func makeStore() {}\n"
                        "}\n"
                    )
                },
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceProtectedDataTests", str(raised.exception))

    def test_unresolvable_superclass_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceOpaqueTests.swift": (
                        "final class DeviceOpaqueTests: SomeBaseDeclaredSomewhereElse {\n"
                        "    func testSomething() throws {}\n"
                        "}\n"
                    )
                },
                [],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceOpaqueTests", str(raised.exception))

    def test_tests_declared_in_an_extension_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceExtensionTests.swift": (
                        "import XCTest\n"
                        "final class DeviceExtensionTests: XCTestCase {\n"
                        "    private let subject = 1\n"
                        "}\n"
                        "\n"
                        "extension DeviceExtensionTests {\n"
                        "    func testViaExtension() throws {}\n"
                        "}\n"
                    )
                },
                [],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceExtensionTests", str(raised.exception))

    def test_declaration_with_a_brace_on_a_later_line_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceWrappedTests.swift": (
                        "import XCTest\n"
                        "@MainActor\n"
                        "final class DeviceWrappedTests:\n"
                        "    DeviceSecurityTestCase,\n"
                        "    SomeProtocol\n"
                        "{\n"
                        "    func testWrapped() throws {}\n"
                        "}\n"
                    ),
                    "DeviceSecurityTestCase.swift": (
                        "import XCTest\nclass DeviceSecurityTestCase: XCTestCase {}\n"
                    ),
                },
                [],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceWrappedTests", str(raised.exception))

    def test_module_qualified_xctest_base_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceQualifiedTests.swift": (
                        "import XCTest\n"
                        "final class DeviceQualifiedTests: XCTest.XCTestCase {\n"
                        "    func testQualified() throws {}\n"
                        "}\n"
                    )
                },
                [],
            )
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("DeviceQualifiedTests", str(raised.exception))

    def test_comments_and_string_literals_do_not_declare_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(
                Path(temp_dir_name),
                {
                    "DeviceSecureEnclaveTests.swift": (
                        "import XCTest\n"
                        "// final class DeviceCommentedOutTests: XCTestCase {\n"
                        "/*\n"
                        "final class DeviceBlockCommentTests: XCTestCase {\n"
                        "    func testSomething() {}\n"
                        "}\n"
                        "*/\n"
                        "final class DeviceSecureEnclaveTests: XCTestCase {\n"
                        '    let sample = "final class DeviceLiteralTests: XCTestCase { }"\n'
                        "    func testWrapsKey() throws {}\n"
                        "}\n"
                    )
                },
                ["DeviceSecureEnclaveTests"],
            )
            module.check(root)
            self.assertEqual(module.required_class_names(root), ["DeviceSecureEnclaveTests"])

    def test_empty_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            root = self.make_repo(Path(temp_dir_name), {}, [])
            with self.assertRaises(module.SkipListError) as raised:
                module.check(root)
            self.assertIn("no device test classes", str(raised.exception))

    def test_repository_tree_is_covered(self) -> None:
        # The shipped gate: every device class in the real tree is skipped, and
        # the parser still recognises the classes it is meant to protect.
        module.check(REPO_ROOT)
        required = module.required_class_names(REPO_ROOT)
        self.assertIn("DeviceSecureEnclaveTests", required)
        self.assertIn("DeviceMIETests", required)
        self.assertNotIn("DeviceSecurityTestCase", required)


if __name__ == "__main__":
    unittest.main()
