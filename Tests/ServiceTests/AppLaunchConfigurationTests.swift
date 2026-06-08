import XCTest
@testable import CypherAir

final class AppLaunchConfigurationTests: XCTestCase {
    func test_debugGateHonorsUITestLaunchOverrides() {
        let configuration = AppLaunchConfiguration(
            environment: [
                "UITEST_ROOT": "tutorial",
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_TUTORIAL_TASK": "enableHighSecurity",
                "UITEST_REQUIRE_MANUAL_AUTH": "1",
                "UITEST_OPEN_AUTHMODE_CONFIRMATION": "1",
                "UITEST_PRELOAD_CONTACT": "1"
            ],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: true
        )

        XCTAssertEqual(configuration.root, .tutorial)
        XCTAssertTrue(configuration.isUITestMode)
        XCTAssertFalse(configuration.isXCTestHost)
        XCTAssertTrue(configuration.usesUITestAppContainer)
        XCTAssertTrue(configuration.shouldSkipOnboarding)
        XCTAssertEqual(configuration.tutorialModule, .enableHighSecurity)
        XCTAssertTrue(configuration.requiresManualAuthentication)
        XCTAssertTrue(configuration.opensAuthModeConfirmation)
        XCTAssertTrue(configuration.preloadsUITestContact)
    }

    func test_debugGateHonorsXCTestHostDetection() {
        let configuration = AppLaunchConfiguration(
            environment: [:],
            detectsXCTestHost: true,
            allowsUITestLaunchOverrides: true
        )

        XCTAssertEqual(configuration.root, .main)
        XCTAssertFalse(configuration.isUITestMode)
        XCTAssertTrue(configuration.isXCTestHost)
        XCTAssertTrue(configuration.usesUITestAppContainer)
        XCTAssertFalse(configuration.shouldSkipOnboarding)
        XCTAssertNil(configuration.tutorialModule)
    }

    func test_releaseGateIgnoresUITestLaunchOverrides() {
        let configuration = AppLaunchConfiguration(
            environment: [
                "UITEST_ROOT": "tutorial",
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_TUTORIAL_TASK": "enableHighSecurity",
                "UITEST_REQUIRE_MANUAL_AUTH": "1",
                "UITEST_OPEN_AUTHMODE_CONFIRMATION": "1",
                "UITEST_PRELOAD_CONTACT": "1"
            ],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: false
        )

        XCTAssertEqual(configuration.root, .main)
        XCTAssertFalse(configuration.isUITestMode)
        XCTAssertFalse(configuration.isXCTestHost)
        XCTAssertFalse(configuration.usesUITestAppContainer)
        XCTAssertFalse(configuration.shouldSkipOnboarding)
        XCTAssertNil(configuration.tutorialModule)
        XCTAssertFalse(configuration.requiresManualAuthentication)
        XCTAssertFalse(configuration.opensAuthModeConfirmation)
        XCTAssertFalse(configuration.preloadsUITestContact)
    }

    func test_releaseGateIgnoresXCTestHostDetection() {
        let configuration = AppLaunchConfiguration(
            environment: [:],
            detectsXCTestHost: true,
            allowsUITestLaunchOverrides: false
        )

        XCTAssertEqual(configuration.root, .main)
        XCTAssertFalse(configuration.isUITestMode)
        XCTAssertFalse(configuration.isXCTestHost)
        XCTAssertFalse(configuration.usesUITestAppContainer)
        XCTAssertFalse(configuration.shouldSkipOnboarding)
        XCTAssertNil(configuration.tutorialModule)
    }

    func test_retiredSettingsRoot_fallsBackToMain() {
        // The standalone macOS settings surface (UITEST_ROOT="settings") was removed in
        // the single-window unification; the now-unknown value must fall back to .main.
        let configuration = AppLaunchConfiguration(
            environment: ["UITEST_ROOT": "settings"],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: true
        )

        XCTAssertEqual(configuration.root, .main)
        XCTAssertTrue(configuration.isUITestMode)
    }
}
