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

    func test_manualAuthStartsUnlocked_requiresTheManualAuthPairing() {
        // The boot-unlocked lock-shield seam must never arm without the
        // manual-auth container: alone, the flag is inert.
        let withoutManualAuth = AppLaunchConfiguration(
            environment: [
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_MANUAL_AUTH_STARTS_UNLOCKED": "1"
            ],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: true
        )
        XCTAssertFalse(withoutManualAuth.manualAuthStartsUnlocked)

        let withManualAuth = AppLaunchConfiguration(
            environment: [
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_REQUIRE_MANUAL_AUTH": "1",
                "UITEST_MANUAL_AUTH_STARTS_UNLOCKED": "1"
            ],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: true
        )
        XCTAssertTrue(withManualAuth.manualAuthStartsUnlocked)
    }

    func test_releaseGateIgnoresManualAuthStartsUnlocked() {
        let configuration = AppLaunchConfiguration(
            environment: [
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_REQUIRE_MANUAL_AUTH": "1",
                "UITEST_MANUAL_AUTH_STARTS_UNLOCKED": "1"
            ],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: false
        )

        XCTAssertFalse(configuration.manualAuthStartsUnlocked)
    }

    /// `bootsPreAuthenticated` is the single predicate that decides whether the
    /// app settles its session as already authenticated at launch, so it is the
    /// one place a UI-test launch can open the lock. It must be true for exactly
    /// the two UI-test flavors that boot pre-authenticated, false for the plain
    /// manual-auth container that has to authenticate for real, and false in a
    /// build where the launch overrides are off.
    func test_bootsPreAuthenticated_coversOnlyTheUITestFlavorsThatBootUnlocked() {
        func configuration(
            _ environment: [String: String],
            allowsUITestLaunchOverrides: Bool = true
        ) -> AppLaunchConfiguration {
            AppLaunchConfiguration(
                environment: environment,
                detectsXCTestHost: false,
                allowsUITestLaunchOverrides: allowsUITestLaunchOverrides
            )
        }

        XCTAssertTrue(
            configuration(["UITEST_SKIP_ONBOARDING": "1"]).bootsPreAuthenticated,
            "A UI-test container that asks for no manual unlock boots pre-authenticated."
        )
        XCTAssertFalse(
            configuration([
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_REQUIRE_MANUAL_AUTH": "1"
            ]).bootsPreAuthenticated,
            "Plain manual auth must reach the real authentication path at launch."
        )
        XCTAssertTrue(
            configuration([
                "UITEST_SKIP_ONBOARDING": "1",
                "UITEST_REQUIRE_MANUAL_AUTH": "1",
                "UITEST_MANUAL_AUTH_STARTS_UNLOCKED": "1"
            ]).bootsPreAuthenticated,
            "The lock-shield seam boots unlocked with the lock armed."
        )
        XCTAssertFalse(
            configuration(
                ["UITEST_SKIP_ONBOARDING": "1"],
                allowsUITestLaunchOverrides: false
            ).bootsPreAuthenticated,
            "With the launch overrides off, nothing may open the lock at launch."
        )
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

    func test_unknownRoot_fallsBackToMain() {
        // An unrecognized UITEST_ROOT value falls back to .main.
        let configuration = AppLaunchConfiguration(
            environment: ["UITEST_ROOT": "unrecognized-root"],
            detectsXCTestHost: false,
            allowsUITestLaunchOverrides: true
        )

        XCTAssertEqual(configuration.root, .main)
        XCTAssertTrue(configuration.isUITestMode)
    }
}
