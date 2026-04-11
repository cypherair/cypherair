import XCTest

@MainActor
final class MacUISmokeTests: XCTestCase {
    private var app: XCUIApplication!
    private let manualAuthenticationTimeout: TimeInterval = 45
    private let requiresManualAuthentication =
        ProcessInfo.processInfo.environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
    }

    func test_mainFlow_keyReady_opensKeyDetail() throws {
        launchMain()
        generateKey()

        element("postgen.keyDetail").tap()

        waitForScreenReady("keydetail.ready")
    }

    func test_mainFlow_keyReady_opensQRCode() throws {
        launchMain()
        generateKey()

        element("postgen.qr").tap()

        waitForScreenReady("qr.ready")
    }

    func test_mainFlow_keyReady_opensBackup() throws {
        launchMain()
        generateKey()

        element("postgen.backup").tap()

        waitForScreenReady("backup.ready")
    }

    func test_mainFlow_keyDetail_opensModifyExpirySheet() throws {
        launchMain()
        generateKey()

        element("postgen.keyDetail").tap()
        waitForScreenReady("keydetail.ready")

        element("keydetail.modifyExpiry").tap()

        waitForScreenReady("modifyexpiry.ready")
    }

    func test_settingsRoot_opensThemePicker() throws {
        launchSettings()

        element("settings.theme").tap()

        waitForScreenReady("theme.ready")
    }

    func test_settingsRoot_opensSelfTest() throws {
        launchSettings()

        element("settings.selfTest").tap()

        waitForScreenReady("selftest.ready")
    }

    func test_settingsRoot_opensAbout() throws {
        launchSettings()

        element("settings.about").tap()

        waitForScreenReady("about.ready")
    }

    func test_settingsRoot_opensLicenseList() throws {
        launchSettings()

        element("settings.license").tap()

        waitForScreenReady("license.ready")
    }

    func test_settingsRoot_opensAuthModeConfirmation() throws {
        launchSettings(openAuthModeConfirmation: true)

        waitForScreenReady("settings.authmode.ready")
        XCTAssertTrue(element("settings.mode.confirm").exists)
    }

    func test_tutorial_generateAlice_opensKeyDetailFromKeyReady() throws {
        launchTutorial(task: "generateAliceKey")
        generateTutorialKey()

        element("postgen.keyDetail").tap()

        waitForScreenReady("keydetail.ready")
    }

    func test_tutorial_generateAlice_opensQRCodeFromKeyReady() throws {
        launchTutorial(task: "generateAliceKey")
        generateTutorialKey()

        element("postgen.qr").tap()

        waitForScreenReady("qr.ready")
    }

    func test_tutorial_generateAlice_opensBackupFromKeyReady() throws {
        launchTutorial(task: "generateAliceKey")
        generateTutorialKey()

        element("postgen.backup").tap()

        waitForScreenReady("backup.ready")
    }

    // MARK: - Launch Helpers

    private func launchMain() {
        app.launchEnvironment["UITEST_ROOT"] = "main"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "main.ready")
    }

    private func launchSettings() {
        launchSettings(openAuthModeConfirmation: false)
    }

    private func launchSettings(openAuthModeConfirmation: Bool) {
        app.launchEnvironment["UITEST_ROOT"] = "settings"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        app.launchEnvironment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] = openAuthModeConfirmation ? "1" : "0"
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "settings.ready")
    }

    private func launchTutorial(task: String) {
        app.launchEnvironment["UITEST_ROOT"] = "tutorial"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_TUTORIAL_TASK"] = task
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "tutorial.ready")
    }

    private func prepareLaunchIgnoringSavedState() {
        app.launchArguments = ["-ApplePersistenceIgnoreState", "YES"]
    }

    // MARK: - Flow Helpers

    private func generateKey() {
        XCTAssertTrue(element("home.generate").waitForExistence(timeout: 10))
        element("home.generate").tap()

        waitForScreenReady("keygen.ready")
        let nameField = element("keygen.name")
        nameField.tap()
        nameField.typeText("UITest Alice")

        app.buttons["Generate Key"].tap()
        waitForScreenReady("postgen.ready", timeout: 15)
    }

    private func generateTutorialKey() {
        if element("tutorial.hub.ready").waitForExistence(timeout: 2) {
            XCTAssertTrue(element("tutorial.primaryAction").waitForExistence(timeout: 5))
            element("tutorial.primaryAction").tap()
        }

        if element("tutorial.sandbox.ready").waitForExistence(timeout: 2) {
            XCTAssertTrue(element("tutorial.module.0.open").waitForExistence(timeout: 5))
            element("tutorial.module.0.open").tap()
        }

        XCTAssertTrue(element("keys.generate").waitForExistence(timeout: 10))
        element("keys.generate").tap()

        waitForScreenReady("keygen.ready")
        app.buttons["Generate Key"].tap()

        waitForScreenReady("postgen.ready", timeout: 15)
    }

    // MARK: - Element Helpers

    private func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
    }

    private func waitForLaunchReadiness(rootReadyID: String) {
        let timeout = requiresManualAuthentication ? manualAuthenticationTimeout : 10
        let unlocked = element(rootReadyID).waitForExistence(timeout: timeout)
        let failureMessage: String
        if requiresManualAuthentication {
            failureMessage = "Timed out waiting for launch ready marker \(rootReadyID) to appear, or for manual Touch ID / Face ID authentication to complete."
        } else {
            failureMessage = "Expected launch ready marker \(rootReadyID) to appear."
        }
        XCTAssertTrue(
            unlocked,
            failureMessage
        )
    }

    private func waitForScreenReady(_ identifier: String, timeout: TimeInterval = 10) {
        XCTAssertTrue(
            element(identifier).waitForExistence(timeout: timeout),
            "Expected ready marker \(identifier) to appear."
        )
    }
}
