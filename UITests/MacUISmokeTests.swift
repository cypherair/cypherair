import XCTest

@MainActor
final class MacUISmokeTests: XCTestCase {
    private enum TutorialIDs {
        static let hubReady = "tutorial.hub.ready"
        static let sandboxReady = "tutorial.module.sandbox.ready"
        static let demoIdentityReady = "tutorial.module.identity.ready"
        static let demoContactReady = "tutorial.module.contact.ready"
        static let encryptReady = "tutorial.module.encrypt.ready"
        static let decryptReady = "tutorial.module.decrypt.ready"
        static let backupReady = "tutorial.module.backup.ready"
        static let coreCompletionReady = "tutorial.completion.core.ready"
        static let moduleCompletionReady = "tutorial.completion.module.ready"
        static let leaveConfirmationReady = "tutorial.leave.ready"
        static let authModalReady = "tutorial.modal.auth.ready"

        static let hubPrimaryAction = "tutorial.hub.primary"
        static let hubBackupModule = "tutorial.hub.module.backupKey"
        static let hubDemoIdentityModule = "tutorial.hub.module.demoIdentity"
        static let hubDemoContactModule = "tutorial.hub.module.demoContact"
        static let hubEncryptModule = "tutorial.hub.module.encryptMessage"
        static let hubDecryptModule = "tutorial.hub.module.decryptAndVerify"
        static let closeButton = "tutorial.close"
        static let primaryAction = "tutorial.primaryAction"
        static let returnButton = "tutorial.return"
        static let exploreAdvanced = "tutorial.exploreAdvanced"
        static let leaveContinue = "tutorial.leave.continue"
        static let leaveConfirm = "tutorial.leave.confirm"
        static let modalConfirm = "tutorial.modal.confirm"
    }

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

    func test_tutorialRoot_startsCoreTutorialFromHub() throws {
        launchTutorial()

        element(TutorialIDs.hubPrimaryAction).tap()

        waitForScreenReady(TutorialIDs.sandboxReady)
    }

    func test_tutorialCore_inProgressCloseShowsLeaveConfirmation() throws {
        launchTutorial()
        element(TutorialIDs.hubPrimaryAction).tap()
        waitForScreenReady(TutorialIDs.sandboxReady)

        element(TutorialIDs.closeButton).tap()

        waitForScreenReady(TutorialIDs.leaveConfirmationReady)
        XCTAssertTrue(element(TutorialIDs.leaveContinue).exists)
        XCTAssertTrue(element(TutorialIDs.leaveConfirm).exists)
    }

    func test_tutorialCore_completionUnlocksAdvancedModules() throws {
        launchTutorial(completedCore: true)

        XCTAssertTrue(element(TutorialIDs.hubBackupModule).exists)
    }

    func test_tutorialAdvancedBackup_canCompleteFromHub() throws {
        launchTutorial(completedCore: true)

        element(TutorialIDs.hubBackupModule).tap()
        waitForScreenReady(TutorialIDs.backupReady)

        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.moduleCompletionReady)
    }

    // MARK: - Launch Helpers

    private func launchMain() {
        app.launchEnvironment["UITEST_ROOT"] = "main"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
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
        app.launch()
        waitForLaunchReadiness(rootReadyID: "settings.ready")
    }

    private func launchTutorial(
        completedCore: Bool = false,
        completedModules: [String] = []
    ) {
        app.launchEnvironment["UITEST_ROOT"] = "tutorial"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        app.launchEnvironment["UITEST_COMPLETE_GUIDED_TUTORIAL"] = completedCore ? "1" : "0"
        if !completedModules.isEmpty {
            app.launchEnvironment["UITEST_COMPLETED_TUTORIAL_MODULES"] = completedModules.joined(separator: ",")
        }
        app.launch()
        waitForLaunchReadiness(rootReadyID: TutorialIDs.hubReady)
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

    private func completeCoreTutorial() {
        element(TutorialIDs.hubPrimaryAction).tap()
        waitForScreenReady(TutorialIDs.sandboxReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.hubReady)

        element(TutorialIDs.hubDemoIdentityModule).tap()
        waitForScreenReady(TutorialIDs.demoIdentityReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.demoIdentityReady)
        element(TutorialIDs.returnButton).tap()
        waitForScreenReady(TutorialIDs.hubReady)

        element(TutorialIDs.hubDemoContactModule).tap()
        waitForScreenReady(TutorialIDs.demoContactReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.demoContactReady)
        element(TutorialIDs.returnButton).tap()
        waitForScreenReady(TutorialIDs.hubReady)

        element(TutorialIDs.hubEncryptModule).tap()
        waitForScreenReady(TutorialIDs.encryptReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.encryptReady)
        element(TutorialIDs.returnButton).tap()
        waitForScreenReady(TutorialIDs.hubReady)

        element(TutorialIDs.hubDecryptModule).tap()
        waitForScreenReady(TutorialIDs.decryptReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.decryptReady)
        element(TutorialIDs.primaryAction).tap()
        waitForScreenReady(TutorialIDs.authModalReady)
        element(TutorialIDs.modalConfirm).tap()
    }

    // MARK: - Element Helpers

    private func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
    }

    private func waitForLaunchReadiness(rootReadyID: String) {
        let timeout = requiresManualAuthentication ? manualAuthenticationTimeout : 20
        let unlocked = element(rootReadyID).waitForExistence(timeout: timeout)
        XCTAssertTrue(
            unlocked,
            "Timed out waiting for manual Touch ID / Face ID authentication to complete before interacting with the UI."
        )
    }

    private func waitForScreenReady(_ identifier: String, timeout: TimeInterval = 10) {
        XCTAssertTrue(
            element(identifier).waitForExistence(timeout: timeout),
            "Expected ready marker \(identifier) to appear."
        )
    }
}
