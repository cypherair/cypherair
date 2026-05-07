import XCTest

@MainActor
final class MacUISmokeTests: XCTestCase {
    private var app: XCUIApplication!
    private let manualAuthenticationTimeout: TimeInterval = 45
    private let requiresManualAuthentication =
        ProcessInfo.processInfo.environment["UITEST_REQUIRE_MANUAL_AUTH"] == "1"

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = MainActor.assumeIsolated {
            XCUIApplication()
        }
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

    func test_mainFlow_keyDetail_opensSelectiveRevocation() throws {
        launchMain()
        generateKey()

        element("postgen.keyDetail").tap()
        waitForScreenReady("keydetail.ready")

        element("keydetail.selectiveRevocation").tap()

        waitForScreenReady("selectiverevocation.ready")
    }

    func test_mainFlow_contacts_opensCertificateSignatures() throws {
        launchMain(preloadContact: true)

        element("sidebar.contacts").tap()
        XCTAssertTrue(element("contacts.row").waitForExistence(timeout: 10))
        element("contacts.row").tap()

        waitForScreenReady("contactdetail.ready")

        element("contactdetail.certificateSignatures").tap()

        waitForScreenReady("contactcertsig.ready")
    }

    func test_settingsRoot_opensThemePicker() throws {
        launchSettings()

        tapSettingsRow("settings.theme")

        waitForScreenReady("theme.ready")
    }

    func test_settingsRoot_opensSelfTest() throws {
        launchSettings()

        tapSettingsRow("settings.selfTest")

        waitForScreenReady("selftest.ready")
    }

    func test_settingsRoot_opensAbout() throws {
        launchSettings()

        tapSettingsRow("settings.about")

        waitForScreenReady("about.ready")
    }

    func test_settingsRoot_aboutOpensSourceCompliance() throws {
        launchSettings()

        tapSettingsRow("settings.about")
        waitForScreenReady("about.ready")

        element("about.sourceCompliance").tap()

        waitForScreenReady("sourcecompliance.ready")
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

    func test_tutorial_keyDetail_showsDisabledSelectiveRevocationEntry() throws {
        launchTutorial(task: "generateAliceKey")
        generateTutorialKey()

        element("postgen.keyDetail").tap()

        waitForScreenReady("keydetail.ready")
        XCTAssertTrue(element("keydetail.selectiveRevocation").exists)
        XCTAssertFalse(element("keydetail.selectiveRevocation").isEnabled)
    }

    func test_tutorial_contactDetail_showsDisabledCertificateSignatureEntry() throws {
        launchTutorial(task: "addDemoContact", preloadedContactDetail: true)

        waitForScreenReady("contactdetail.ready")
        XCTAssertTrue(element("contactdetail.certificateSignatures").exists)
        XCTAssertFalse(element("contactdetail.certificateSignatures").isEnabled)
    }

    func test_tutorial_firstRunOnboardingStart_launchesTutorial() throws {
        launchFirstRunOnboarding()
        navigateToTutorialDecisionPage()

        element("onboarding.tutorial.start").tap()

        waitForScreenReady("tutorial.hub.ready")
    }

    func test_tutorial_firstRunOnboardingSkip_entersMainApp() throws {
        launchFirstRunOnboarding()
        navigateToTutorialDecisionPage()

        element("onboarding.tutorial.skip").tap()

        waitForElementToDisappear("onboarding.tutorialDecision.ready")
        XCTAssertTrue(element("main.ready").exists)
        XCTAssertFalse(element("tutorial.ready").exists)
    }

    func test_tutorial_leaveConfirmation_continueAndLeaveFromSettingsLaunch() throws {
        launchMain()
        openSettingsTab()
        element("settings.tutorial").tap()

        waitForScreenReady("tutorial.hub.ready")
        element("tutorial.primaryAction.toolbar").tap()
        waitForScreenReady("tutorial.sandbox.ready")
        element("tutorial.module.0.open").tap()
        waitForScreenReady("tutorial.module.1.ready")

        element("tutorial.return").tap()
        waitForScreenReady("tutorial.hub.ready")
        element("tutorial.close").tap()
        waitForScreenReady("tutorial.leave.ready")
        XCTAssertTrue(element("tutorial.modalGuidance").exists)

        element("tutorial.leave.continue").tap()
        waitForScreenReady("tutorial.hub.ready")

        element("tutorial.close").tap()
        waitForScreenReady("tutorial.leave.ready")
        element("tutorial.leave.confirm").tap()
        waitForElementToDisappear("tutorial.ready")
        XCTAssertTrue(element("settings.ready").exists)
    }

    func test_tutorial_completionFinish_allowsSettingsReplay() throws {
        launchMain(extraEnvironment: ["UITEST_TUTORIAL_COMPLETION": "1"])
        openSettingsTab()
        element("settings.tutorial").tap()

        waitForScreenReady("tutorial.completion.ready")
        element("tutorial.finish.toolbar").tap()
        waitForElementToDisappear("tutorial.completion.ready")

        element("settings.tutorial").tap()
        waitForScreenReady("tutorial.hub.ready")
        XCTAssertTrue(element("tutorial.primaryAction").exists)
    }

    func test_tutorial_authModeConfirmation_exposesGuidanceAndActions() throws {
        launchTutorial(
            task: "enableHighSecurity",
            extraEnvironment: ["UITEST_TUTORIAL_AUTHMODE_CONFIRMATION": "1"]
        )

        waitForScreenReady("tutorial.authMode.ready")
        XCTAssertTrue(element("tutorial.modalGuidance").exists)
        XCTAssertTrue(element("tutorial.authMode.riskAcknowledgement").exists)
        XCTAssertFalse(element("tutorial.authMode.confirm").isEnabled)

        element("tutorial.authMode.riskAcknowledgement").tap()
        waitForElementEnabled(element("tutorial.authMode.confirm"))
        XCTAssertTrue(element("tutorial.authMode.cancel").exists)
    }

    func test_tutorial_workspaceGuidance_usesSingleReturnSurface() throws {
        launchTutorial(task: "generateAliceKey")

        if element("tutorial.hub.ready").waitForExistence(timeout: 2) {
            element("tutorial.primaryAction").tap()
        }
        if element("tutorial.sandbox.ready").waitForExistence(timeout: 2) {
            element("tutorial.module.0.open").tap()
        }
        waitForScreenReady("tutorial.module.1.ready")

        XCTAssertEqual(
            matchingElementCount("tutorial.return"),
            1,
            "The macOS tutorial workspace should not show duplicate return controls while the guidance rail is visible."
        )

        element("keys.generate").tap()
        waitForScreenReady("keygen.ready")
        app.buttons["Generate Key"].tap()
        waitForScreenReady("postgen.ready", timeout: 15)
        XCTAssertTrue(element("tutorial.completionPrompt.primary").waitForExistence(timeout: 5))
        XCTAssertEqual(
            matchingElementCount("tutorial.return"),
            0,
            "The completion prompt should be the only tutorial action surface after a task completes."
        )
    }

    func test_tutorial_addContactPrefilledPaste_keepsAddActionHittable() throws {
        launchTutorial(task: "generateAliceKey")
        generateTutorialKey()
        completeCurrentTutorialTaskFromPrompt()

        waitForScreenReady("tutorial.hub.ready")
        element("tutorial.primaryAction").tap()
        waitForScreenReady("tutorial.module.2.ready")

        element("contacts.add").tap()
        let addContactButton = element("addcontact.add")
        XCTAssertTrue(addContactButton.waitForExistence(timeout: 10))
        XCTAssertTrue(
            addContactButton.isHittable,
            "The prefilled Bob public key editor should not push Add Contact offscreen in the tutorial."
        )
    }

    // MARK: - Launch Helpers

    private func launchMain(
        preloadContact: Bool = false,
        extraEnvironment: [String: String] = [:]
    ) {
        app.launchEnvironment["UITEST_ROOT"] = "main"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        app.launchEnvironment["UITEST_PRELOAD_CONTACT"] = preloadContact ? "1" : "0"
        apply(extraEnvironment: extraEnvironment)
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "main.ready")
    }

    private func launchFirstRunOnboarding() {
        app.launchEnvironment["UITEST_ROOT"] = "main"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "main.ready")
    }

    private func launchSettings() {
        launchSettings(openAuthModeConfirmation: false)
    }

    private func launchSettings(
        openAuthModeConfirmation: Bool,
        extraEnvironment: [String: String] = [:]
    ) {
        app.launchEnvironment["UITEST_ROOT"] = "settings"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        app.launchEnvironment["UITEST_OPEN_AUTHMODE_CONFIRMATION"] = openAuthModeConfirmation ? "1" : "0"
        apply(extraEnvironment: extraEnvironment)
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "settings.ready")
    }

    private func launchTutorial(
        task: String,
        preloadedContactDetail: Bool = false,
        extraEnvironment: [String: String] = [:]
    ) {
        app.launchEnvironment["UITEST_ROOT"] = "tutorial"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_TUTORIAL_TASK"] = task
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = requiresManualAuthentication ? "1" : "0"
        app.launchEnvironment["UITEST_TUTORIAL_CONTACT_DETAIL"] = preloadedContactDetail ? "1" : "0"
        apply(extraEnvironment: extraEnvironment)
        prepareLaunchIgnoringSavedState()
        app.launch()
        waitForLaunchReadiness(rootReadyID: "tutorial.ready")
    }

    private func apply(extraEnvironment: [String: String]) {
        for (key, value) in extraEnvironment {
            app.launchEnvironment[key] = value
        }
    }

    private func prepareLaunchIgnoringSavedState() {
        app.launchArguments = ["-ApplePersistenceIgnoreState", "YES"]
    }

    // MARK: - Flow Helpers

    private func navigateToTutorialDecisionPage() {
        if element("onboarding.tutorialDecision.ready").waitForExistence(timeout: 1) {
            return
        }

        for _ in 0..<2 where !element("onboarding.tutorialDecision.ready").exists {
            XCTAssertTrue(app.buttons["Next"].waitForExistence(timeout: 5))
            app.buttons["Next"].tap()
        }

        waitForScreenReady("onboarding.tutorialDecision.ready")
    }

    private func openSettingsTab() {
        if element("settings.ready").exists {
            return
        }

        element("sidebar.settings").tap()
        waitForScreenReady("settings.ready")
    }

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

    private func completeCurrentTutorialTaskFromPrompt() {
        let primaryPromptAction = element("tutorial.completionPrompt.primary")
        if primaryPromptAction.waitForExistence(timeout: 5) {
            primaryPromptAction.tap()
            return
        }

        let fallback = app.buttons["Return to Tutorial Overview"].firstMatch
        XCTAssertTrue(fallback.waitForExistence(timeout: 5))
        fallback.tap()
    }

    // MARK: - Element Helpers

    private func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
    }

    private func matchingElementCount(_ identifier: String) -> Int {
        app.descendants(matching: .any)
            .matching(identifier: identifier)
            .count
    }

    private func tapSettingsRow(_ identifier: String) {
        let row = element(identifier)
        XCTAssertTrue(row.waitForExistence(timeout: 10))

        let settingsRoot = element("settings.root")
        XCTAssertTrue(settingsRoot.waitForExistence(timeout: 5))
        scroll(row, fullyInto: settingsRoot)

        XCTAssertTrue(
            isFullyVisible(row, in: settingsRoot),
            "Expected \(identifier) to be fully visible in the Settings scroll area before tapping."
        )
        XCTAssertTrue(row.isHittable, "Expected \(identifier) to be hittable before tapping.")
        row.tap()
    }

    private func scroll(_ row: XCUIElement, fullyInto scrollArea: XCUIElement) {
        for _ in 0..<6 where !isFullyVisible(row, in: scrollArea) {
            if row.frame.midY < scrollArea.frame.midY {
                scrollArea.swipeDown()
            } else {
                scrollArea.swipeUp()
            }
        }
    }

    private func isFullyVisible(_ row: XCUIElement, in scrollArea: XCUIElement) -> Bool {
        guard row.exists, scrollArea.exists else { return false }

        let rowFrame = row.frame
        let visibleFrame = scrollArea.frame.insetBy(dx: 0, dy: 4)
        return rowFrame.minX >= visibleFrame.minX
            && rowFrame.maxX <= visibleFrame.maxX
            && rowFrame.minY >= visibleFrame.minY
            && rowFrame.maxY <= visibleFrame.maxY
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

    private func waitForElementToDisappear(
        _ identifier: String,
        timeout: TimeInterval = 10
    ) {
        let target = element(identifier)
        let predicate = NSPredicate(format: "exists == false")
        let expectation = XCTNSPredicateExpectation(predicate: predicate, object: target)
        XCTAssertEqual(
            XCTWaiter.wait(for: [expectation], timeout: timeout),
            .completed,
            "Expected element \(identifier) to disappear."
        )
    }

    private func waitForElementEnabled(
        _ element: XCUIElement,
        timeout: TimeInterval = 10
    ) {
        XCTAssertTrue(
            element.waitForExistence(timeout: timeout),
            "Expected element \(element) to appear."
        )

        let predicate = NSPredicate(format: "isEnabled == true")
        let expectation = XCTNSPredicateExpectation(predicate: predicate, object: element)
        XCTAssertEqual(
            XCTWaiter.wait(for: [expectation], timeout: timeout),
            .completed,
            "Expected element to become enabled."
        )
    }
}
