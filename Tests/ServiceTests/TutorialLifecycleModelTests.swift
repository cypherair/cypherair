import XCTest
@testable import CypherAir

@MainActor
final class TutorialLifecycleModelTests: XCTestCase {
    func test_tutorialCapabilityPolicy_deniesRealWorldCapabilities() {
        let policy = TutorialCapabilityPolicy()

        for capability in TutorialCapabilityPolicy.Capability.allCases {
            XCTAssertFalse(policy.allows(capability), "Capability \(capability.rawValue) should be blocked in tutorial mode.")
        }
    }

    func test_tutorialLifecycle_coreStepsDoNotPersistCompletionUntilFinish() async throws {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.lifecycle.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        let model = TutorialLifecycleModel(launchOrigin: .inApp)
        model.configure(appConfiguration: config)

        try await completeCoreTutorialSteps(using: model)

        XCTAssertEqual(model.lifecycleState, .coreStepsCompleted)
        XCTAssertEqual(config.guidedTutorialCompletedVersion, 0)
        XCTAssertEqual(config.guidedTutorialCompletionState, .neverCompleted)

        model.completeCoreFinish(stayInTutorial: true)

        XCTAssertEqual(config.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
        XCTAssertEqual(config.guidedTutorialCompletionState, .completedCurrentVersion)
        XCTAssertEqual(model.lifecycleState, .coreFinished)
    }

    func test_tutorialLifecycle_advancedModuleCompletionPersistsSeparately() async throws {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.advanced.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        config.markGuidedTutorialCompletedCurrentVersion()

        let model = TutorialLifecycleModel(launchOrigin: .inApp)
        model.configure(appConfiguration: config)

        await model.openModule(.backupKey)
        await model.createTutorialBackup(passphrase: "demo-passphrase")

        XCTAssertEqual(model.lifecycleState, .moduleCompleted(.backupKey))
        XCTAssertEqual(config.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
        XCTAssertEqual(config.completedGuidedTutorialModulesCurrentVersion, [.backupKey])
    }

    func test_tutorialLifecycle_resetClearsLiveSessionButKeepsPersistentHistory() async throws {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.reset.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        config.markGuidedTutorialCompletedCurrentVersion()
        config.markGuidedTutorialModuleCompleted(TutorialModuleID.backupKey.rawValue)

        let model = TutorialLifecycleModel(launchOrigin: .inApp)
        model.configure(appConfiguration: config)

        await model.openModule(.enableHighSecurity)
        XCTAssertNotNil(model.activeSession)

        model.resetCurrentTutorialSession()

        XCTAssertNil(model.activeSession)
        XCTAssertEqual(model.surface, .hub)
        XCTAssertEqual(model.completedAdvancedModules, [.backupKey])
        XCTAssertEqual(config.guidedTutorialCompletedVersion, GuidedTutorialVersion.current)
    }

    func test_tutorialLifecycle_advancedSessionsAreDistinctFromCoreSessions() async throws {
        let defaults = UserDefaults(suiteName: "com.cypherair.tests.tutorial.sessions.\(UUID().uuidString)")!
        let config = AppConfiguration(defaults: defaults)
        config.markGuidedTutorialCompletedCurrentVersion()

        let model = TutorialLifecycleModel(launchOrigin: .inApp)
        model.configure(appConfiguration: config)

        await model.startCoreTutorial()
        let coreSessionID = try XCTUnwrap(model.activeSession?.id.rawValue)

        await model.openModule(.backupKey)
        let advancedSessionID = try XCTUnwrap(model.activeSession?.id.rawValue)

        XCTAssertNotEqual(coreSessionID, advancedSessionID)
        XCTAssertEqual(model.activeLayer, .advanced)
    }

    private func completeCoreTutorialSteps(using model: TutorialLifecycleModel) async throws {
        await model.startCoreTutorial()
        model.acknowledgeSandbox()
        model.returnToHub()

        await model.openModule(.demoIdentity)
        await model.createDemoIdentity(name: "Alice Demo", email: "alice@demo.invalid")
        model.returnToHub()

        await model.openModule(.demoContact)
        try model.addDemoContact()
        model.returnToHub()

        await model.openModule(.encryptMessage)
        await model.encryptDemoMessage("Hello from the rebuilt tutorial")
        model.returnToHub()

        await model.openModule(.decryptAndVerify)
        await model.inspectRecipients()
        model.beginDecryptContinuation()
        await model.confirmAuthContinuation()
    }
}
