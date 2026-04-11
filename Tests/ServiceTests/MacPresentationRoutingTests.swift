import SwiftUI
import XCTest
@testable import CypherAir

@MainActor
final class MacPresentationRoutingTests: XCTestCase {
    func test_tutorialHostAvailability_appLevelBlockers_eachPreventTutorialPresentation() {
        let availability = MacTutorialHostAvailability()
        let appLevelBlockers: [MacTutorialHostBlocker] = [
            .importConfirmationSheet,
            .importErrorAlert,
            .keyUpdateAlert,
            .tutorialImportBlockedAlert,
            .loadWarningAlert
        ]

        for blocker in appLevelBlockers {
            availability.setAppLevelBlocker(blocker, isActive: true)
            XCTAssertFalse(
                availability.canPresentTutorialInMainWindow,
                "\(blocker.rawValue) should block tutorial presentation"
            )
            availability.setAppLevelBlocker(blocker, isActive: false)
            XCTAssertTrue(
                availability.canPresentTutorialInMainWindow,
                "\(blocker.rawValue) should unblock tutorial presentation when cleared"
            )
        }
    }

    func test_tutorialHostAvailability_hostManagedPresentations_blockAsExpected() {
        let availability = MacTutorialHostAvailability()

        availability.updateHostPresentation(
            .importConfirmation(
                ImportConfirmationRequest(
                    keyData: Data(),
                    keyInfo: testKeyInfo(),
                    profile: .universal,
                    allowsUnverifiedImport: true,
                    onImportVerified: {},
                    onImportUnverified: {},
                    onCancel: {}
                )
            )
        )
        XCTAssertFalse(availability.canPresentTutorialInMainWindow)

        availability.updateHostPresentation(
            .authModeConfirmation(SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest())
        )
        XCTAssertFalse(availability.canPresentTutorialInMainWindow)

        availability.updateHostPresentation(
            .modifyExpiry(
                ModifyExpiryRequest(
                    fingerprint: "abc123",
                    initialDate: Date()
                )
            )
        )
        XCTAssertFalse(availability.canPresentTutorialInMainWindow)

        availability.updateHostPresentation(.onboarding(initialPage: 0))
        XCTAssertFalse(availability.canPresentTutorialInMainWindow)

        availability.updateHostPresentation(.tutorial(presentationContext: .inApp))
        XCTAssertTrue(availability.canPresentTutorialInMainWindow)

        availability.updateHostPresentation(nil)
        XCTAssertTrue(availability.canPresentTutorialInMainWindow)
    }

    func test_settingsSceneController_presentsOnboardingLocally() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        let availability = MacTutorialHostAvailability()
        var openMainWindowCount = 0
        var blockedCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            tutorialHostAvailability: availability,
            onTutorialLaunchBlocked: {
                blockedCount += 1
            },
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.onboarding(initialPage: 1))

        guard case .onboarding(let initialPage)? = storage.activePresentation else {
            return XCTFail("Expected onboarding to remain local to the settings scene")
        }
        XCTAssertEqual(initialPage, 1)
        XCTAssertEqual(openMainWindowCount, 0)
        XCTAssertNil(relay.pendingRequest)
        XCTAssertEqual(blockedCount, 0)
    }

    func test_settingsSceneController_routesDirectTutorialRequestToMainWindow() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        let availability = MacTutorialHostAvailability()
        var openMainWindowCount = 0
        var blockedCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            tutorialHostAvailability: availability,
            onTutorialLaunchBlocked: {
                blockedCount += 1
            },
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.tutorial(presentationContext: .inApp))

        XCTAssertNil(storage.activePresentation)
        XCTAssertEqual(openMainWindowCount, 1)
        XCTAssertEqual(relay.pendingRequest?.presentationContext, .inApp)
        XCTAssertEqual(blockedCount, 0)
    }

    func test_settingsSceneController_showsBlockedNoticeWhenMainWindowIsBusy() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        let availability = MacTutorialHostAvailability()
        availability.setAppLevelBlocker(.loadWarningAlert, isActive: true)
        var openMainWindowCount = 0
        var blockedCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            tutorialHostAvailability: availability,
            onTutorialLaunchBlocked: {
                blockedCount += 1
            },
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.tutorial(presentationContext: .inApp))

        XCTAssertNil(storage.activePresentation)
        XCTAssertEqual(openMainWindowCount, 0)
        XCTAssertNil(relay.pendingRequest)
        XCTAssertEqual(blockedCount, 1)
    }

    func test_settingsSceneController_routesOnboardingToTutorialHandoffToMainWindow() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        let availability = MacTutorialHostAvailability()
        var openMainWindowCount = 0
        var blockedCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            tutorialHostAvailability: availability,
            onTutorialLaunchBlocked: {
                blockedCount += 1
            },
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.onboarding(initialPage: 2))
        controller.present(.tutorial(presentationContext: .onboardingFirstRun))

        XCTAssertNil(storage.activePresentation)
        XCTAssertEqual(openMainWindowCount, 1)
        XCTAssertEqual(relay.pendingRequest?.presentationContext, .onboardingFirstRun)
        XCTAssertEqual(blockedCount, 0)
    }

    func test_settingsSceneController_keepsOnboardingOpenWhenTutorialLaunchIsBlocked() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        let availability = MacTutorialHostAvailability()
        availability.updateHostPresentation(.authModeConfirmation(SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()))
        var openMainWindowCount = 0
        var blockedCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            tutorialHostAvailability: availability,
            onTutorialLaunchBlocked: {
                blockedCount += 1
            },
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.onboarding(initialPage: 2))
        controller.present(.tutorial(presentationContext: .onboardingFirstRun))

        guard case .onboarding(let initialPage)? = storage.activePresentation else {
            return XCTFail("Expected onboarding to stay visible when tutorial launch is blocked")
        }

        XCTAssertEqual(initialPage, 2)
        XCTAssertEqual(openMainWindowCount, 0)
        XCTAssertNil(relay.pendingRequest)
        XCTAssertEqual(blockedCount, 1)
    }

    func test_relay_submit_sameContextTwice_generatesDistinctRequestIDs() throws {
        let relay = MacTutorialLaunchRelay()
        relay.submit(.inApp)
        let firstRequestID = try XCTUnwrap(relay.pendingRequest?.id)

        relay.submit(.inApp)
        let secondRequestID = try XCTUnwrap(relay.pendingRequest?.id)

        XCTAssertNotEqual(firstRequestID, secondRequestID)
    }

    func test_relay_clearIfMatches_doesNotClearNewerPendingRequest() throws {
        let relay = MacTutorialLaunchRelay()
        relay.submit(.inApp)
        let firstRequestID = try XCTUnwrap(relay.pendingRequest?.id)

        relay.submit(.onboardingFirstRun)
        let secondRequestID = try XCTUnwrap(relay.pendingRequest?.id)
        relay.clearIfMatches(firstRequestID)

        XCTAssertEqual(relay.pendingRequest?.id, secondRequestID)
        XCTAssertEqual(relay.pendingRequest?.presentationContext, .onboardingFirstRun)
    }

    private func binding(for storage: PresentationStorage) -> Binding<MacPresentation?> {
        Binding(
            get: { storage.activePresentation },
            set: { storage.activePresentation = $0 }
        )
    }

    private func testKeyInfo() -> KeyInfo {
        KeyInfo(
            fingerprint: "abc123",
            keyVersion: 4,
            userId: "alice@example.com",
            hasEncryptionSubkey: true,
            isRevoked: false,
            isExpired: false,
            profile: .universal,
            primaryAlgo: "Ed25519",
            subkeyAlgo: "X25519",
            expiryTimestamp: nil
        )
    }
}

@MainActor
private final class PresentationStorage {
    var activePresentation: MacPresentation?
}
