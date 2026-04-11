import SwiftUI
import XCTest
@testable import CypherAir

@MainActor
final class MacPresentationRoutingTests: XCTestCase {
    func test_settingsSceneController_presentsOnboardingLocally() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        var openMainWindowCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
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
    }

    func test_settingsSceneController_routesDirectTutorialRequestToMainWindow() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        var openMainWindowCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.tutorial(presentationContext: .inApp))

        XCTAssertNil(storage.activePresentation)
        XCTAssertEqual(openMainWindowCount, 1)
        XCTAssertEqual(relay.pendingRequest?.presentationContext, .inApp)
    }

    func test_settingsSceneController_routesOnboardingToTutorialHandoffToMainWindow() {
        let storage = PresentationStorage()
        let relay = MacTutorialLaunchRelay()
        var openMainWindowCount = 0

        let controller = MacPresentationController.settingsScene(
            activePresentation: binding(for: storage),
            tutorialLaunchRelay: relay,
            openMainWindow: {
                openMainWindowCount += 1
            }
        )

        controller.present(.onboarding(initialPage: 2))
        controller.present(.tutorial(presentationContext: .onboardingFirstRun))

        XCTAssertNil(storage.activePresentation)
        XCTAssertEqual(openMainWindowCount, 1)
        XCTAssertEqual(relay.pendingRequest?.presentationContext, .onboardingFirstRun)
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

    func test_relay_pendingPresentation_allowsTutorialWhenMainWindowIsIdle() {
        let relay = MacTutorialLaunchRelay()
        relay.submit(.inApp)

        guard case .tutorial(let presentationContext)? = relay.pendingPresentation(currentPresentation: nil) else {
            return XCTFail("Expected tutorial presentation when the main window is idle")
        }

        XCTAssertEqual(presentationContext, .inApp)
    }

    func test_relay_pendingPresentation_canReplaceOnboarding() {
        let relay = MacTutorialLaunchRelay()
        relay.submit(.onboardingFirstRun)

        guard case .tutorial(let presentationContext)? = relay.pendingPresentation(
            currentPresentation: .onboarding(initialPage: 0)
        ) else {
            return XCTFail("Expected tutorial relay to replace onboarding")
        }

        XCTAssertEqual(presentationContext, .onboardingFirstRun)
    }

    func test_relay_pendingPresentation_defersWhileMainWindowShowsOtherModal() {
        let relay = MacTutorialLaunchRelay()
        relay.submit(.inApp)

        XCTAssertNil(
            relay.pendingPresentation(
                currentPresentation: .authModeConfirmation(
                    SettingsAuthModeRequestBuilder.makeLaunchPreviewRequest()
                )
            )
        )
        XCTAssertNotNil(relay.pendingRequest)
    }

    private func binding(for storage: PresentationStorage) -> Binding<MacPresentation?> {
        Binding(
            get: { storage.activePresentation },
            set: { storage.activePresentation = $0 }
        )
    }
}

@MainActor
private final class PresentationStorage {
    var activePresentation: MacPresentation?
}
