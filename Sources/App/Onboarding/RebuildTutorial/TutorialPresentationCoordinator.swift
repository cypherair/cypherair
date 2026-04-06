import Foundation
#if canImport(XCTest) && canImport(CypherAir)
@testable import CypherAir
#endif

@MainActor
@Observable
final class TutorialPresentationCoordinator {
    struct MacTutorialRequest: Identifiable, Equatable {
        let id = UUID()
        let origin: TutorialLaunchOrigin
    }

    var activeMacTutorialRequest: MacTutorialRequest?
    var pendingMacPresentation: MacPresentation?

    func presentMacTutorial(origin: TutorialLaunchOrigin) {
        activeMacTutorialRequest = MacTutorialRequest(origin: origin)
    }

    func dismissMacTutorial() {
        activeMacTutorialRequest = nil
    }

    func queueMacPresentation(_ presentation: MacPresentation) {
        pendingMacPresentation = presentation
    }

    func drainPendingMacPresentation() -> MacPresentation? {
        defer { pendingMacPresentation = nil }
        return pendingMacPresentation
    }
}
