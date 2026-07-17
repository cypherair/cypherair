import Foundation
import XCTest
@testable import CypherAir

/// The `onOperationPromptsEnded` hook fires exactly when the
/// operation-prompt stack becomes empty — the moment the `.authenticating` rule's
/// deferred away decision is made — and never for privacy prompts.
final class AuthenticationPromptCoordinatorCallbackTests: XCTestCase {
    func test_onOperationPromptsEnded_firesOnlyWhenStackEmpties() {
        let coordinator = AuthenticationPromptCoordinator()
        nonisolated(unsafe) var firedCount = 0
        coordinator.onOperationPromptsEnded = { firedCount += 1 }

        let outer = coordinator.beginOperationPrompt(source: "outer")
        let inner = coordinator.beginOperationPrompt(source: "inner")
        XCTAssertEqual(firedCount, 0)

        coordinator.endOperationPrompt(inner)
        XCTAssertEqual(firedCount, 0, "A nested prompt ending must not fire the hook.")

        coordinator.endOperationPrompt(outer)
        XCTAssertEqual(firedCount, 1, "The hook fires once when the last prompt ends.")

        let next = coordinator.beginOperationPrompt(source: "next")
        coordinator.endOperationPrompt(next)
        XCTAssertEqual(firedCount, 2, "Each completed prompt session fires once.")
    }

    func test_onOperationPromptSessionBegan_firesOnlyWhenStackOpens() {
        let coordinator = AuthenticationPromptCoordinator()
        nonisolated(unsafe) var beganCount = 0
        coordinator.onOperationPromptSessionBegan = { beganCount += 1 }

        let outer = coordinator.beginOperationPrompt(source: "outer")
        XCTAssertEqual(beganCount, 1)
        let inner = coordinator.beginOperationPrompt(source: "inner")
        XCTAssertEqual(beganCount, 1, "A nested prompt must not fire the began hook.")
        coordinator.endOperationPrompt(inner)
        coordinator.endOperationPrompt(outer)

        _ = coordinator.beginOperationPrompt(source: "next")
        XCTAssertEqual(beganCount, 2, "Each new session fires the began hook once.")
    }

    func test_onOperationPromptsEnded_ignoresPrivacyPrompts() {
        let coordinator = AuthenticationPromptCoordinator()
        nonisolated(unsafe) var firedCount = 0
        coordinator.onOperationPromptsEnded = { firedCount += 1 }

        let privacy = coordinator.beginPrivacyPrompt(source: "privacy")
        coordinator.endPrivacyPrompt(privacy)

        XCTAssertEqual(firedCount, 0, "Privacy prompts never fire the operation hook.")
    }
}
