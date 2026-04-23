import XCTest
@testable import CypherAir

@MainActor
final class AuthenticationShieldCoordinatorTests: XCTestCase {
    func test_beginAndEndPrivacyPrompt_togglesVisibility() {
        let coordinator = AuthenticationShieldCoordinator()

        XCTAssertFalse(coordinator.isVisible)

        coordinator.begin(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.privacy]
            )
        )

        coordinator.end(.privacy)

        XCTAssertFalse(coordinator.isVisible)
        XCTAssertNil(coordinator.presentationState)
    }

    func test_beginAndEndOperationPrompt_togglesVisibility() {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .operation,
                activeKinds: [.operation]
            )
        )

        coordinator.end(.operation)

        XCTAssertFalse(coordinator.isVisible)
        XCTAssertNil(coordinator.presentationState)
    }

    func test_nestedMixedPrompts_keepShieldVisibleUntilLastPromptEnds() {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.begin(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.operation, .privacy]
            )
        )

        coordinator.end(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.privacy]
            )
        )

        coordinator.end(.privacy)

        XCTAssertFalse(coordinator.isVisible)
    }

    func test_repeatedSameKindPrompt_doesNotHidePrematurely() {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.begin(.operation)

        XCTAssertTrue(coordinator.isVisible)

        coordinator.end(.operation)
        XCTAssertTrue(coordinator.isVisible)

        coordinator.end(.operation)
        XCTAssertFalse(coordinator.isVisible)
    }

    func test_promptCoordinator_withOperationPrompt_showsShieldBeforeOperationAndClearsAfterSuccess() async throws {
        let shieldCoordinator = AuthenticationShieldCoordinator()
        let promptCoordinator = AuthenticationPromptCoordinator(
            shieldEventHandler: { kind, delta in
                await MainActor.run {
                    if delta > 0 {
                        shieldCoordinator.begin(kind)
                    } else {
                        shieldCoordinator.end(kind)
                    }
                }
            }
        )

        let result = try await promptCoordinator.withOperationPrompt {
            XCTAssertTrue(shieldCoordinator.isVisible)
            XCTAssertEqual(shieldCoordinator.presentationState?.primaryKind, .operation)
            return 42
        }

        XCTAssertEqual(result, 42)
        XCTAssertFalse(promptCoordinator.isOperationPromptInProgress)
        XCTAssertFalse(shieldCoordinator.isVisible)
    }

    func test_promptCoordinator_withOperationPrompt_clearsShieldAfterFailure() async {
        enum ExpectedError: Error {
            case failed
        }

        let shieldCoordinator = AuthenticationShieldCoordinator()
        let promptCoordinator = AuthenticationPromptCoordinator(
            shieldEventHandler: { kind, delta in
                await MainActor.run {
                    if delta > 0 {
                        shieldCoordinator.begin(kind)
                    } else {
                        shieldCoordinator.end(kind)
                    }
                }
            }
        )

        do {
            _ = try await promptCoordinator.withOperationPrompt {
                XCTAssertTrue(shieldCoordinator.isVisible)
                throw ExpectedError.failed
            }
            XCTFail("Expected withOperationPrompt to throw")
        } catch ExpectedError.failed {
            XCTAssertFalse(promptCoordinator.isOperationPromptInProgress)
            XCTAssertFalse(shieldCoordinator.isVisible)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
