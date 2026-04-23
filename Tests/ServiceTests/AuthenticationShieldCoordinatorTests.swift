import XCTest
@testable import CypherAir

@MainActor
final class AuthenticationShieldCoordinatorTests: XCTestCase {
    func test_beginAndEndPrivacyPrompt_togglesVisibility() async {
        let coordinator = AuthenticationShieldCoordinator()

        XCTAssertFalse(coordinator.isVisible)

        coordinator.begin(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.privacy],
                isPendingDismissal: false
            )
        )

        coordinator.end(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [],
                isPendingDismissal: true
            )
        )

        await settleShieldDismissal()

        XCTAssertFalse(coordinator.isVisible)
        XCTAssertNil(coordinator.presentationState)
    }

    func test_beginAndEndOperationPrompt_togglesVisibility() async {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .operation,
                activeKinds: [.operation],
                isPendingDismissal: false
            )
        )

        coordinator.end(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .operation,
                activeKinds: [],
                isPendingDismissal: true
            )
        )

        await settleShieldDismissal()

        XCTAssertFalse(coordinator.isVisible)
        XCTAssertNil(coordinator.presentationState)
    }

    func test_nestedMixedPrompts_keepShieldVisibleUntilLastPromptEnds() async {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.begin(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.operation, .privacy],
                isPendingDismissal: false
            )
        )

        coordinator.end(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.privacy],
                isPendingDismissal: false
            )
        )

        coordinator.end(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [],
                isPendingDismissal: true
            )
        )

        await settleShieldDismissal()

        XCTAssertFalse(coordinator.isVisible)
    }

    func test_repeatedSameKindPrompt_doesNotHidePrematurely() async {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.begin(.operation)

        XCTAssertTrue(coordinator.isVisible)

        coordinator.end(.operation)
        XCTAssertTrue(coordinator.isVisible)

        coordinator.end(.operation)
        XCTAssertTrue(coordinator.isVisible)

        await settleShieldDismissal()

        XCTAssertFalse(coordinator.isVisible)
    }

    func test_promptCoordinator_withOperationPrompt_showsShieldBeforeOperationAndSettlesAfterSuccess() async throws {
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
        XCTAssertTrue(shieldCoordinator.isVisible)
        XCTAssertEqual(
            shieldCoordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .operation,
                activeKinds: [],
                isPendingDismissal: true
            )
        )

        await settleShieldDismissal()
        XCTAssertFalse(shieldCoordinator.isVisible)
    }

    func test_promptCoordinator_withOperationPrompt_settlesAfterFailure() async {
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
            XCTAssertTrue(shieldCoordinator.isVisible)
            XCTAssertEqual(
                shieldCoordinator.presentationState,
                AuthenticationShieldPresentationState(
                    primaryKind: .operation,
                    activeKinds: [],
                    isPendingDismissal: true
                )
            )

            await settleShieldDismissal()
            XCTAssertFalse(shieldCoordinator.isVisible)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func test_pendingDismissal_staysVisibleThroughBackgroundUntilActiveSettles() {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.privacy)
        coordinator.end(.privacy)

        coordinator.sceneDidEnterBackground()

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [],
                isPendingDismissal: true
            )
        )

        coordinator.sceneDidBecomeActive()

        XCTAssertFalse(coordinator.isVisible)
    }

    func test_pendingDismissal_isCancelledWhenANewPromptBegins() {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.end(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(coordinator.presentationState?.isPendingDismissal, true)

        coordinator.begin(.privacy)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(
            coordinator.presentationState,
            AuthenticationShieldPresentationState(
                primaryKind: .privacy,
                activeKinds: [.privacy],
                isPendingDismissal: false
            )
        )
    }

    func test_withoutLifecycleBounce_shieldClearsOnNextStableCycle() async {
        let coordinator = AuthenticationShieldCoordinator()

        coordinator.begin(.operation)
        coordinator.end(.operation)

        XCTAssertTrue(coordinator.isVisible)
        XCTAssertEqual(coordinator.presentationState?.isPendingDismissal, true)

        await settleShieldDismissal()

        XCTAssertFalse(coordinator.isVisible)
    }

    private func settleShieldDismissal() async {
        for _ in 0..<5 {
            await Task.yield()
        }
    }
}
