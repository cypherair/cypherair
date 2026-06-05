import Foundation
import XCTest
@testable import CypherAir

private final class MutableDateProvider: @unchecked Sendable {
    var value: Date

    init(_ value: Date) {
        self.value = value
    }

    func now() -> Date {
        value
    }
}

@MainActor
final class PrivacyScreenLifecycleGateTests: XCTestCase {
    private func operationPromptSnapshot(
        generation: UInt64 = 1,
        sessionGeneration: UInt64? = nil,
        depth: Int = 0,
        beganAt: Date? = Date(timeIntervalSinceReferenceDate: 1_000),
        endedAt: Date? = Date(timeIntervalSinceReferenceDate: 1_000)
    ) -> CypherAir.AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot {
        CypherAir.AuthenticationPromptCoordinator.OperationAuthenticationPromptSnapshot(
            generation: generation,
            sessionGeneration: sessionGeneration,
            depth: depth,
            lastBeganAt: beganAt,
            lastEndedAt: endedAt
        )
    }

    func test_privacyScreenLifecycleGate_allowsNormalResignAndActivation() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertEqual(gate.shouldHandleResignActive(isAuthenticating: false), .handle)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_suppressesAuthPromptActivationBeforeAuthCompletes() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertEqual(gate.shouldHandleResignActive(isAuthenticating: true), .suppress)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: true), .suppress)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_suppressesOnlyOneActivationPerAuthPromptCycle() {
        var gate = PrivacyScreenLifecycleGate()

        XCTAssertEqual(gate.shouldHandleResignActive(isAuthenticating: true), .suppress)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_suppressesOneActivationForExternalAuthPromptCycle() {
        let start = Date(timeIntervalSinceReferenceDate: 2_000)
        let clock = MutableDateProvider(start)
        var gate = PrivacyScreenLifecycleGate(now: clock.now)

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    depth: 1,
                    beganAt: start,
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    depth: 0,
                    beganAt: start,
                    endedAt: start
                )
            ),
            .suppress
        )
        clock.value = start.addingTimeInterval(0.2)
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    depth: 0,
                    beganAt: start,
                    endedAt: start
                )
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_observedOperationPromptSettleBlursLateInactiveAndSettlesActivation() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_000)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .blurOnly
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .settleTransientBlur
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_unobservedOperationPromptTailHandlesRealLifecycleWithinSettleWindow() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_500)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_nestedOperationPromptCarriesObservedSessionEligibilityAcrossGeneration() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_750)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let endedPrompt = operationPromptSnapshot(
            generation: 2,
            sessionGeneration: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-0.5),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: endedPrompt
            ),
            .blurOnly
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: endedPrompt
            ),
            .settleTransientBlur
        )
    }

    func test_privacyScreenLifecycleGate_serialOperationPromptSessionDoesNotInheritSettleEligibility() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_850)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let serialEndedPrompt = operationPromptSnapshot(
            generation: 2,
            sessionGeneration: 2,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-0.5),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: serialEndedPrompt
            ),
            .handle
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: serialEndedPrompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_serialOperationPromptSessionClearsOlderArmedSettle() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_875)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let firstEndedPrompt = operationPromptSnapshot(
            generation: 1,
            sessionGeneration: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )
        let serialEndedPrompt = operationPromptSnapshot(
            generation: 2,
            sessionGeneration: 2,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-0.5),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: firstEndedPrompt
            ),
            .blurOnly
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: serialEndedPrompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_activeOnlyNestedOperationPromptDoesNotGrantSettleEligibility() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 3_900)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let endedPrompt = operationPromptSnapshot(
            generation: 2,
            sessionGeneration: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-0.5),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: endedPrompt
            ),
            .handle
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: endedPrompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_expiredOperationPromptGenerationHandlesRealLifecycle() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 4_000)
        // Explicit small settle window to exercise the safety-expiry bound. Production
        // uses a generous default (30 s) so a real ~2.4 s Face ID `.active` never
        // expires — see test_…_lateActiveWithinSettleWindow… for that path.
        var gate = PrivacyScreenLifecycleGate(
            operationPromptSettleWindow: 1.0,
            now: { promptEndedAt.addingTimeInterval(1.1) }
        )
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_activeDuringPromptDoesNotConsumeSuppression() {
        var gate = PrivacyScreenLifecycleGate()
        let prompt = operationPromptSnapshot(depth: 1, endedAt: nil)

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .suppress
        )
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_backgroundClearsPromptSuppression() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertTrue(gate.shouldHandleBackground())
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_backgroundClearsObservedOperationPromptSuppression() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 5_000)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.1) })
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        XCTAssertTrue(gate.shouldHandleBackground(operationPrompt: prompt))

        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .handle
        )
    }

    func test_privacyScreenLifecycleGate_appSessionCompletionSurvivesExpiredOperationPrompt() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 6_000)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(1.1) })
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .blurOnly
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .settleTransientBlur
        )
    }

    func test_privacyScreenLifecycleGate_appSessionCompletionSurvivesUnobservedOperationPromptTail() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 6_500)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.25) })
        let prompt = operationPromptSnapshot(
            generation: 1,
            depth: 0,
            beganAt: promptEndedAt.addingTimeInterval(-1),
            endedAt: promptEndedAt
        )

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .blurOnly
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: prompt
            ),
            .settleTransientBlur
        )
    }

    func test_privacyScreenLifecycleGate_nestedOperationPromptSettlesOnlyAfterDepthReachesZero() {
        let promptEndedAt = Date(timeIntervalSinceReferenceDate: 7_000)
        var gate = PrivacyScreenLifecycleGate(now: { promptEndedAt.addingTimeInterval(0.1) })

        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 1,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleBecomeActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 2,
                    sessionGeneration: 1,
                    depth: 1,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: nil
                )
            ),
            .suppress
        )
        XCTAssertEqual(
            gate.shouldHandleResignActive(
                isAuthenticating: false,
                operationPrompt: operationPromptSnapshot(
                    generation: 2,
                    sessionGeneration: 1,
                    depth: 0,
                    beganAt: promptEndedAt.addingTimeInterval(-1),
                    endedAt: promptEndedAt
                )
            ),
            .blurOnly
        )
    }

    func test_privacyScreenLifecycleGate_authenticationAttemptSuppressesActivationWithoutResignEvent() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
    }

    func test_privacyScreenLifecycleGate_authenticationAttemptSuppressionIsConsumedAfterOneActivation() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }

    func test_privacyScreenLifecycleGate_appSessionCompletionBlursInactiveAndSettlesActive() {
        var gate = PrivacyScreenLifecycleGate()

        gate.armForAuthenticationAttempt()

        XCTAssertEqual(gate.shouldHandleResignActive(isAuthenticating: false), .blurOnly)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .settleTransientBlur)
        XCTAssertEqual(gate.shouldHandleBecomeActive(isAuthenticating: false), .handle)
    }
}
