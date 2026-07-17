import XCTest
@testable import CypherAir

/// The load-warning gate must never surface a warning while the app is locked,
/// authenticating, or showing its lock cover — otherwise warning content could
/// appear over the lock surface ahead of authentication. This guards that
/// suppression (each blocking condition wins over the permissive flags) with a
/// positive anchor proving the gate is not blanket-suppressed once unblocked.
final class LoadWarningPresentationGateTests: XCTestCase {
    private func state(
        isAppLocked: Bool = false,
        isAuthenticating: Bool = false,
        isLockCoverVisible: Bool = false,
        hasAuthenticatedSession: Bool = false,
        allowsPreAuthenticationPresentation: Bool = false
    ) -> LoadWarningPresentationState {
        LoadWarningPresentationState(
            isAppLocked: isAppLocked,
            isAuthenticating: isAuthenticating,
            isLockCoverVisible: isLockCoverVisible,
            hasAuthenticatedSession: hasAuthenticatedSession,
            allowsPreAuthenticationPresentation: allowsPreAuthenticationPresentation
        )
    }

    func test_suppressesPresentationWhileLockedAuthenticatingOrCovered() {
        // Each blocking condition must suppress presentation even when both
        // permissive flags are set.
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(state(
            isAppLocked: true,
            hasAuthenticatedSession: true,
            allowsPreAuthenticationPresentation: true
        )))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(state(
            isAuthenticating: true,
            hasAuthenticatedSession: true,
            allowsPreAuthenticationPresentation: true
        )))
        XCTAssertFalse(LoadWarningPresentationGate.canPresent(state(
            isLockCoverVisible: true,
            hasAuthenticatedSession: true,
            allowsPreAuthenticationPresentation: true
        )))

        // Positive anchor: unblocked with an authenticated session, presentation
        // is permitted — the suppression above is conditional, not blanket.
        XCTAssertTrue(LoadWarningPresentationGate.canPresent(state(hasAuthenticatedSession: true)))
    }
}
