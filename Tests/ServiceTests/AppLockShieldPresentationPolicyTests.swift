import XCTest
@testable import CypherAir

/// The unified shield's pure decision rules (issue #723). What these guard:
///
/// - The presentation condition must include the dumb synchronous cover
///   trigger — only `isCosmeticallyCovered` is guaranteed true before the
///   system snapshots a backgrounding scene (the lock lands on an async
///   `Task`), so presentation must never collapse to lock-machine state
///   alone.
/// - The rendering mode follows `isLocked` exclusively, which is already true
///   for `.authenticating`/`.authenticationFailed` — the lock face winning
///   during auth prompts needs no extra precedence state.
/// - Privacy mode is purely visual: it must never take key status or end the
///   text-editing session it covers (a within-grace return resumes focus and
///   keyboard untouched); lock mode must do both.
/// - The lock-mode input side effects apply exactly on entering lock mode —
///   including the async lock landing while the window is already visible in
///   privacy mode — and never on staying in or leaving it.
final class AppLockShieldPresentationPolicyTests: XCTestCase {
    func test_presentation_coveredOrLocked() {
        XCTAssertFalse(AppLockShieldPolicy.isPresented(isCosmeticallyCovered: false, isLocked: false))
        // The cover trigger presents on its own — never lock state alone.
        XCTAssertTrue(AppLockShieldPolicy.isPresented(isCosmeticallyCovered: true, isLocked: false))
        XCTAssertTrue(AppLockShieldPolicy.isPresented(isCosmeticallyCovered: false, isLocked: true))
        XCTAssertTrue(AppLockShieldPolicy.isPresented(isCosmeticallyCovered: true, isLocked: true))
    }

    func test_mode_followsLockStateAlone() {
        XCTAssertEqual(AppLockShieldPolicy.mode(isLocked: true), .lock)
        XCTAssertEqual(AppLockShieldPolicy.mode(isLocked: false), .privacy)
    }

    func test_lockMode_takesKeyAndEndsTextEditing() {
        XCTAssertTrue(AppLockShieldPolicy.Mode.lock.takesKeyStatus)
        XCTAssertTrue(AppLockShieldPolicy.Mode.lock.endsActiveTextEditingSession)
    }

    func test_privacyMode_isPurelyVisual() {
        XCTAssertFalse(AppLockShieldPolicy.Mode.privacy.takesKeyStatus)
        XCTAssertFalse(AppLockShieldPolicy.Mode.privacy.endsActiveTextEditingSession)
    }

    func test_lockModeInputDiscipline_appliesExactlyOnEnteringLock() {
        // Presenting directly into lock mode.
        XCTAssertTrue(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: nil, to: .lock)
        )
        // The async lock landing while the window is already visible.
        XCTAssertTrue(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: .privacy, to: .lock)
        )
        // Presenting into privacy, staying put, or leaving lock applies nothing
        // (key restoration happens when the shield hides, not on the flip).
        XCTAssertFalse(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: nil, to: .privacy)
        )
        XCTAssertFalse(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: .lock, to: .privacy)
        )
        XCTAssertFalse(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: .lock, to: .lock)
        )
        XCTAssertFalse(
            AppLockShieldPolicy.appliesLockModeInputDiscipline(transitioningFrom: .privacy, to: .privacy)
        )
    }
}
