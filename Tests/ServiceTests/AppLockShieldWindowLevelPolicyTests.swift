#if os(macOS)
import AppKit
import XCTest
@testable import CypherAir

/// The macOS shield's activation-level policy (#697). The regression this
/// guards: while an app-session unlock is in flight, LocalAuthentication's
/// prompt resigns the app, and a shield dropped to `.normal` on that resign
/// falls behind an attached window-modal sheet — exposing covered content for
/// the whole prompt. The shield must stay elevated for auth-driven resigns
/// and drop to `.normal` only on a real app switch (so it never floats above
/// other apps' windows).
@MainActor
final class AppLockShieldWindowLevelPolicyTests: XCTestCase {
    func test_activeApp_isElevated_regardlessOfUnlockState() {
        XCTAssertEqual(
            AppLockShieldWindowCoordinator.shieldLevel(
                appIsActive: true,
                isUnlockAuthenticationInFlight: false
            ),
            AppLockShieldWindowCoordinator.activeShieldLevel
        )
        XCTAssertEqual(
            AppLockShieldWindowCoordinator.shieldLevel(
                appIsActive: true,
                isUnlockAuthenticationInFlight: true
            ),
            AppLockShieldWindowCoordinator.activeShieldLevel
        )
    }

    func test_inactiveDuringUnlockAttempt_staysElevated() {
        // The auth prompt's own resign must not demote the shield below an
        // attached sheet.
        XCTAssertEqual(
            AppLockShieldWindowCoordinator.shieldLevel(
                appIsActive: false,
                isUnlockAuthenticationInFlight: true
            ),
            AppLockShieldWindowCoordinator.activeShieldLevel
        )
    }

    func test_realAppSwitch_dropsToNormal() {
        // Inactive with no unlock in flight is a genuine app switch: the
        // shield must not float above other apps' windows.
        XCTAssertEqual(
            AppLockShieldWindowCoordinator.shieldLevel(
                appIsActive: false,
                isUnlockAuthenticationInFlight: false
            ),
            .normal
        )
    }
}
#endif
