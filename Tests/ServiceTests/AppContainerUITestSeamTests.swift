import XCTest
@testable import CypherAir

/// Composition guard for the pre-authenticated manual-auth seam
/// (`UITEST_MANUAL_AUTH_STARTS_UNLOCKED`). The seam's contract is that its
/// boot state is, for UI purposes, indistinguishable from a genuinely
/// authenticated session — ordinary settings LOADED, so settings-gated
/// controls (the Guided Tutorial entry requires
/// `isProtectedOrdinarySettingsEditable`) are enabled. The plain manual-auth
/// container must keep them LOCKED until a real unlock's post-auth fan-out,
/// exactly like production.
@MainActor
final class AppContainerUITestSeamTests: XCTestCase {
    func test_manualAuthStartsUnlocked_bootsOrdinarySettingsLoaded() {
        let container = AppContainer.makeUITest(
            requiresManualAuthentication: true,
            manualAuthStartsUnlocked: true
        )

        XCTAssertTrue(
            container.protectedOrdinarySettingsCoordinator.isLoaded,
            "The pre-authenticated seam must boot with ordinary settings loaded, or settings-gated UI boots disabled."
        )
    }

    func test_plainManualAuth_bootsOrdinarySettingsLocked() {
        let container = AppContainer.makeUITest(requiresManualAuthentication: true)

        XCTAssertFalse(
            container.protectedOrdinarySettingsCoordinator.isLoaded,
            "The plain manual-auth container must keep ordinary settings behind the real post-unlock gate."
        )
    }
}
