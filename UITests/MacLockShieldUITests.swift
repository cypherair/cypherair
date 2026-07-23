import AppKit
import XCTest

/// Behavioral guard for issue #697: while the app is locked, the lock shield
/// window covers ALL app content — including window-modal sheets, which render
/// above any in-scene overlay — and locking dismisses no presentation.
///
/// Mechanics: the app launches the manual-auth UI-test container
/// pre-authenticated (`UITEST_MANUAL_AUTH_STARTS_UNLOCKED`), so it boots
/// unlocked with the lock genuinely armed (auth bypass OFF — a bypass
/// container can never hold a locked state, because the lock surface's
/// auto-auth immediately unlocks it). Each test then confirms the app is
/// genuinely ACTIVE (frontmost) before opening its presentation and locking —
/// active-app-then-lock is the canonical #697 reproduction, and only an
/// active app elevates the shield above sheet level, which is what makes the
/// input-block and geometry asserts meaningful. If the app does not become
/// active within the timeout, those asserts are not evaluable in that run,
/// so the test skips explicitly rather than failing — precedent: the
/// biometric-gated skips of docs/TESTING.md §1; re-running is the normal
/// path. The lock is driven by posting the same
/// `com.apple.screenIsLocked` distributed notification the app's lifecycle
/// observer subscribes to for real macOS screen locks. The observer clears
/// foreground-active before locking, so the locked state is stable: the
/// surface's auto-auth no-ops until a genuine foreground return, and no
/// biometric prompt appears during the test.
///
/// Note: the posted distributed notification is system-wide; other listeners
/// on this machine observe a spurious screen-lock event for the duration of a
/// test run. That mirrors what a real screen lock broadcasts.
@MainActor
final class MacLockShieldUITests: XCTestCase {
    /// The app under test's fixed bundle identifier, used for the
    /// frontmost-application activation check.
    private static let appBundleIdentifier = "com.chentianren.cypherair"

    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = MainActor.assumeIsolated {
            XCUIApplication()
        }
    }

    func test_lockWhileSheetOpen_shieldCoversSheet_withoutDismissingIt() throws {
        launchMainPreAuthenticatedWithLockArmed(
            extraEnvironment: ["UITEST_OPEN_AUTHMODE_CONFIRMATION": "1"]
        )
        try confirmAppActiveOrSkip()

        // Open a real window-modal sheet (the auth-mode confirmation modal
        // auto-opens on the Settings tab under UITEST_OPEN_AUTHMODE_CONFIRMATION).
        element("sidebar.settings").tap()
        XCTAssertTrue(element("settings.authmode.ready").waitForExistence(timeout: 10))
        let sheetAction = element("settings.mode.confirm")
        XCTAssertTrue(sheetAction.waitForExistence(timeout: 10))
        XCTAssertTrue(
            sheetAction.isHittable,
            "Precondition: the sheet's action must be hittable before locking."
        )

        postScreenIsLockedNotification()

        let shield = element("appLock.surface")
        XCTAssertTrue(
            shield.waitForExistence(timeout: 10),
            "Expected the lock shield to appear after the screen-lock event."
        )

        // Invariant: locking dismisses no presentation.
        XCTAssertTrue(
            sheetAction.exists,
            "The window-modal sheet must survive the lock (dismiss-on-lock is rejected by design)."
        )

        // Invariant: input to the covered sheet is blocked.
        XCTAssertFalse(
            sheetAction.isHittable,
            "The covered sheet's action must not be hittable while locked."
        )

        // Invariant: the shield WINDOW geometrically covers the sheet. The
        // surface element's own accessibility frame is its content cluster,
        // so measure the window that hosts it — resolved directly by the
        // window's own identifier (a `.containing(...)` subquery failed to
        // resolve against a never-activated app's AX snapshot even while the
        // window was present in the dump).
        let shieldWindow = app.windows["appLock.shieldWindow"]
        XCTAssertTrue(shieldWindow.waitForExistence(timeout: 5))
        XCTAssertTrue(
            shieldWindow.frame.contains(sheetAction.frame),
            "The shield window frame \(shieldWindow.frame) must cover the sheet action frame \(sheetAction.frame)."
        )

        // Optional human-driven tail for the manual verification lane: unlock
        // with a real biometric and confirm the sheet is exactly where it was.
        if ProcessInfo.processInfo.environment["UITEST_LOCK_SHIELD_HUMAN_UNLOCK"] == "1" {
            app.activate()
            let retryButton = app.buttons["Tap to Authenticate"].firstMatch
            XCTAssertTrue(retryButton.waitForExistence(timeout: 10))
            retryButton.tap()
            XCTAssertTrue(
                sheetAction.waitForExistence(timeout: 45),
                "Expected the sheet to still exist after a human-driven unlock."
            )
            let unlockedAndRestored = NSPredicate(format: "isHittable == true")
            let restored = XCTNSPredicateExpectation(predicate: unlockedAndRestored, object: sheetAction)
            XCTAssertEqual(
                XCTWaiter.wait(for: [restored], timeout: 45),
                .completed,
                "Expected the sheet action to become hittable again after unlock (presentation preserved)."
            )
        }
    }

    /// The originally-reported #697 scenario: locking while the Guided
    /// Tutorial is open must leave the tutorial covered by the shield — and
    /// still present afterwards (the in-memory tutorial session is not
    /// dismissed by locking).
    func test_lockWhileTutorialOpen_shieldCoversTutorial_withoutDismissingIt() throws {
        launchMainPreAuthenticatedWithLockArmed()
        try confirmAppActiveOrSkip()

        element("sidebar.settings").tap()
        XCTAssertTrue(element("settings.ready").waitForExistence(timeout: 10))
        element("settings.tutorial").tap()
        let tutorialHub = element("tutorial.hub.ready")
        XCTAssertTrue(tutorialHub.waitForExistence(timeout: 10))

        postScreenIsLockedNotification()

        let shield = element("appLock.surface")
        XCTAssertTrue(
            shield.waitForExistence(timeout: 10),
            "Expected the lock shield to appear after the screen-lock event."
        )
        XCTAssertTrue(
            tutorialHub.exists,
            "The tutorial must survive the lock (no presentation is dismissed)."
        )
        let shieldWindow = app.windows["appLock.shieldWindow"]
        XCTAssertTrue(shieldWindow.waitForExistence(timeout: 5))
        XCTAssertTrue(
            shieldWindow.frame.contains(tutorialHub.frame),
            "The shield window frame \(shieldWindow.frame) must cover the tutorial hub frame \(tutorialHub.frame)."
        )
    }

    // MARK: - Helpers

    /// Bring the app to the front and wait until macOS reports it as the
    /// frontmost application. Only an ACTIVE app elevates the shield above
    /// sheet level, so the input-block and geometry asserts are meaningful
    /// only past this gate; asserting them against an app that is not active
    /// would fail on the deliberate `.normal`-level inactive posture, not on
    /// a regression. When activation is not achieved, the condition becomes
    /// an explicit skip (precedent: the biometric-gated skips of
    /// docs/TESTING.md §1), never a weakened assert: every assert after this
    /// gate runs unconditionally, and re-running is the normal path.
    private func confirmAppActiveOrSkip() throws {
        app.activate()
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if NSWorkspace.shared.frontmostApplication?.bundleIdentifier == Self.appBundleIdentifier {
                return
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }
        throw XCTSkip(
            "The app did not become active in this run; elevated-shield asserts are not evaluable — re-run to evaluate."
        )
    }

    private func launchMainPreAuthenticatedWithLockArmed(
        extraEnvironment: [String: String] = [:]
    ) {
        app.launchEnvironment["UITEST_ROOT"] = "main"
        app.launchEnvironment["UITEST_SKIP_ONBOARDING"] = "1"
        app.launchEnvironment["UITEST_REQUIRE_MANUAL_AUTH"] = "1"
        app.launchEnvironment["UITEST_MANUAL_AUTH_STARTS_UNLOCKED"] = "1"
        for (key, value) in extraEnvironment {
            app.launchEnvironment[key] = value
        }
        app.launchArguments = ["-ApplePersistenceIgnoreState", "YES"]
        app.launch()

        XCTAssertTrue(
            element("main.ready").waitForExistence(timeout: 15),
            "Expected the pre-authenticated manual-auth launch to reach the main shell without a biometric prompt."
        )
    }

    private func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
    }

    /// Post the same distributed notification `AppLifecycleObserverModifier`
    /// subscribes to for macOS screen locks. The app responds by clearing
    /// foreground-active and locking immediately (`lockNow`), exactly as it
    /// does for a real screen lock.
    private func postScreenIsLockedNotification() {
        DistributedNotificationCenter.default().postNotificationName(
            Notification.Name("com.apple.screenIsLocked"),
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
    }
}
