#if os(macOS)
import AppKit
import CoreGraphics
import XCTest
@testable import CypherAir

/// The macOS screen-capture exclusion (#920), guarded because its breakage is
/// silent: `ScreenCaptureExclusion.install()` is three lines in
/// `CypherAirApp.init()`, and deleting them leaves every build, lane and
/// visible behaviour of the app unchanged while plaintext on screen becomes
/// readable by any process holding the Screen Recording grant.
///
/// These run in the unit lane because that lane is local and hosted by the
/// real app in a real GUI session (docs/TESTING.md §2.2 — CI runs no
/// `xcodebuild test`), so `install()` has genuinely run, the scene window
/// genuinely exists, and a process may read its own windows'
/// `kCGWindowSharingState` through `CGWindowListCopyWindowInfo` with no Screen
/// Recording permission of its own.
///
/// What they cannot see: whether macOS still *enforces* the state it records.
/// Both assertions read the window server's bookkeeping, and a future macOS
/// that kept storing `sharingType` while ignoring it would leave them green.
/// That residual is the per-macOS-major manual re-check —
/// `scripts/probe_macos_window_capture.sh`, which attempts a real capture.
@MainActor
final class ScreenCaptureExclusionTests: XCTestCase {
    /// A window this process makes is non-shareable by the time it is on
    /// screen. The precondition is what keeps this able to fail: it pins the
    /// starting state as shareable, so a green result means the exclusion
    /// acted rather than AppKit having defaulted the way we wanted.
    func test_newWindow_isExcludedFromCapture_onceShown() {
        let window = NSWindow(
            contentRect: NSRect(x: -10_000, y: -10_000, width: 1, height: 1),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        defer { window.close() }

        XCTAssertEqual(
            window.sharingType,
            .readOnly,
            "AppKit no longer creates windows shareable — this test can no longer tell the exclusion apart from the default."
        )

        window.orderFrontRegardless()
        RunLoop.current.run(until: Date().addingTimeInterval(0.2))

        XCTAssertEqual(
            window.sharingType,
            .none,
            "A window this process shows was left readable by other processes: ScreenCaptureExclusion.install() is not running."
        )
    }

    /// Every window the *app* has on screen — the SwiftUI scene window and
    /// whatever it is presenting, none of them made by this test — is
    /// non-shareable, as the window server reports it to a separate reader.
    func test_everyOnScreenWindowOfThisProcess_isExcludedFromCapture() {
        let windows = Self.onScreenWindowSharingStates(timeout: 10)

        XCTAssertFalse(
            windows.isEmpty,
            "The host app had no window on screen, so this test proved nothing about the exclusion."
        )
        for (windowNumber, sharingState) in windows {
            XCTAssertEqual(
                sharingState,
                0,
                "Window \(windowNumber) is readable by other processes (kCGWindowSharingState \(sharingState))."
            )
        }
    }

    /// `(windowNumber, kCGWindowSharingState)` for every on-screen window this
    /// process owns, waiting for the host app's window to appear rather than
    /// racing its launch. Off-screen windows are excluded deliberately: AppKit
    /// keeps `NSMenuBarReplicantWindow`s out of `NSApp.windows`, so the
    /// exclusion does not reach them, which the mechanism documents.
    private static func onScreenWindowSharingStates(timeout: TimeInterval) -> [(Int, Int)] {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            let states = currentOnScreenWindowSharingStates()
            if !states.isEmpty || Date() >= deadline {
                return states
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
        }
    }

    private static func currentOnScreenWindowSharingStates() -> [(Int, Int)] {
        let ownPID = Int(ProcessInfo.processInfo.processIdentifier)
        guard let list = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly],
            kCGNullWindowID
        ) as? [[String: Any]] else {
            return []
        }
        return list.compactMap { info in
            guard info[kCGWindowOwnerPID as String] as? Int == ownPID,
                  let windowNumber = info[kCGWindowNumber as String] as? Int,
                  let sharingState = info[kCGWindowSharingState as String] as? Int else {
                return nil
            }
            return (windowNumber, sharingState)
        }
    }
}
#endif
