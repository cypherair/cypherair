#if os(macOS)
import AppKit

/// Refuses cross-process capture of every window this process puts on screen,
/// so a screen recorder — a conferencing tool, a capture utility, or malware
/// that obtained the Screen Recording grant — cannot read decrypted plaintext,
/// contact identities or armored key material off the display (issue #920).
///
/// The rule is process-wide because almost none of the windows are ours to
/// make: SwiftUI creates the scene window, every window-modal sheet and every
/// alert panel, and AppKit creates the file panels, menus and tooltips. Only
/// the lock shield and its per-sheet covers are built by hand, so a per-site
/// assignment would protect the two least interesting windows and leave the
/// ones carrying plaintext shareable.
///
/// Two limits, both measured for #920. It protects pixels, not metadata: a
/// capturing process still enumerates each window and reads its title, which
/// is why the app's titles stay generic. And its reach is `NSApp.windows`,
/// which excludes the `NSMenuBarReplicantWindow`s AppKit keeps off screen for
/// every app — they hold a copy of the menu bar and never app content.
@MainActor
enum ScreenCaptureExclusion {
    /// Arms the exclusion. Call before the first window is created.
    ///
    /// One sweep, two triggers, because a window is capturable from the moment
    /// the window server has it — which is not the same moment the app next
    /// reaches its run loop:
    ///
    /// - `NSWindowDidUpdate` is posted while a window is being created, before
    ///   it is ordered on screen, so the window is already non-shareable when
    ///   it first appears. That matters most exactly where it is hardest to
    ///   see: a busy main thread lets the window server show and animate a
    ///   window for as long as the app stays blocked. Measured for #920 on a
    ///   launch that opens a sheet — without this trigger the scene window and
    ///   the sheet were readable for ~240ms after appearing.
    /// - A run-loop observer at the lowest order for `beforeWaiting`/`exit`,
    ///   the activity where Core Animation commits the frame that publishes
    ///   new content; observers of one activity run in ascending order, so the
    ///   sweep precedes that commit. It asks no window to announce itself,
    ///   which is what makes it a backstop rather than a duplicate.
    static func install() {
        NotificationCenter.default.addObserver(
            forName: NSWindow.didUpdateNotification,
            object: nil,
            queue: nil
        ) { _ in
            MainActor.assumeIsolated {
                excludeEveryWindow()
            }
        }

        let observer = CFRunLoopObserverCreateWithHandler(
            nil,
            CFRunLoopActivity.beforeWaiting.rawValue | CFRunLoopActivity.exit.rawValue,
            true,
            CFIndex.min
        ) { _, _ in
            MainActor.assumeIsolated {
                excludeEveryWindow()
            }
        }
        CFRunLoopAddObserver(CFRunLoopGetMain(), observer, .commonModes)
    }

    private static func excludeEveryWindow() {
        for window in NSApplication.shared.windows where window.sharingType != .none {
            window.sharingType = .none
        }
    }
}
#endif
