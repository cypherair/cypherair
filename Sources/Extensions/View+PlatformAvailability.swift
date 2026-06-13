import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

/// Defensive shield for Apple framework bug **FB23066215** (tracked in issue #499).
///
/// On macOS 27 (arm64e, MIE v2 / Hardware Memory Tagging), a SwiftUI
/// `TextField`/`SecureField`/`TextEditor` that has been *focused* and is then torn
/// down during a navigation pop hits a use-after-free in SwiftUI↔AppKit focus
/// weak-bookkeeping: the backing `NSTextField` deallocates inside a deferred
/// `NSDisplayCycleFlush` autorelease drain and `weak_clear_no_lock` faults
/// (`EXC_ARM_MTE_TAGCHECK_FAIL`). Focus is the necessary condition; the same code is
/// crash-free on macOS 26.x / MIE v1. We cannot patch the framework and MIE is a hard
/// product constraint, so we nudge teardown timing: resign the window's field editor so
/// the focused control deallocates *synchronously, before* the faulting flush.
///
/// Strictly gated to macOS 27+; a no-op everywhere else. Remove this whole type and its
/// call sites once Apple ships a fix (see issue #499 / FB23066215).
enum MIEWeakTeardownMitigation {
    /// Runtime gate — NOT `#available`. CI builds against the 26.5 SDK, which has no
    /// macOS-27 availability symbol, so the version check must be runtime-only.
    static let isActive: Bool = {
        #if os(macOS)
        return ProcessInfo.processInfo.isOperatingSystemAtLeast(
            .init(majorVersion: 27, minorVersion: 0, patchVersion: 0)
        )
        #else
        return false
        #endif
    }()

    /// Detach the key window's field editor so any focused `NSText*` resigns and
    /// deallocates synchronously, before the deferred `NSDisplayCycleFlush` pool drain.
    ///
    /// Touches nothing in MIE, the entitlements, or the heap. `endEditing(for:)` commits
    /// pending edits to the bound `String` and unbinds the field editor exactly as a
    /// normal focus loss does; `makeFirstResponder(nil)` is a belt-and-suspenders detach.
    /// No key material, passphrase, or plaintext is read, copied, logged, or retained.
    /// Idempotent — safe to call from multiple teardown hooks.
    @MainActor
    static func resignActiveTextEditing() {
        #if os(macOS)
        guard isActive else { return }
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            window.endEditing(for: nil)
            window.makeFirstResponder(nil)
        }
        #endif
    }
}

extension View {
    @ViewBuilder
    func scrollDismissesKeyboardInteractivelyIfAvailable() -> some View {
        #if os(iOS)
        self.scrollDismissesKeyboard(.interactively)
        #else
        self
        #endif
    }
}
