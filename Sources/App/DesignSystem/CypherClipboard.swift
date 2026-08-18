import Foundation
#if canImport(UIKit)
import UIKit
import UniformTypeIdentifiers
#elseif canImport(AppKit)
import AppKit
#endif

/// The app's only clipboard write, and the one policy that comes with it: every
/// copy the app makes — ciphertext, signed text, public keys, fingerprints,
/// URLs — stays on the device that made it and is gone five minutes later.
///
/// iPhone, iPad and Vision Pro hand both halves to the system: `localOnly`
/// keeps the write away from Handoff and Universal Clipboard, and the system
/// itself removes the item at its expiration date. macOS offers the first half
/// (`currentHostOnly`) and no expiry at all, so `ExpiringPasteboard` runs that
/// clock in-process.
@MainActor
enum CypherClipboard {
    /// How long a copy stays on the clipboard. One number for every platform
    /// and every copy — the Clipboard Safety Notice promises it in words.
    private static let lifetime: TimeInterval = 5 * 60

    static func copy(_ string: String) {
        #if canImport(UIKit)
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: string]],
            options: [
                .localOnly: true,
                .expirationDate: Date(timeIntervalSinceNow: lifetime)
            ]
        )
        #elseif canImport(AppKit)
        pasteboard.write(string)
        #endif
    }

    #if canImport(AppKit)
    private static let pasteboard = ExpiringPasteboard(pasteboard: .general, lifetime: lifetime)
    #endif
}

#if canImport(AppKit)
/// The macOS half of the clipboard policy: the app takes its own copy back.
///
/// One pending clear at a time, superseded by the next copy, so the newest copy
/// always gets a full lifetime rather than the remainder of an older one. The
/// clear fires only while the pasteboard still holds the write it was scheduled
/// for: anything the user copied elsewhere in the meantime has moved the change
/// count on and is left alone. That check reads the change count and never the
/// contents, so it asks for no pasteboard access of its own.
///
/// The clock runs in-process — quitting the app before a copy expires leaves it
/// on the pasteboard (docs/SECURITY.md §9).
@MainActor
final class ExpiringPasteboard {
    private let pasteboard: NSPasteboard
    private let lifetime: TimeInterval
    private var pendingClear: Task<Void, Never>?

    init(pasteboard: NSPasteboard, lifetime: TimeInterval) {
        self.pasteboard = pasteboard
        self.lifetime = lifetime
    }

    func write(_ string: String) {
        pasteboard.prepareForNewContents(with: .currentHostOnly)
        pasteboard.setString(string, forType: .string)
        let written = pasteboard.changeCount

        pendingClear?.cancel()
        pendingClear = Task { [lifetime] in
            try? await Task.sleep(for: .seconds(lifetime))
            guard !Task.isCancelled else { return }
            self.clear(ifStillHolding: written)
        }
    }

    private func clear(ifStillHolding changeCount: Int) {
        pendingClear = nil
        guard pasteboard.changeCount == changeCount else { return }
        pasteboard.clearContents()
    }
}
#endif
