import SwiftUI

extension View {
    /// The Clipboard Safety Notice — one alert stating the one clipboard
    /// promise (`CypherClipboard`), so no screen can describe a copy of its own
    /// differently. `onDismiss` reports whether the user asked to stop seeing
    /// it.
    func clipboardSafetyNotice(
        isPresented: Binding<Bool>,
        onDismiss: @escaping @MainActor (_ disableFutureNotices: Bool) -> Void
    ) -> some View {
        alert(
            String(localized: "clipboard.notice.title", defaultValue: "Copied to Clipboard"),
            isPresented: isPresented
        ) {
            Button(String(localized: "clipboard.notice.dismiss", defaultValue: "OK")) {
                onDismiss(false)
            }
            Button(String(localized: "clipboard.notice.dontShow", defaultValue: "Don't Show Again")) {
                onDismiss(true)
            }
        } message: {
            Text(
                String(
                    localized: "clipboard.notice.message",
                    defaultValue: "This copy stays on this device and is removed from the clipboard after 5 minutes. It is never sent to your other devices."
                )
            )
        }
    }
}
