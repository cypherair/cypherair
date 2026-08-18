import SwiftUI
#if os(iOS)
import UIKit
#endif

/// The app's one success confirmation: the button the user just tapped *is* the
/// confirmation. It becomes "Copied" with a checkmark for a moment, then
/// returns to its resting label. Nothing has to be dismissed and nothing
/// interrupts — an alert only ever asks a question or reports a failure, never
/// a success (docs/PRODUCT.md §5).
///
/// The checkmark swaps in with a small symbol transition, and iPhone adds a
/// gentle success haptic. Reduce Motion drops the animation and keeps the
/// haptic: a haptic is not motion.
///
/// Enablement stays with the caller (`.disabled`), which knows why a copy is
/// unavailable; the action reports whether a copy actually happened, so a copy
/// a screen declines to make confirms nothing.
struct CypherCopyButton: View {
    /// How long the confirmation holds before the button returns to rest — long
    /// enough to read, short enough to stay out of the way.
    private static let confirmationDuration = Duration.seconds(2)

    private let title: String
    private let copy: @MainActor () async -> Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var copyCount = 0
    @State private var isConfirming = false

    /// Copies `value` — the plain case, where reaching the clipboard is the
    /// whole operation.
    init(title: String, value: String) {
        self.init(title: title) {
            CypherClipboard.copy(value)
            return true
        }
    }

    /// `copy` performs the copy and reports whether it landed. It may suspend —
    /// the Encrypt and Sign copies wait on a protected setting before writing —
    /// and the confirmation waits with it, so nothing is ever confirmed at tap
    /// time. A refusal, an interception or a superseded copy reports `false`
    /// and confirms nothing.
    init(title: String, copy: @escaping @MainActor () async -> Bool) {
        self.title = title
        self.copy = copy
    }

    var body: some View {
        let haptic = confirmationHaptic

        Button {
            Task {
                guard await copy() else { return }
                copyCount += 1
                withAnimation(CypherMotion.spring(reduceMotion: reduceMotion)) {
                    isConfirming = true
                }
                // The label swap is silent to VoiceOver, which is focused on
                // the button it just activated; the alert this replaced spoke
                // for itself.
                AccessibilityNotification.Announcement(confirmedTitle).post()
            }
        } label: {
            Label {
                Text(isConfirming ? confirmedTitle : title)
            } icon: {
                Image(systemName: isConfirming ? "checkmark" : "doc.on.doc")
                    .contentTransition(.symbolEffect(.replace))
            }
        }
        .task(id: copyCount) {
            guard isConfirming else { return }
            try? await Task.sleep(for: Self.confirmationDuration)
            guard !Task.isCancelled else { return }
            withAnimation(CypherMotion.spring(reduceMotion: reduceMotion)) {
                isConfirming = false
            }
        }
        .sensoryFeedback(trigger: copyCount) { _, _ in haptic }
    }

    private var confirmedTitle: String {
        String(localized: "confirmation.copied", defaultValue: "Copied")
    }

    /// The confirmation haptic is an iPhone detail: nothing else the app runs
    /// on has a Taptic Engine to speak with.
    @MainActor
    private var confirmationHaptic: SensoryFeedback? {
        #if os(iOS)
        UIDevice.current.userInterfaceIdiom == .phone ? .success : nil
        #else
        nil
        #endif
    }
}
