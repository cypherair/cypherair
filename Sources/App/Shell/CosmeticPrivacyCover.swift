import SwiftUI

/// A pure, opaque cosmetic cover shown whenever the app is not foreground-active.
/// It exists only to keep sensitive content out of the app-switcher snapshot and
/// away from shoulder-surfing.
///
/// It has **zero** coupling to authentication: it never schedules a resume, clears
/// content, inspects prompts, or reads a lock interval. It renders solely from the
/// single `isCovered` boolean the app drives off the foreground-active signal.
///
/// `.ultraThinMaterial` preserves the current privacy-overlay semantics (PRD §4.9:
/// a security overlay, not a Liquid Glass UI element).
private struct CosmeticPrivacyCoverModifier: ViewModifier {
    let isCovered: Bool

    func body(content: Content) -> some View {
        content
            .overlay {
                if isCovered {
                    Rectangle()
                        .fill(.ultraThinMaterial)
                        .ignoresSafeArea()
                        // Asymmetric by design (PRD §4.9): the cover must be
                        // inserted INSTANTLY on backgrounding so it is already
                        // present in the app-switcher snapshot — a fade-in would
                        // let the snapshot capture the in-flight, partly-clear
                        // frame. Removal may fade for a smooth reveal on return.
                        .transition(.asymmetric(insertion: .identity, removal: .opacity))
                }
            }
            .animation(.easeOut(duration: 0.2), value: isCovered)
    }
}

extension View {
    /// Apply the cosmetic privacy cover when the app is not foreground-active.
    func cosmeticPrivacyCover(isCovered: Bool) -> some View {
        modifier(CosmeticPrivacyCoverModifier(isCovered: isCovered))
    }
}
