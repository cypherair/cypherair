import SwiftUI

/// A pure, opaque cosmetic cover shown whenever the app is not foreground-active
/// (P1 of the auth-lifecycle redesign — TARGET §2.A). It exists only to keep
/// sensitive content out of the app-switcher snapshot and away from
/// shoulder-surfing.
///
/// It has **zero** coupling to authentication: it never schedules a resume, clears
/// content, inspects prompts, or reads a lock interval. It renders solely from the
/// single `isCovered` boolean the app drives off the foreground-active signal. This
/// replaces the cosmetic role of the old `PrivacyScreenModifier` blur + the
/// authentication shield, with none of their lifecycle inference.
///
/// `.ultraThinMaterial` preserves the current privacy-overlay semantics (PRD §4.9:
/// a security overlay, not a Liquid Glass UI element).
private struct CosmeticPrivacyCoverModifier: ViewModifier {
    let isCovered: Bool
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore

    func body(content: Content) -> some View {
        content
            .overlay {
                if isCovered {
                    Rectangle()
                        .fill(.ultraThinMaterial)
                        .ignoresSafeArea()
                        .transition(.opacity)
                        .onAppear {
                            authLifecycleTraceStore?.record(category: .lifecycle, name: "cover.shown")
                        }
                        .onDisappear {
                            authLifecycleTraceStore?.record(category: .lifecycle, name: "cover.hidden")
                        }
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
