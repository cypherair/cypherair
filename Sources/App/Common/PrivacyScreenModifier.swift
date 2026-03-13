import SwiftUI

/// Applies a blur overlay when the app enters the background.
/// Prevents multitasking switcher from showing sensitive content.
///
/// Per PRD Section 4.9:
/// - Blur overlay when app enters background.
/// - On resume: check grace period → if expired, require re-authentication.
/// - Uses `.ultraThinMaterial` (NOT Liquid Glass — privacy screen is a security overlay, not a UI element).
struct PrivacyScreenModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(AppConfiguration.self) private var config
    @Environment(AuthenticationManager.self) private var authManager

    @State private var isBlurred = false
    @State private var isAuthenticating = false

    func body(content: Content) -> some View {
        content
            .overlay {
                if isBlurred {
                    Rectangle()
                        .fill(.ultraThinMaterial)
                        .ignoresSafeArea()
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.15), value: isBlurred)
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .background, .inactive:
                    isBlurred = true
                case .active:
                    handleResume()
                @unknown default:
                    break
                }
            }
    }

    private func handleResume() {
        if config.gracePeriod == 0 || config.isGracePeriodExpired {
            // Grace period expired or set to "Immediately" — require re-authentication
            guard !isAuthenticating else { return }
            isAuthenticating = true
            let auth = authManager
            let mode = config.authMode
            Task {
                do {
                    let success = try await auth.evaluate(
                        mode: mode,
                        reason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
                    )
                    if success {
                        config.recordAuthentication()
                        isBlurred = false
                    }
                    // If not successful, keep blur
                } catch {
                    // Auth failed or cancelled — keep blur
                }
                isAuthenticating = false
            }
        } else {
            // Within grace period — resume normally
            isBlurred = false
        }
    }
}

extension View {
    /// Apply the privacy screen blur overlay when app is backgrounded.
    func privacyScreen() -> some View {
        modifier(PrivacyScreenModifier())
    }
}
