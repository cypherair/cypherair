import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

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
    @State private var authFailed = false
    @State private var hasAppearedOnce = false
    #if os(macOS)
    /// Suppresses the next didBecomeActive notification after auth completes,
    /// because the Touch ID dialog itself causes a resign/become-active cycle.
    @State private var suppressNextActivation = false
    #endif

    func body(content: Content) -> some View {
        content
            .overlay {
                if isBlurred {
                    ZStack {
                        Rectangle()
                            .fill(.ultraThinMaterial)
                            .ignoresSafeArea()

                        if authFailed && !isAuthenticating {
                            Button {
                                handleResume()
                            } label: {
                                Label(
                                    String(localized: "privacy.tapToAuth", defaultValue: "Tap to Authenticate"),
                                    systemImage: biometricIconName
                                )
                                .font(.headline)
                            }
                            .buttonStyle(.borderedProminent)
                            .accessibilityLabel(String(localized: "privacy.tapToAuth.a11y", defaultValue: "Authenticate to unlock the app"))
                        }
                    }
                    .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.15), value: isBlurred)
            #if canImport(UIKit)
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .background, .inactive:
                    isBlurred = true
                    authFailed = false
                case .active:
                    handleResume()
                @unknown default:
                    break
                }
            }
            #endif
            #if os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                // Skip if auth is in progress — the system Touch ID dialog causes
                // the app to resign active, and we must not re-blur during that.
                guard !isAuthenticating && !suppressNextActivation else { return }
                isBlurred = true
                authFailed = false
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                if suppressNextActivation {
                    suppressNextActivation = false
                    return
                }
                guard !isAuthenticating else { return }
                handleResume()
            }
            #endif
            .onAppear {
                guard !hasAppearedOnce else { return }
                hasAppearedOnce = true
                if config.requireAuthOnLaunch {
                    isBlurred = true
                    handleResume()
                }
            }
    }

    private var biometricIconName: String {
        #if os(macOS)
        "touchid"
        #else
        "faceid"
        #endif
    }

    private func handleResume() {
        if config.gracePeriod == 0 || config.isGracePeriodExpired {
            // Grace period expired or set to "Immediately" — require re-authentication
            // Clear any decrypted content before re-auth.
            config.requestContentClear()
            guard !isAuthenticating else { return }
            isAuthenticating = true
            authFailed = false
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
                        authFailed = false
                        isBlurred = false
                    } else {
                        authFailed = true
                    }
                } catch {
                    // Auth failed or cancelled — show retry button
                    authFailed = true
                }
                #if os(macOS)
                // The Touch ID dialog dismissal will trigger didBecomeActive;
                // suppress it to prevent re-triggering authentication.
                suppressNextActivation = true
                #endif
                isAuthenticating = false
            }
        } else {
            // Within grace period — resume normally
            authFailed = false
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
