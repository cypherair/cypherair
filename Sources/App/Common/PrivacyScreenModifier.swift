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
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    #if os(macOS)
    /// Suppresses the next didBecomeActive notification after auth completes,
    /// because the Touch ID dialog itself causes a resign/become-active cycle.
    @State private var suppressNextActivation = false
    #endif

    func body(content: Content) -> some View {
        content
            .overlay {
                if appSessionOrchestrator.isPrivacyScreenBlurred {
                    ZStack {
                        Rectangle()
                            .fill(.ultraThinMaterial)
                            .ignoresSafeArea()

                        if appSessionOrchestrator.authFailed && !appSessionOrchestrator.isAuthenticating {
                            Button {
                                performResumeAction(retry: true)
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
            .animation(.easeInOut(duration: 0.15), value: appSessionOrchestrator.isPrivacyScreenBlurred)
            #if canImport(UIKit)
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .background, .inactive:
                    appSessionOrchestrator.handleSceneDidResignActive()
                case .active:
                    performResumeAction()
                @unknown default:
                    break
                }
            }
            #endif
            #if os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                // Skip if auth is in progress — the system Touch ID dialog causes
                // the app to resign active, and we must not re-blur during that.
                guard !appSessionOrchestrator.isAuthenticating && !suppressNextActivation else { return }
                appSessionOrchestrator.handleSceneDidResignActive()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                if suppressNextActivation {
                    suppressNextActivation = false
                    return
                }
                guard !appSessionOrchestrator.isAuthenticating else { return }
                performResumeAction()
            }
            #endif
            .onAppear {
                performInitialAppearanceAction()
            }
    }

    private var biometricIconName: String {
        #if os(macOS)
        "touchid"
        #else
        "faceid"
        #endif
    }

    private func performInitialAppearanceAction() {
        Task {
            let attemptedAuthentication = await appSessionOrchestrator.handleInitialAppearance(
                localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
            )
            #if os(macOS)
            if attemptedAuthentication {
                suppressNextActivation = true
            }
            #endif
        }
    }

    private func performResumeAction(retry: Bool = false) {
        Task {
            let attemptedAuthentication: Bool
            if retry {
                attemptedAuthentication = await appSessionOrchestrator.retryPrivacyUnlock(
                    localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
                )
            } else {
                attemptedAuthentication = await appSessionOrchestrator.handleResume(
                    localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
                )
            }
            #if os(macOS)
            if attemptedAuthentication {
                suppressNextActivation = true
            }
            #endif
        }
    }
}

extension View {
    /// Apply the privacy screen blur overlay when app is backgrounded.
    func privacyScreen() -> some View {
        modifier(PrivacyScreenModifier())
    }
}
