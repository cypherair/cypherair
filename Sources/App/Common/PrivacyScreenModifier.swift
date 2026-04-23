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
    @Environment(\.authLifecycleTraceStore) private var authLifecycleTraceStore
    @Environment(AppSessionOrchestrator.self) private var appSessionOrchestrator
    @State private var lifecycleGate = PrivacyScreenLifecycleGate()

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
                authLifecycleTraceStore?.record(
                    category: .lifecycle,
                    name: "scenePhase.observed",
                    metadata: ["phase": scenePhaseName(newPhase)]
                )
                switch newPhase {
                case .inactive:
                    guard lifecycleGate.shouldHandleInactive(
                        isAuthenticating: appSessionOrchestrator.isAuthenticating,
                        isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                    ) else {
                        return
                    }
                    appSessionOrchestrator.handleSceneDidResignActive()
                case .background:
                    guard lifecycleGate.shouldHandleBackground() else {
                        return
                    }
                    appSessionOrchestrator.handleSceneDidEnterBackground()
                case .active:
                    guard lifecycleGate.shouldHandleBecomeActive(
                        isAuthenticating: appSessionOrchestrator.isAuthenticating,
                        isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                    ) else {
                        return
                    }
                    performResumeAction()
                @unknown default:
                    break
                }
            }
            #endif
            #if os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                guard lifecycleGate.shouldHandleResignActive(
                    isAuthenticating: appSessionOrchestrator.isAuthenticating,
                    isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                ) else {
                    return
                }
                appSessionOrchestrator.handleSceneDidResignActive()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                guard lifecycleGate.shouldHandleBecomeActive(
                    isAuthenticating: appSessionOrchestrator.isAuthenticating,
                    isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                ) else {
                    return
                }
                performResumeAction()
            }
            #endif
            .onAppear {
                lifecycleGate.attachTraceStore(authLifecycleTraceStore)
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

    private func scenePhaseName(_ phase: ScenePhase) -> String {
        switch phase {
        case .active:
            "active"
        case .inactive:
            "inactive"
        case .background:
            "background"
        @unknown default:
            "unknown"
        }
    }

    private func performInitialAppearanceAction() {
        Task {
            let attemptedAuthentication = await appSessionOrchestrator.handleInitialAppearance(
                localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume")
            )
            if attemptedAuthentication {
                lifecycleGate.armForAuthenticationAttempt()
            }
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
            if attemptedAuthentication {
                lifecycleGate.armForAuthenticationAttempt()
            }
        }
    }
}

extension View {
    /// Apply the privacy screen blur overlay when app is backgrounded.
    func privacyScreen() -> some View {
        modifier(PrivacyScreenModifier())
    }
}
