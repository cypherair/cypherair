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
    @State private var appearanceCount = 0

    func body(content: Content) -> some View {
        content
            .overlay {
                if appSessionOrchestrator.isPrivacyScreenBlurred {
                    ZStack {
                        Rectangle()
                            .fill(.ultraThinMaterial)
                            .ignoresSafeArea()

                        authenticationFailureView
                    }
                    .transition(.opacity)
                    .onAppear {
                        authLifecycleTraceStore?.record(
                            category: .lifecycle,
                            name: "privacy.overlay.visible",
                            metadata: [
                                "isAuthenticating": appSessionOrchestrator.isAuthenticating ? "true" : "false",
                                "authFailed": appSessionOrchestrator.authFailed ? "true" : "false"
                            ]
                        )
                    }
                    .onDisappear {
                        authLifecycleTraceStore?.record(
                            category: .lifecycle,
                            name: "privacy.overlay.hidden"
                        )
                    }
                    .transaction { transaction in
                        if appSessionOrchestrator.isPrivacyScreenBlurred {
                            transaction.animation = nil
                        }
                    }
                    .transition(.asymmetric(insertion: .identity, removal: .opacity))
                }
            }
            .animation(
                appSessionOrchestrator.isPrivacyScreenBlurred ? nil : .easeOut(duration: 0.26),
                value: appSessionOrchestrator.isPrivacyScreenBlurred
            )
            #if canImport(UIKit)
            .onChange(of: scenePhase) { _, newPhase in
                authLifecycleTraceStore?.record(
                    category: .lifecycle,
                    name: "scenePhase.observed",
                    metadata: ["phase": scenePhaseName(newPhase)]
                )
                lifecycleGate.syncOperationAuthenticationAttemptGeneration(
                    appSessionOrchestrator.operationAuthenticationAttemptGeneration
                )
                switch newPhase {
                case .inactive:
                    guard lifecycleGate.shouldHandleInactive(
                        isAuthenticating: appSessionOrchestrator.isAuthenticating,
                        isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                    ) == .handle else {
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
                    ) == .handle else {
                        return
                    }
                    performResumeAction(source: "sceneActive")
                @unknown default:
                    break
                }
            }
            #endif
            #if os(macOS)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                lifecycleGate.syncOperationAuthenticationAttemptGeneration(
                    appSessionOrchestrator.operationAuthenticationAttemptGeneration
                )
                switch lifecycleGate.shouldHandleResignActive(
                    isAuthenticating: appSessionOrchestrator.isAuthenticating,
                    isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                ) {
                case .handle:
                    appSessionOrchestrator.handleSceneDidResignActive()
                case .blurOnly:
                    appSessionOrchestrator.handleAuthenticationSettleInactive(source: "sceneInactive")
                case .settleTransientBlur, .suppress:
                    break
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                lifecycleGate.syncOperationAuthenticationAttemptGeneration(
                    appSessionOrchestrator.operationAuthenticationAttemptGeneration
                )
                switch lifecycleGate.shouldHandleBecomeActive(
                    isAuthenticating: appSessionOrchestrator.isAuthenticating,
                    isOperationPromptInProgress: appSessionOrchestrator.isOperationAuthenticationPromptInProgress
                ) {
                case .handle:
                    performResumeAction(source: "sceneActive")
                case .settleTransientBlur:
                    appSessionOrchestrator.handleAuthenticationSettleActive(source: "sceneActive")
                case .blurOnly, .suppress:
                    break
                }
            }
            #endif
            .onAppear {
                appearanceCount += 1
                authLifecycleTraceStore?.record(
                    category: .lifecycle,
                    name: "privacy.onAppear",
                    metadata: ["appearanceCount": String(appearanceCount)]
                )
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

    @ViewBuilder
    private var authenticationFailureView: some View {
        if appSessionOrchestrator.authFailed && !appSessionOrchestrator.isAuthenticating {
            switch appSessionOrchestrator.authenticationFailureReason {
            case .biometricsLockedOut:
                VStack(spacing: 14) {
                    Image(systemName: biometricIconName)
                        .font(.system(size: 32, weight: .semibold))
                        .foregroundStyle(.secondary)

                    VStack(spacing: 8) {
                        Text(biometricsLockedOutTitle)
                            .font(.headline)
                            .multilineTextAlignment(.center)

                        Text(biometricsLockedOutMessage)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)

                        Text(biometricsLockedOutRecoveryMessage)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    retryAuthenticationButton(
                        title: biometricsLockedOutRetryTitle,
                        accessibilityLabel: biometricsLockedOutRetryAccessibilityLabel
                    )
                }
                .padding(22)
                .frame(maxWidth: 440)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            case .authenticationFailed, nil:
                retryAuthenticationButton(
                    title: String(localized: "privacy.tapToAuth", defaultValue: "Tap to Authenticate"),
                    accessibilityLabel: String(localized: "privacy.tapToAuth.a11y", defaultValue: "Authenticate to unlock the app")
                )
            }
        }
    }

    private func retryAuthenticationButton(title: String, accessibilityLabel: String) -> some View {
        Button {
            performResumeAction(retry: true, source: "retryButton")
        } label: {
            Label(title, systemImage: biometricIconName)
                .font(.headline)
        }
        .buttonStyle(.borderedProminent)
        .accessibilityLabel(accessibilityLabel)
    }

    private var biometricsLockedOutTitle: String {
        #if os(macOS)
        String(localized: "privacy.biometricsLockedOut.title.macOS", defaultValue: "Touch ID is locked by macOS")
        #elseif os(visionOS)
        String(localized: "privacy.biometricsLockedOut.title.visionOS", defaultValue: "Optic ID is locked by visionOS")
        #else
        String(localized: "privacy.biometricsLockedOut.title.iOS", defaultValue: "Biometric authentication is locked by iOS")
        #endif
    }

    private var biometricsLockedOutMessage: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.message.macOS",
            defaultValue: "CypherAir is set to Biometrics Only, so it will not use your Mac password as a fallback."
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.message.device",
            defaultValue: "CypherAir is set to Biometrics Only, so it will not use your device passcode as a fallback."
        )
        #endif
    }

    private var biometricsLockedOutRecoveryMessage: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.recovery.macOS",
            defaultValue: "Unlock your Mac with your password to re-enable Touch ID, then retry."
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.recovery.device",
            defaultValue: "Use the system passcode flow to re-enable biometric authentication, then retry."
        )
        #endif
    }

    private var biometricsLockedOutRetryTitle: String {
        #if os(macOS)
        String(localized: "privacy.biometricsLockedOut.retry.touchID", defaultValue: "Retry Touch ID")
        #elseif os(visionOS)
        String(localized: "privacy.biometricsLockedOut.retry.opticID", defaultValue: "Retry Optic ID")
        #else
        String(localized: "privacy.biometricsLockedOut.retry.faceID", defaultValue: "Retry Face ID")
        #endif
    }

    private var biometricsLockedOutRetryAccessibilityLabel: String {
        #if os(macOS)
        String(
            localized: "privacy.biometricsLockedOut.retry.a11y.macOS",
            defaultValue: "Retry Touch ID after re-enabling it with your Mac password"
        )
        #else
        String(
            localized: "privacy.biometricsLockedOut.retry.a11y.device",
            defaultValue: "Retry biometric authentication after re-enabling it with the system passcode"
        )
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
        authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "privacy.resumeTask.schedule",
            metadata: ["source": "initialAppearance"]
        )
        Task {
            authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: "privacy.resumeTask.start",
                metadata: ["source": "initialAppearance"]
            )
            let attemptedAuthentication = await appSessionOrchestrator.handleInitialAppearance(
                localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume"),
                source: "initialAppearance"
            )
            if attemptedAuthentication {
                lifecycleGate.armForAuthenticationAttempt()
            }
            authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: "privacy.resumeTask.finish",
                metadata: [
                    "source": "initialAppearance",
                    "attemptedAuthentication": attemptedAuthentication ? "true" : "false"
                ]
            )
        }
    }

    private func performResumeAction(retry: Bool = false, source: String) {
        authLifecycleTraceStore?.record(
            category: .lifecycle,
            name: "privacy.resumeTask.schedule",
            metadata: ["source": source, "retry": retry ? "true" : "false"]
        )
        Task {
            authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: "privacy.resumeTask.start",
                metadata: ["source": source, "retry": retry ? "true" : "false"]
            )
            let attemptedAuthentication: Bool
            if retry {
                attemptedAuthentication = await appSessionOrchestrator.retryPrivacyUnlock(
                    localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume"),
                    source: source
                )
            } else {
                attemptedAuthentication = await appSessionOrchestrator.handleResume(
                    localizedReason: String(localized: "privacy.reauth.reason", defaultValue: "Authenticate to resume"),
                    source: source
                )
            }
            if attemptedAuthentication {
                lifecycleGate.armForAuthenticationAttempt()
            }
            authLifecycleTraceStore?.record(
                category: .lifecycle,
                name: "privacy.resumeTask.finish",
                metadata: [
                    "source": source,
                    "retry": retry ? "true" : "false",
                    "attemptedAuthentication": attemptedAuthentication ? "true" : "false"
                ]
            )
        }
    }
}

extension View {
    /// Apply the privacy screen blur overlay when app is backgrounded.
    func privacyScreen() -> some View {
        modifier(PrivacyScreenModifier())
    }
}
