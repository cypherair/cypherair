import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

enum AuthenticationShieldKind: String, Equatable, Hashable {
    case privacy
    case operation
}

struct AuthenticationShieldPresentationState: Equatable {
    let primaryKind: AuthenticationShieldKind
    let activeKinds: Set<AuthenticationShieldKind>
    let isPendingDismissal: Bool
}

private enum AuthenticationShieldLifecyclePhase: Equatable {
    case active
    case inactive
    case background
}

@Observable
final class AuthenticationShieldCoordinator: @unchecked Sendable {
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0
    private var isPendingDismissal = false
    private var promptCycleID: UInt64 = 0
    private var lastVisiblePrimaryKind: AuthenticationShieldKind?
    private var lastLifecyclePhase: AuthenticationShieldLifecyclePhase = .active
    private var observedNonActiveLifecycleInCurrentCycle = false
    private var dismissalFallbackTask: Task<Void, Never>?

    var isVisible: Bool {
        totalPromptDepth > 0 || isPendingDismissal
    }

    var presentationState: AuthenticationShieldPresentationState? {
        let activeKinds = activeKinds
        let primaryKind: AuthenticationShieldKind
        if let activePrimaryKind = activePrimaryKind(for: activeKinds) {
            primaryKind = activePrimaryKind
        } else if isPendingDismissal, let lastVisiblePrimaryKind {
            primaryKind = lastVisiblePrimaryKind
        } else {
            return nil
        }

        return AuthenticationShieldPresentationState(
            primaryKind: primaryKind,
            activeKinds: activeKinds,
            isPendingDismissal: isPendingDismissal
        )
    }

    func begin(_ kind: AuthenticationShieldKind) {
        if totalPromptDepth == 0 {
            promptCycleID &+= 1
            isPendingDismissal = false
            observedNonActiveLifecycleInCurrentCycle = false
            cancelDismissalFallback()
        }
        adjustDepth(for: kind, delta: 1)
        refreshLastVisiblePrimaryKind()
    }

    func end(_ kind: AuthenticationShieldKind) {
        adjustDepth(for: kind, delta: -1)
        if totalPromptDepth == 0 {
            isPendingDismissal = true
            scheduleFallbackDismissalIfNeeded(for: promptCycleID)
        } else {
            refreshLastVisiblePrimaryKind()
        }
    }

    func sceneDidBecomeActive() {
        noteLifecyclePhase(.active)
    }

    func sceneDidResignActive() {
        noteLifecyclePhase(.inactive)
    }

    func sceneDidEnterBackground() {
        noteLifecyclePhase(.background)
    }

    private var activeKinds: Set<AuthenticationShieldKind> {
        var result: Set<AuthenticationShieldKind> = []
        if privacyPromptDepth > 0 {
            result.insert(.privacy)
        }
        if operationPromptDepth > 0 {
            result.insert(.operation)
        }
        return result
    }

    private var totalPromptDepth: Int {
        privacyPromptDepth + operationPromptDepth
    }

    private func adjustDepth(for kind: AuthenticationShieldKind, delta: Int) {
        switch kind {
        case .privacy:
            privacyPromptDepth = max(privacyPromptDepth + delta, 0)
        case .operation:
            operationPromptDepth = max(operationPromptDepth + delta, 0)
        }
    }

    private func noteLifecyclePhase(_ phase: AuthenticationShieldLifecyclePhase) {
        lastLifecyclePhase = phase

        switch phase {
        case .active:
            guard isPendingDismissal else { return }
            if observedNonActiveLifecycleInCurrentCycle {
                completePendingDismissalIfEligible(for: promptCycleID)
            } else {
                scheduleFallbackDismissalIfNeeded(for: promptCycleID)
            }
        case .inactive, .background:
            observedNonActiveLifecycleInCurrentCycle = true
            cancelDismissalFallback()
        }
    }

    private func scheduleFallbackDismissalIfNeeded(for cycleID: UInt64) {
        guard isPendingDismissal, lastLifecyclePhase == .active else { return }

        cancelDismissalFallback()
        dismissalFallbackTask = Task { @MainActor [weak self] in
            await Task.yield()
            self?.completePendingDismissalIfEligible(for: cycleID)
        }
    }

    private func completePendingDismissalIfEligible(for cycleID: UInt64) {
        guard isPendingDismissal else { return }
        guard promptCycleID == cycleID else { return }
        guard totalPromptDepth == 0 else { return }
        guard lastLifecyclePhase == .active else { return }

        isPendingDismissal = false
        observedNonActiveLifecycleInCurrentCycle = false
        lastVisiblePrimaryKind = nil
        cancelDismissalFallback()
    }

    private func cancelDismissalFallback() {
        dismissalFallbackTask?.cancel()
        dismissalFallbackTask = nil
    }

    private func refreshLastVisiblePrimaryKind() {
        if let activePrimaryKind = activePrimaryKind(for: activeKinds) {
            lastVisiblePrimaryKind = activePrimaryKind
        }
    }

    private func activePrimaryKind(for activeKinds: Set<AuthenticationShieldKind>) -> AuthenticationShieldKind? {
        if activeKinds.contains(.privacy) {
            return .privacy
        }
        if activeKinds.contains(.operation) {
            return .operation
        }
        return nil
    }

    deinit {
        dismissalFallbackTask?.cancel()
    }
}

private struct AuthenticationShieldCoordinatorKey: EnvironmentKey {
    static let defaultValue: AuthenticationShieldCoordinator? = nil
}

extension EnvironmentValues {
    var authenticationShieldCoordinator: AuthenticationShieldCoordinator? {
        get { self[AuthenticationShieldCoordinatorKey.self] }
        set { self[AuthenticationShieldCoordinatorKey.self] = newValue }
    }
}

private struct AuthenticationShieldHostModifier: ViewModifier {
    let explicitCoordinator: AuthenticationShieldCoordinator?
    let handlesLifecycleEvents: Bool

    @Environment(\.authenticationShieldCoordinator) private var environmentCoordinator
    @Environment(\.scenePhase) private var scenePhase

    private var coordinator: AuthenticationShieldCoordinator? {
        explicitCoordinator ?? environmentCoordinator
    }

    func body(content: Content) -> some View {
        let base = ZStack {
            content

            if let coordinator,
               let presentationState = coordinator.presentationState {
                AuthenticationShieldView(presentationState: presentationState)
                    .zIndex(10)
            }
        }

        if handlesLifecycleEvents {
            lifecycleAwareBody(base)
        } else {
            base
        }
    }

    @ViewBuilder
    private func lifecycleAwareBody<Content: View>(_ content: Content) -> some View {
        #if canImport(UIKit)
        content
            .onChange(of: scenePhase) { _, newPhase in
                guard let coordinator else { return }
                switch newPhase {
                case .active:
                    coordinator.sceneDidBecomeActive()
                case .inactive:
                    coordinator.sceneDidResignActive()
                case .background:
                    coordinator.sceneDidEnterBackground()
                @unknown default:
                    break
                }
            }
        #elseif os(macOS)
        content
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                coordinator?.sceneDidBecomeActive()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                coordinator?.sceneDidResignActive()
            }
        #else
        content
        #endif
    }
}

private struct AuthenticationShieldView: View {
    let presentationState: AuthenticationShieldPresentationState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()

            VStack(spacing: 18) {
                Image(systemName: iconName)
                    .font(.system(size: 38, weight: .medium))
                    .foregroundStyle(.primary)
                    .if(!reduceMotion) { view in
                        view.symbolEffect(.pulse, options: .repeating)
                    }

                VStack(spacing: 6) {
                    Text(String(localized: "authShield.title", defaultValue: "Authenticating…"))
                        .font(.headline)
                        .foregroundStyle(.primary)

                    Text(String(localized: "authShield.subtitle", defaultValue: "Secure content is temporarily hidden"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                ProgressView()
                    .tint(.primary)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 320)
            .background(
                .regularMaterial,
                in: RoundedRectangle(cornerRadius: 24, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(Color.primary.opacity(0.08), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.08), radius: 18, y: 8)
            .padding(24)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(
                String(localized: "authShield.a11y.label", defaultValue: "Authentication in progress")
            )
            .accessibilityValue(
                String(localized: "authShield.a11y.value", defaultValue: "Secure content is hidden")
            )
        }
    }

    private var iconName: String {
        #if os(macOS)
        "touchid"
        #else
        "faceid"
        #endif
    }
}

extension View {
    func authenticationShieldHost(
        _ coordinator: AuthenticationShieldCoordinator? = nil,
        handlesLifecycleEvents: Bool = false
    ) -> some View {
        modifier(
            AuthenticationShieldHostModifier(
                explicitCoordinator: coordinator,
                handlesLifecycleEvents: handlesLifecycleEvents
            )
        )
    }
}

private extension View {
    @ViewBuilder
    func `if`<Content: View>(
        _ condition: Bool,
        transform: (Self) -> Content
    ) -> some View {
        if condition {
            transform(self)
        } else {
            self
        }
    }
}
