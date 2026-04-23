import SwiftUI

enum AuthenticationShieldKind: String, Equatable, Hashable {
    case privacy
    case operation
}

struct AuthenticationShieldPresentationState: Equatable {
    let primaryKind: AuthenticationShieldKind
    let activeKinds: Set<AuthenticationShieldKind>
}

@Observable
final class AuthenticationShieldCoordinator: @unchecked Sendable {
    private var privacyPromptDepth = 0
    private var operationPromptDepth = 0

    var isVisible: Bool {
        privacyPromptDepth > 0 || operationPromptDepth > 0
    }

    var presentationState: AuthenticationShieldPresentationState? {
        let activeKinds = activeKinds
        guard !activeKinds.isEmpty else {
            return nil
        }

        let primaryKind: AuthenticationShieldKind = activeKinds.contains(.privacy)
            ? .privacy
            : .operation
        return AuthenticationShieldPresentationState(
            primaryKind: primaryKind,
            activeKinds: activeKinds
        )
    }

    func begin(_ kind: AuthenticationShieldKind) {
        adjustDepth(for: kind, delta: 1)
    }

    func end(_ kind: AuthenticationShieldKind) {
        adjustDepth(for: kind, delta: -1)
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

    private func adjustDepth(for kind: AuthenticationShieldKind, delta: Int) {
        switch kind {
        case .privacy:
            privacyPromptDepth = max(privacyPromptDepth + delta, 0)
        case .operation:
            operationPromptDepth = max(operationPromptDepth + delta, 0)
        }
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

    @Environment(\.authenticationShieldCoordinator) private var environmentCoordinator

    private var coordinator: AuthenticationShieldCoordinator? {
        explicitCoordinator ?? environmentCoordinator
    }

    func body(content: Content) -> some View {
        ZStack {
            content

            if let coordinator,
               let presentationState = coordinator.presentationState {
                AuthenticationShieldView(presentationState: presentationState)
                    .zIndex(10)
            }
        }
    }
}

private struct AuthenticationShieldView: View {
    let presentationState: AuthenticationShieldPresentationState

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            Rectangle()
                .fill(
                    LinearGradient(
                        colors: [
                            Color(red: 0.06, green: 0.08, blue: 0.12),
                            Color(red: 0.02, green: 0.03, blue: 0.05)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .ignoresSafeArea()

            VStack(spacing: 18) {
                Image(systemName: iconName)
                    .font(.system(size: 38, weight: .medium))
                    .foregroundStyle(.white)
                    .if(!reduceMotion) { view in
                        view.symbolEffect(.pulse, options: .repeating)
                    }

                VStack(spacing: 6) {
                    Text(String(localized: "authShield.title", defaultValue: "Authenticating…"))
                        .font(.headline)
                        .foregroundStyle(.white)

                    Text(String(localized: "authShield.subtitle", defaultValue: "Secure content is temporarily hidden"))
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.72))
                        .multilineTextAlignment(.center)
                }

                ProgressView()
                    .tint(.white)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 320)
            .background(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .fill(Color.white.opacity(0.08))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(Color.white.opacity(0.12), lineWidth: 1)
            )
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
        _ coordinator: AuthenticationShieldCoordinator? = nil
    ) -> some View {
        modifier(AuthenticationShieldHostModifier(explicitCoordinator: coordinator))
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
