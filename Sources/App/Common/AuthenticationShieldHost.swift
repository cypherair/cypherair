import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

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
        let coordinator = coordinator
        let presentationState = coordinator?.presentationState

        let base = ZStack {
            content

            if let coordinator,
               let presentationState {
                AuthenticationShieldView(presentationState: presentationState)
                    .zIndex(10)
                    .transition(.asymmetric(insertion: .identity, removal: .opacity))
                    .onAppear {
                        coordinator.noteRenderVisible(presentationState)
                    }
                    .onDisappear {
                        coordinator.noteRenderHidden()
                    }
            }
        }
        .animation(
            presentationState == nil ? .easeOut(duration: AuthenticationShieldAnimation.overlayDismissalDuration) : nil,
            value: presentationState
        )

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
