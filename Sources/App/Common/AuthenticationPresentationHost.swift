#if os(macOS)
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Hosts the in-window macOS authentication prompt (P3 of the auth-lifecycle redesign;
/// TARGET §2.C / §4). It observes `MacAuthenticationPresenter.activePresentation` and,
/// while a presentation is active, renders an `LAAuthenticationView` for its `LAContext`
/// inside the app window — so authentication does not resign the app.
///
/// PR-1 mounts this **dormant**: nothing sets `activePresentation` yet, so it renders
/// nothing. The occluding `AuthenticationShield` was removed in P1, so no `.zIndex`
/// handling is needed here.
private struct AuthenticationPresentationHostModifier: ViewModifier {
    let presenter: MacAuthenticationPresenter

    func body(content: Content) -> some View {
        content
            .overlay {
                if let presentation = presenter.activePresentation {
                    LAAuthenticationViewHost(context: presentation.context) {
                        presenter.viewDidMount()
                    }
                    .id(presentation.id)
                    .ignoresSafeArea()
                    .transition(.opacity)
                }
            }
    }
}

/// Wraps the AppKit `LAAuthenticationView` (LocalAuthenticationEmbeddedUI, macOS 12+)
/// for SwiftUI, signalling `onReady` once the `NSView` is in the hierarchy so the
/// presenter only evaluates after the paired view exists.
private struct LAAuthenticationViewHost: NSViewRepresentable {
    let context: LAContext
    let onReady: () -> Void

    func makeNSView(context _: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: self.context)
        DispatchQueue.main.async { onReady() }
        return view
    }

    func updateNSView(_: LAAuthenticationView, context _: Context) {}
}

extension View {
    /// Mount the macOS in-window authentication host, driven by the given presenter.
    /// Renders nothing unless the presenter is the macOS `MacAuthenticationPresenter`
    /// with an active presentation.
    @ViewBuilder
    func authenticationPresentationHost(_ presenter: any AuthenticationPresenting) -> some View {
        if let macPresenter = presenter as? MacAuthenticationPresenter {
            modifier(AuthenticationPresentationHostModifier(presenter: macPresenter))
        } else {
            self
        }
    }
}
#endif
