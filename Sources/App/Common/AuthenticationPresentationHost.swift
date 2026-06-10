#if os(macOS)
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Hosts the macOS in-window authentication prompt (P3 of the auth-lifecycle
/// redesign; TARGET §2.C / §4). While `MacAuthenticationPresenter` has an active
/// presentation, it renders an `LAAuthenticationView` paired with that
/// presentation's `LAContext` inside the app window — so authentication never
/// resigns the app.
///
/// The prompt chrome reproduces the P0-PoC-validated shape: the embedded view is
/// given an explicit size inside a visible material card (an unconstrained bare
/// mount does not reliably render), behind a full-window scrim that holds the
/// prompt's modality. The occluding `AuthenticationShield` was removed in P1, so
/// no `.zIndex` handling is needed here.
private struct AuthenticationPresentationHostModifier: ViewModifier {
    let presenter: MacAuthenticationPresenter

    func body(content: Content) -> some View {
        content
            .overlay {
                if let presentation = presenter.activePresentation {
                    InWindowAuthenticationSurface(
                        presentation: presentation,
                        onReady: { presenter.viewDidMount(presentation.id) },
                        onCancel: { presenter.cancelActivePresentation() }
                    )
                    .transition(.opacity)
                }
            }
            .animation(
                .easeInOut(duration: 0.15),
                value: presenter.activePresentation?.id
            )
    }
}

private struct InWindowAuthenticationSurface: View {
    let presentation: MacAuthenticationPresenter.ActivePresentation
    let onReady: () -> Void
    let onCancel: () -> Void

    var body: some View {
        ZStack {
            // Scrim: dims and intercepts interaction with the content below for the
            // prompt's lifetime (the modality the detached system sheet provided).
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()

            VStack(spacing: 14) {
                Text(presentation.request.localizedReason)
                    .font(.headline)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)

                LAAuthenticationViewHost(
                    context: presentation.context,
                    onReady: onReady
                )
                .frame(width: 160, height: 160)
                .id(presentation.id)

                Button(
                    String(localized: "auth.inWindow.cancel", defaultValue: "Cancel"),
                    action: onCancel
                )
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("auth.inWindow.cancel")
            }
            .padding(28)
            .frame(maxWidth: 440)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .shadow(radius: 24)
        }
        .accessibilityIdentifier("auth.inWindow.host")
    }
}

/// Wraps the AppKit `LAAuthenticationView` (`LocalAuthenticationEmbeddedUI`) for
/// SwiftUI, signalling `onReady` once the `NSView` exists so the presenter only
/// evaluates after the paired view is mounted (the PoC `viewDidMount` handshake).
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
    /// Mount the macOS in-window authentication host, driven by the given
    /// presenter. Renders nothing unless `presenter` is the macOS
    /// `MacAuthenticationPresenter` with an active presentation.
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
