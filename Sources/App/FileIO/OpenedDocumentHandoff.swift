import SwiftUI

/// Holds a routed document until the screen it is bound for takes it.
///
/// The tool screens own their models privately, which is right — nothing
/// outside a screen should be able to reach into its state. So an opened
/// document is offered rather than injected: the coordinator navigates and
/// leaves the document here, and the screen that arrives claims it. One slot,
/// because an open replaces whatever an earlier open left unclaimed; the app
/// is showing the destination for the newest one either way.
@MainActor
@Observable
final class OpenedDocumentHandoff {
    private(set) var pending: OpenedDocument?

    func offer(_ document: OpenedDocument) {
        pending = document
    }

    /// Claim the pending document if it was meant for this screen.
    func take(for screen: OpenedDocumentScreen) -> OpenedDocument? {
        guard let pending, pending.screen == screen else {
            return nil
        }
        self.pending = nil
        return pending
    }
}

private struct OpenedDocumentHandoffKey: EnvironmentKey {
    static let defaultValue: OpenedDocumentHandoff? = nil
}

extension EnvironmentValues {
    /// The opened-document handoff, where a tool screen is one the app really
    /// navigated to.
    ///
    /// Absent inside the guided tutorial: its screens are a sandbox, and a
    /// document the reader opened belongs to the app they will use afterwards.
    var openedDocumentHandoff: OpenedDocumentHandoff? {
        get { self[OpenedDocumentHandoffKey.self] }
        set { self[OpenedDocumentHandoffKey.self] = newValue }
    }
}

extension View {
    /// Claim a document routed to this screen, on arrival and whenever a later
    /// open routes another one here while it is still on screen.
    func claimsOpenedDocument(
        for screen: OpenedDocumentScreen,
        perform claim: @escaping @MainActor (OpenedDocument) -> Void
    ) -> some View {
        modifier(OpenedDocumentClaimModifier(screen: screen, claim: claim))
    }
}

private struct OpenedDocumentClaimModifier: ViewModifier {
    @Environment(\.openedDocumentHandoff) private var handoff

    let screen: OpenedDocumentScreen
    let claim: @MainActor (OpenedDocument) -> Void

    func body(content: Content) -> some View {
        content
            .onAppear {
                claimPendingDocument()
            }
            .onChange(of: handoff?.pending?.id) { _, _ in
                claimPendingDocument()
            }
    }

    private func claimPendingDocument() {
        guard let document = handoff?.take(for: screen) else { return }
        claim(document)
    }
}
