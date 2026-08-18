import Foundation

/// Everything that arrives from outside the app: an import link from a scanned
/// QR code, and a document the system asked the app to open.
///
/// Both are URLs delivered to the same scene callback, and both end the same
/// way — something visible. A link resolves to one destination, the contact
/// import confirmation; a document is read first, because its content decides
/// where it goes and its name decides where it is allowed to go. Nothing here
/// returns silently: the app advertises itself as a handler for these files, and
/// a handler that drops one is worse than not claiming them.
@MainActor
@Observable
final class IncomingURLImportCoordinator {
    let importConfirmationCoordinator: ImportConfirmationCoordinator

    private let importLoader: PublicKeyImportLoader
    private let importWorkflow: ContactImportWorkflow
    private let openedDocumentReader: OpenedDocumentReader
    private let openedDocumentHandoff: OpenedDocumentHandoff
    private let navigationState: AppShellNavigationState

    var importError: CypherAirError?
    var isTutorialImportBlocked = false

    var importErrorDescription: String {
        importError?.localizedDescription ?? ""
    }

    init(
        importLoader: PublicKeyImportLoader,
        importWorkflow: ContactImportWorkflow,
        openedDocumentReader: OpenedDocumentReader,
        openedDocumentHandoff: OpenedDocumentHandoff,
        navigationState: AppShellNavigationState,
        importConfirmationCoordinator: ImportConfirmationCoordinator = ImportConfirmationCoordinator()
    ) {
        self.importLoader = importLoader
        self.importWorkflow = importWorkflow
        self.openedDocumentReader = openedDocumentReader
        self.openedDocumentHandoff = openedDocumentHandoff
        self.navigationState = navigationState
        self.importConfirmationCoordinator = importConfirmationCoordinator
    }

    func handleIncomingURL(
        _ url: URL,
        isTutorialPresentationActive: Bool
    ) {
        guard url.isFileURL || url.scheme == CypherAirImportURL.scheme else { return }

        guard !isTutorialPresentationActive else {
            isTutorialImportBlocked = true
            discardIfOpenedDocument(url)
            return
        }

        // One confirmation at a time, whichever route asked for it. Queueing
        // would put a second key behind a sheet the reader is already deciding
        // about, and they would approve the one they never saw arrive.
        guard importConfirmationCoordinator.request == nil else {
            importError = .contactImportConfirmationAlreadyPending
            discardIfOpenedDocument(url)
            return
        }

        if url.isFileURL {
            handleOpenedDocument(at: url)
        } else {
            presentContactImportConfirmation(for: url)
        }
    }

    func dismissImportError() {
        importError = nil
    }

    func dismissTutorialImportBlocked() {
        isTutorialImportBlocked = false
    }

    private func discardIfOpenedDocument(_ url: URL) {
        guard url.isFileURL else { return }
        openedDocumentReader.discard(url)
    }

    private func presentContactImportConfirmation(for url: URL) {
        do {
            try presentContactImportConfirmation(
                inspection: try importLoader.loadFromURL(url)
            )
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
    }

    private func handleOpenedDocument(at url: URL) {
        do {
            switch try openedDocumentReader.read(url) {
            case .contactImport(let certificate):
                try presentContactImportConfirmation(
                    inspection: try importLoader.inspect(keyData: certificate)
                )
            case .handoff(let document):
                // Navigate first: the screen claims the document as it appears,
                // so a document offered before the app has moved would be
                // claimed by whatever screen happened to be showing.
                navigationState.present(document.screen.route, on: document.screen.tab)
                openedDocumentHandoff.offer(document)
            }
        } catch {
            importError = CypherAirError.from(error) { _ in .openedFileUnsupportedContent }
        }
    }

    /// Raise the confirmation. Nothing can be pending: `handleIncomingURL`
    /// refused this arrival if something was, and everything between that guard
    /// and here runs on this actor without suspending.
    private func presentContactImportConfirmation(
        inspection: PublicKeyImportInspection
    ) throws {
        importConfirmationCoordinator.present(
            try importWorkflow.makeImportConfirmationRequest(
                inspection: inspection,
                allowsUnverifiedImport: true,
                onSuccess: { [self] _ in
                    importConfirmationCoordinator.dismiss()
                },
                onFailure: { [self] importError in
                    self.importError = importError
                    importConfirmationCoordinator.dismiss()
                }
            )
        )
    }
}
