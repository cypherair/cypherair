import Foundation

@MainActor
@Observable
final class IncomingURLImportCoordinator {
    let importConfirmationCoordinator: ImportConfirmationCoordinator

    private let importLoader: PublicKeyImportLoader
    private let importWorkflow: ContactImportWorkflow

    var importError: CypherAirError?
    var pendingKeyUpdateRequest: ContactKeyUpdateConfirmationRequest?
    var isTutorialImportBlocked = false

    init(
        importLoader: PublicKeyImportLoader,
        importWorkflow: ContactImportWorkflow,
        importConfirmationCoordinator: ImportConfirmationCoordinator = ImportConfirmationCoordinator()
    ) {
        self.importLoader = importLoader
        self.importWorkflow = importWorkflow
        self.importConfirmationCoordinator = importConfirmationCoordinator
    }

    func handleIncomingURL(
        _ url: URL,
        isTutorialPresentationActive: Bool
    ) {
        guard url.scheme == "cypherair" else { return }

        guard !isTutorialPresentationActive else {
            isTutorialImportBlocked = true
            return
        }

        do {
            let inspection = try importLoader.loadFromURL(url)
            importConfirmationCoordinator.present(
                importWorkflow.makeImportConfirmationRequest(
                    inspection: inspection,
                    allowsUnverifiedImport: true,
                    onSuccess: { [self] _ in
                        importConfirmationCoordinator.dismiss()
                    },
                    onReplaceRequested: { [self] request in
                        importConfirmationCoordinator.dismiss()
                        pendingKeyUpdateRequest = request
                    },
                    onFailure: { [self] importError in
                        self.importError = importError
                        importConfirmationCoordinator.dismiss()
                    }
                )
            )
        } catch {
            importError = CypherAirError.from(error) { _ in .invalidQRCode }
        }
    }

    func dismissImportError() {
        importError = nil
    }

    func dismissTutorialImportBlocked() {
        isTutorialImportBlocked = false
    }

    func confirmPendingKeyUpdate() {
        guard let pendingKeyUpdateRequest else {
            return
        }

        self.pendingKeyUpdateRequest = nil
        pendingKeyUpdateRequest.onConfirm()
    }

    func cancelPendingKeyUpdate() {
        guard let pendingKeyUpdateRequest else {
            return
        }

        self.pendingKeyUpdateRequest = nil
        pendingKeyUpdateRequest.onCancel()
    }
}
