import Foundation

@MainActor
@Observable
final class IncomingURLImportCoordinator {
    let importConfirmationCoordinator: ImportConfirmationCoordinator

    private let importLoader: PublicKeyImportLoader
    private let importWorkflow: ContactImportWorkflow

    var importError: CypherAirError?
    var isTutorialImportBlocked = false

    var importErrorDescription: String {
        importError?.localizedDescription ?? ""
    }

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

        guard importConfirmationCoordinator.request == nil else {
            importError = .contactImportConfirmationAlreadyPending
            return
        }

        do {
            let inspection = try importLoader.loadFromURL(url)
            let request = try importWorkflow.makeImportConfirmationRequest(
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
            guard importConfirmationCoordinator.present(request) else {
                importError = .contactImportConfirmationAlreadyPending
                return
            }
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
}
