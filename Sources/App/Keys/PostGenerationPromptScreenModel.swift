import Foundation

@MainActor
@Observable
final class PostGenerationPromptScreenModel {
    typealias RevocationExportAction = @MainActor (String) async throws -> Data

    let identity: PGPKeyIdentity
    let exportController: FileExportController

    private let revocationExportAction: RevocationExportAction
    private var revocationExportTask: Task<Void, Never>?
    private var revocationExportGeneration: UInt64 = 0

    var isPreparingRevocationExport = false
    var error: CypherAirError?
    var showError = false

    init(
        identity: PGPKeyIdentity,
        keyManagement: KeyManagementService,
        exportController: FileExportController = FileExportController(),
        revocationExportAction: RevocationExportAction? = nil
    ) {
        self.identity = identity
        self.exportController = exportController
        self.revocationExportAction = revocationExportAction ?? { fingerprint in
            try await keyManagement.exportRevocationCertificate(fingerprint: fingerprint)
        }
    }

    var isDeviceBound: Bool {
        identity.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations
    }

    func exportRevocationCertificate() {
        guard !isPreparingRevocationExport else {
            return
        }

        revocationExportTask?.cancel()
        revocationExportGeneration &+= 1
        let generation = revocationExportGeneration
        isPreparingRevocationExport = true

        revocationExportTask = Task { [weak self, generation] in
            guard let self else { return }
            defer {
                if generation == self.revocationExportGeneration {
                    self.isPreparingRevocationExport = false
                    self.revocationExportTask = nil
                }
            }

            do {
                let exported = try await self.revocationExportAction(self.identity.fingerprint)
                try Task.checkCancellation()
                guard generation == self.revocationExportGeneration else {
                    return
                }
                try self.exportController.prepareDataExport(
                    exported,
                    suggestedFilename: "revocation-\(self.identity.shortKeyId).asc"
                )
            } catch {
                guard !Self.shouldIgnore(error),
                      generation == self.revocationExportGeneration else {
                    return
                }
                self.presentMappedError(error)
            }
        }
    }

    func dismissError() {
        error = nil
        showError = false
    }

    func finishExport() {
        exportController.finish()
    }

    func handleExportError(_ error: Error) {
        presentMappedError(error)
    }

    func handleDisappear() {
        revocationExportGeneration &+= 1
        revocationExportTask?.cancel()
        revocationExportTask = nil
        isPreparingRevocationExport = false
        exportController.finish()
    }

    private func presentMappedError(_ error: Error) {
        self.error = CypherAirError.from(error) { .keychainError($0) }
        showError = true
    }

    private static func shouldIgnore(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        if let cypherAirError = error as? CypherAirError,
           case .operationCancelled = cypherAirError {
            return true
        }
        return false
    }
}
