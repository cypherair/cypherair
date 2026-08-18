import CoreTransferable
import Foundation
import UniformTypeIdentifiers

/// File-based export payload used by `fileExporter`.
struct ExportPayload: Transferable {
    let url: URL

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { payload in
            SentTransferredFile(payload.url)
        }
        .suggestedFileName { payload in
            payload.url.lastPathComponent
        }
    }
}

/// Shared export state for exporting either an existing file or generated data.
@Observable
final class FileExportController {
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    private(set) var payload: ExportPayload?
    private(set) var defaultFilename = "export"
    var isPresented = false

    private var ownedTemporaryArtifact: AppTemporaryArtifact?

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) {
        self.temporaryArtifactStore = temporaryArtifactStore
    }

    func prepareDataExport(_ data: Data, suggestedFilename: String) throws {
        cleanupOwnedTemporaryArtifact()

        let artifact = try temporaryArtifactStore.writeProtectedExportData(
            data,
            suggestedFilename: suggestedFilename
        )

        ownedTemporaryArtifact = artifact
        payload = ExportPayload(url: artifact.fileURL)
        defaultFilename = suggestedFilename
        isPresented = true
    }

    func prepareFileExport(fileURL: URL, suggestedFilename: String) {
        cleanupOwnedTemporaryArtifact()
        payload = ExportPayload(url: fileURL)
        defaultFilename = suggestedFilename
        isPresented = true
    }

    func finish() {
        isPresented = false
        payload = nil
        cleanupOwnedTemporaryArtifact()
    }

    private func cleanupOwnedTemporaryArtifact() {
        ownedTemporaryArtifact?.cleanup()
        ownedTemporaryArtifact = nil
    }
}
