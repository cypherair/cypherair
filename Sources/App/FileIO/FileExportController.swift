import CoreTransferable
import Foundation
import UniformTypeIdentifiers

/// What an export offers and the name it is offered under, in one value.
///
/// The picker asks twice — once through the transferable item, once through the
/// exporter's default filename — and both answers read this single stored name,
/// so they cannot disagree. The URL is a storage detail that never reaches the
/// user; only `filename` does.
struct ExportPayload: Transferable {
    let url: URL
    let filename: ExportFilename

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .data) { payload in
            SentTransferredFile(payload.url)
        }
        .suggestedFileName { payload in
            payload.filename.value
        }
    }
}

/// Shared export state for exporting either an existing file or generated data.
///
/// The one owner of an exported file's name: every screen hands its artifact
/// here, and the presentation reads the name back from `payload`.
@Observable
final class FileExportController {
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    private(set) var payload: ExportPayload?
    var isPresented = false

    private var ownedTemporaryFile: URL?

    init(temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()) {
        self.temporaryArtifactStore = temporaryArtifactStore
    }

    /// Offer in-memory data, staged through a temporary file the controller owns
    /// and erases. The staging file is written under verified complete
    /// protection, which is why the app writes it rather than letting the picker
    /// copy the bytes somewhere of its own choosing.
    func prepareDataExport(_ data: Data, filename: ExportFilename) throws {
        cleanupOwnedTemporaryFile()

        let temporaryURL = try temporaryArtifactStore.writeProtectedExportData(data)

        ownedTemporaryFile = temporaryURL
        present(ExportPayload(url: temporaryURL, filename: filename))
    }

    /// Offer a file the controller does not own — an operation artifact whose
    /// lifetime belongs to the workflow that produced it.
    func prepareFileExport(fileURL: URL, filename: ExportFilename) {
        cleanupOwnedTemporaryFile()
        present(ExportPayload(url: fileURL, filename: filename))
    }

    func finish() {
        isPresented = false
        payload = nil
        cleanupOwnedTemporaryFile()
    }

    private func present(_ payload: ExportPayload) {
        self.payload = payload
        isPresented = true
    }

    private func cleanupOwnedTemporaryFile() {
        if let ownedTemporaryFile {
            temporaryArtifactStore.eraseTemporaryArtifact(at: ownedTemporaryFile)
            self.ownedTemporaryFile = nil
        }
    }
}
