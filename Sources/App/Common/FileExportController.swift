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
    private(set) var payload: ExportPayload?
    private(set) var defaultFilename = "export"
    var isPresented = false

    private var ownedTemporaryFile: URL?

    func prepareDataExport(_ data: Data, suggestedFilename: String) throws {
        cleanupOwnedTemporaryFile()

        let sanitizedFilename = (suggestedFilename as NSString).lastPathComponent
        let temporaryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("export-\(UUID().uuidString)-\(sanitizedFilename)")

        try data.write(to: temporaryURL, options: .atomic)

        ownedTemporaryFile = temporaryURL
        payload = ExportPayload(url: temporaryURL)
        defaultFilename = suggestedFilename
        isPresented = true
    }

    func prepareFileExport(fileURL: URL, suggestedFilename: String) {
        cleanupOwnedTemporaryFile()
        payload = ExportPayload(url: fileURL)
        defaultFilename = suggestedFilename
        isPresented = true
    }

    func finish() {
        isPresented = false
        payload = nil
        cleanupOwnedTemporaryFile()
    }

    private func cleanupOwnedTemporaryFile() {
        if let ownedTemporaryFile {
            try? FileManager.default.removeItem(at: ownedTemporaryFile)
            self.ownedTemporaryFile = nil
        }
    }
}
