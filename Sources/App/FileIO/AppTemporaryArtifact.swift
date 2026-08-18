import Foundation

/// A temporary file an operation produced, together with the name it is offered
/// under if the user saves it.
///
/// The two are deliberately independent: the path is a UUID that says nothing
/// about the file's contents, and the user-facing name lives only in memory.
struct AppTemporaryArtifact: Equatable {
    let fileURL: URL
    let exportFilename: ExportFilename
    let ownerDirectoryURL: URL?

    init(fileURL: URL, exportFilename: ExportFilename, ownerDirectoryURL: URL? = nil) {
        self.fileURL = fileURL
        self.exportFilename = exportFilename
        self.ownerDirectoryURL = ownerDirectoryURL
    }

    /// Erase the artifact, taking the whole owned directory when it has one so
    /// that anything the operation wrote beside the output goes with it.
    func cleanup(fileManager: FileManager = .default) {
        try? TemporaryArtifactEraser.erase(
            at: ownerDirectoryURL ?? fileURL,
            fileManager: fileManager
        )
    }
}
