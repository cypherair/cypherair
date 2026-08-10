import Foundation

struct AppTemporaryArtifact: Equatable {
    let fileURL: URL
    let ownerDirectoryURL: URL?

    init(fileURL: URL, ownerDirectoryURL: URL? = nil) {
        self.fileURL = fileURL
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
