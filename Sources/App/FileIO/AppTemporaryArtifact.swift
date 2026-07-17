import Foundation

struct AppTemporaryArtifact: Equatable {
    let fileURL: URL
    let ownerDirectoryURL: URL?

    init(fileURL: URL, ownerDirectoryURL: URL? = nil) {
        self.fileURL = fileURL
        self.ownerDirectoryURL = ownerDirectoryURL
    }

    func cleanup(fileManager: FileManager = .default) {
        if let ownerDirectoryURL {
            try? fileManager.removeItem(at: ownerDirectoryURL)
        } else {
            try? fileManager.removeItem(at: fileURL)
        }
    }
}
