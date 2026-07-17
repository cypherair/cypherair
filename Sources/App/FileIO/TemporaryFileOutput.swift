import Foundation

/// App-layer wrapper for temporary file outputs owned by a workflow.
///
/// ScreenModels expose the URL for presentation/export while this value keeps
/// cleanup ownership out of their public action contracts.
struct TemporaryFileOutput {
    let fileURL: URL

    private let cleanupAction: () -> Void

    init(fileURL: URL, cleanup: @escaping () -> Void) {
        self.fileURL = fileURL
        self.cleanupAction = cleanup
    }

    init(fileURL: URL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.cleanupAction = {
            try? fileManager.removeItem(at: fileURL)
        }
    }

    func cleanup() {
        cleanupAction()
    }
}

extension AppTemporaryArtifact {
    var temporaryFileOutput: TemporaryFileOutput {
        TemporaryFileOutput(fileURL: fileURL) {
            cleanup()
        }
    }
}
