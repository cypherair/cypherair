import Foundation

/// App-layer handle for a temporary file output owned by a workflow.
///
/// ScreenModels expose the URL for presentation/export while this value keeps
/// cleanup ownership out of their public action contracts. Cleanup is the
/// artifact's own — there is no "just the file" variant, because an output that
/// arrived with an owned directory has to take that directory with it.
struct TemporaryFileOutput {
    private let artifact: AppTemporaryArtifact

    var fileURL: URL { artifact.fileURL }

    init(_ artifact: AppTemporaryArtifact) {
        self.artifact = artifact
    }

    init(fileURL: URL) {
        self.init(AppTemporaryArtifact(fileURL: fileURL))
    }

    func cleanup() {
        artifact.cleanup()
    }
}

extension AppTemporaryArtifact {
    var temporaryFileOutput: TemporaryFileOutput {
        TemporaryFileOutput(self)
    }
}
