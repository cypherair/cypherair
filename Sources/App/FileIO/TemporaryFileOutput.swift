import Foundation

/// App-layer handle for a temporary file output owned by a workflow.
///
/// ScreenModels read the URL for presentation and the export name for saving,
/// while this value keeps cleanup ownership out of their public action
/// contracts. Cleanup is always the artifact's own: an output takes its
/// artifact's owned directory with it when it has one, and otherwise removes the
/// single file it was given.
struct TemporaryFileOutput {
    private let artifact: AppTemporaryArtifact

    var fileURL: URL { artifact.fileURL }
    var exportFilename: ExportFilename { artifact.exportFilename }

    init(_ artifact: AppTemporaryArtifact) {
        self.artifact = artifact
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
