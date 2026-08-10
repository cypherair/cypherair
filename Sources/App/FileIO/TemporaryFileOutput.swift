import Foundation

/// App-layer handle for a temporary file output owned by a workflow.
///
/// ScreenModels expose the URL for presentation/export while this value keeps
/// cleanup ownership out of their public action contracts. Cleanup is always the
/// artifact's own, so an output built from an artifact takes that artifact's
/// owned directory with it, and one built from a bare URL removes the one file
/// it was given. What is gone is the second removal *implementation* this type
/// used to carry, which discarded the file and left the directory standing.
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
