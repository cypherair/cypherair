import Foundation

enum OutputArtifactKind {
    case ciphertext
    case publicKey
    case revocation
    case generic
}

struct OutputInterceptionPolicy {
    var interceptClipboardCopy: (@MainActor (String, AppConfiguration, OutputArtifactKind) -> Bool)?
    var interceptDataExport: (@MainActor (Data, ExportFilename, OutputArtifactKind) throws -> Bool)?
    var interceptFileExport: (@MainActor (URL, ExportFilename, OutputArtifactKind) -> Bool)?

    static let passthrough = OutputInterceptionPolicy()
}
