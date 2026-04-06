import Foundation

enum OutputArtifactKind {
    case ciphertext
    case publicKey
    case revocation
    case backup
    case generic
}

struct OutputInterceptionPolicy {
    var interceptClipboardCopy: (@MainActor (String, AppConfiguration, OutputArtifactKind) -> Bool)?
    var interceptDataExport: (@MainActor (Data, String, OutputArtifactKind) throws -> Bool)?
    var interceptFileExport: (@MainActor (URL, String, OutputArtifactKind) -> Bool)?

    static let passthrough = OutputInterceptionPolicy()
}
