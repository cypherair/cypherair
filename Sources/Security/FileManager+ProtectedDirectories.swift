import Foundation

extension FileManager {
    /// Create a directory born with the complete file-protection class.
    ///
    /// Protection is a property of where a file is written, stated once, here:
    /// the class is a creation attribute, applied equally to every intermediate
    /// directory created along the way, and everything later born inside
    /// inherits it — including the files the app does not create itself, such
    /// as the SQLCipher database and its journal, and the encryption engine's
    /// streaming outputs and temporary files. Nothing anywhere re-applies
    /// protection to a file after the fact.
    ///
    /// An existing directory is left as it is: it was created through this
    /// helper and already carries the class.
    func createProtectedDirectory(at url: URL) throws {
        try createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete]
        )
    }
}
