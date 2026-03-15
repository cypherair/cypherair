import Foundation

extension Data {
    /// Writes this data to a temporary file in `tmp/share/` with the given filename.
    /// Returns the file URL on success, or `nil` if the write fails.
    /// Used by ShareLink to ensure exported files retain their proper filenames.
    func writeToShareTempFile(named filename: String) -> URL? {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("share", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let sanitized = (filename as NSString).lastPathComponent
        guard !sanitized.isEmpty else { return nil }
        let url = dir.appendingPathComponent(sanitized)
        do {
            try write(to: url)
            return url
        } catch {
            return nil
        }
    }
}
