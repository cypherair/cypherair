import Foundation

/// Extension for secure memory zeroing of sensitive data.
/// SECURITY-CRITICAL: See CLAUDE.md hard constraint #5.
extension Data {
    /// Overwrite all bytes with zeros.
    /// Call this on any `Data` containing key material, passphrases, or plaintext
    /// as soon as it is no longer needed.
    ///
    /// Uses `resetBytes(in:)` which is a Foundation method call across a module
    /// boundary, preventing the Swift optimizer from eliminating it as a dead store.
    nonisolated mutating func zeroize() {
        guard !isEmpty else { return }
        resetBytes(in: startIndex..<endIndex)
    }
}
