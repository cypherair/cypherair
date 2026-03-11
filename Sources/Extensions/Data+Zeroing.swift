import Foundation

/// Extension for secure memory zeroing of sensitive data.
/// SECURITY-CRITICAL: See CLAUDE.md hard constraint #5.
extension Data {
    /// Overwrite all bytes with zeros.
    /// Call this on any `Data` containing key material, passphrases, or plaintext
    /// as soon as it is no longer needed.
    mutating func zeroize() {
        guard !isEmpty else { return }
        resetBytes(in: startIndex..<endIndex)
    }
}

extension Array where Element == UInt8 {
    /// Overwrite all bytes with zeros.
    mutating func zeroize() {
        for i in indices {
            self[i] = 0
        }
    }
}
