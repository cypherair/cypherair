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
    mutating func zeroize() {
        guard !isEmpty else { return }
        resetBytes(in: startIndex..<endIndex)
    }
}

extension Array where Element == UInt8 {
    /// Overwrite all bytes with zeros.
    ///
    /// Uses `withUnsafeMutableBufferPointer` + `Darwin.memset` via an indirect
    /// call to prevent the optimizer from eliminating the zeroing as a dead store.
    /// The `_opaqueZero` function is `@_optimize(none)` to ensure the compiler
    /// cannot see through the call and eliminate the write.
    mutating func zeroize() {
        guard !isEmpty else { return }
        withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            _opaqueZero(base, buffer.count)
        }
    }
}

/// Zero `count` bytes at `ptr`. Marked `@_optimize(none)` to prevent the
/// compiler from recognizing this as a dead store and optimizing it away.
/// This is the standard mitigation for secure zeroing in Swift, analogous
/// to `explicit_bzero` / `memset_s` / `SecureZeroMemory` in C.
@_optimize(none)
private func _opaqueZero(_ ptr: UnsafeMutablePointer<UInt8>, _ count: Int) {
    ptr.initialize(repeating: 0, count: count)
}
