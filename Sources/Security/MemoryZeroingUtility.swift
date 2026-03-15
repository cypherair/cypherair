import Foundation

/// Auto-zeroing wrapper for sensitive data (private keys, passphrases, plaintext).
/// Calls `resetBytes(in:)` on deinit to prevent key material from lingering in memory.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 7.
///
/// Usage:
/// ```swift
/// let sensitive = SensitiveData(data)
/// // ... use sensitive.data ...
/// // Automatically zeroed when `sensitive` goes out of scope.
/// // Or call sensitive.zeroize() explicitly for immediate clearing.
/// ```
nonisolated final class SensitiveData {
    private var storage: Data

    /// The underlying data. Read-only access.
    ///
    /// WARNING: This returns a value copy of the data (Swift copy-on-write semantics).
    /// The returned copy is NOT controlled by `SensitiveData.zeroize()` or `deinit`.
    /// If you store the returned `Data` in a variable, you are responsible for calling
    /// `.zeroize()` on that copy when done. Prefer `withUnsafeBytes` when possible
    /// to avoid creating unmanaged copies.
    var data: Data { storage }

    /// Access the underlying bytes without creating an unmanaged copy.
    /// The closure receives a read-only pointer to the data. No copy is made,
    /// so `zeroize()` / `deinit` will reliably clear the only copy.
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    /// The byte count of the underlying data.
    var count: Int { storage.count }

    /// Whether the underlying data is empty.
    var isEmpty: Bool { storage.isEmpty }

    init(_ data: Data) {
        self.storage = data
    }

    /// Explicitly zero the data before the object is deallocated.
    func zeroize() {
        storage.zeroize()
    }

    deinit {
        storage.zeroize()
    }
}
