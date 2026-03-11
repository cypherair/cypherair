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
final class SensitiveData {
    private var storage: Data

    /// The underlying data. Read-only access.
    var data: Data { storage }

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
