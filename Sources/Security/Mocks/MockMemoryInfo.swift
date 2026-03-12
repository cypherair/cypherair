import Foundation

/// Mock memory info provider for testing Argon2id memory guard logic.
/// Allows tests to simulate different device memory conditions.
final class MockMemoryInfo: MemoryInfoProvidable, @unchecked Sendable {
    /// The value to return from availableMemoryBytes().
    /// Default: 4 GB (simulates a typical device under moderate load).
    var availableBytes: UInt64 = 4 * 1024 * 1024 * 1024

    /// Track calls for test verification.
    private(set) var callCount = 0

    func availableMemoryBytes() -> UInt64 {
        callCount += 1
        return availableBytes
    }

    /// Reset state for clean test setup.
    func reset() {
        availableBytes = 4 * 1024 * 1024 * 1024
        callCount = 0
    }
}
