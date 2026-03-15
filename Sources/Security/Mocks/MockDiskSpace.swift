import Foundation

/// Mock disk space provider for testing.
/// Allows tests to simulate different disk space conditions.
///
/// Marked `@unchecked Sendable` because `DiskSpaceProvidable` requires `Sendable`.
/// The mutable state (`availableBytes`, `callCount`) is not thread-safe.
/// Only use from test methods on a single actor.
final class MockDiskSpace: DiskSpaceProvidable, @unchecked Sendable {
    /// The value to return from availableDiskSpaceBytes().
    /// Default: 10 GB (simulates a device with ample free space).
    var availableBytes: UInt64 = 10 * 1024 * 1024 * 1024

    /// Track calls for test verification.
    private(set) var callCount = 0

    /// If true, throws a fileIoError instead of returning availableBytes.
    var shouldThrow = false

    func availableDiskSpaceBytes() throws -> UInt64 {
        callCount += 1
        if shouldThrow {
            throw CypherAirError.fileIoError(reason: "Mock disk error")
        }
        return availableBytes
    }

    /// Reset state for clean test setup.
    func reset() {
        availableBytes = 10 * 1024 * 1024 * 1024
        callCount = 0
        shouldThrow = false
    }
}
