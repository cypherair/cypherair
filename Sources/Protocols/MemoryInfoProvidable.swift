import Foundation

/// Protocol for querying system memory availability.
/// Production: calls os_proc_available_memory().
/// Test: configurable mock value.
protocol MemoryInfoProvidable: Sendable {
    /// Returns the number of bytes of memory available to the process
    /// before iOS Jetsam would terminate it.
    func availableMemoryBytes() -> UInt64
}
