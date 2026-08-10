import Foundation

/// Protocol for querying system memory availability.
/// Production: `SystemMemoryInfo`. Test: configurable mock value.
protocol MemoryInfoProvidable: Sendable {
    /// Returns the bytes the process may still allocate under the memory limit
    /// it has actually been granted — the headroom before Jetsam would
    /// terminate it. Advisory and momentary: read it per operation, never cache.
    func availableMemoryBytes() -> UInt64
}
