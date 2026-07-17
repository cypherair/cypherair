import Foundation

/// Protocol for querying available disk space.
/// Production: uses FileManager resource values.
/// Test: configurable mock value.
protocol DiskSpaceProvidable: Sendable {
    /// Returns the number of bytes of disk space available for important usage.
    func availableDiskSpaceBytes() throws -> UInt64
}

/// Production implementation of DiskSpaceProvidable.
/// Uses `volumeAvailableCapacityForImportantUsageKey` which accounts for
/// purgeable space and is the recommended API for pre-flight checks.
struct SystemDiskSpace: DiskSpaceProvidable {
    func availableDiskSpaceBytes() throws -> UInt64 {
        let values = try URL(fileURLWithPath: NSTemporaryDirectory())
            .resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return UInt64(values.volumeAvailableCapacityForImportantUsage ?? 0)
    }
}

/// Pre-encryption disk space validation.
/// Ensures sufficient space for the output file before starting a streaming operation.
///
/// Follows the same pattern as `Argon2idMemoryGuard`:
/// protocol → production impl → guard struct → mock.
struct DiskSpaceChecker {

    private let diskSpace: any DiskSpaceProvidable

    init(diskSpace: any DiskSpaceProvidable = SystemDiskSpace()) {
        self.diskSpace = diskSpace
    }

    /// Validate that sufficient disk space is available for file encryption.
    ///
    /// Uses a 2x multiplier as a conservative estimate for encryption overhead
    /// (PKESK headers, session key packets, AEAD/MDC tags, potential armor encoding).
    ///
    /// Signing produces small .sig files — no disk space check is needed for signing.
    ///
    /// - Parameter inputFileSize: Size of the input file in bytes.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForEncryption(inputFileSize: UInt64) throws {
        let requiredBytes = inputFileSize * 2
        let requiredMB = Int(requiredBytes / (1024 * 1024))
        let fileSizeMB = Int(inputFileSize / (1024 * 1024))

        let available = try diskSpace.availableDiskSpaceBytes()
        let availableMB = Int(available / (1024 * 1024))

        guard available >= requiredBytes else {
            throw CypherAirError.insufficientDiskSpace(
                fileSizeMB: fileSizeMB,
                requiredMB: requiredMB,
                availableMB: availableMB
            )
        }
    }
}
