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

/// Free-space pre-flight for the streaming file operations that write a second
/// whole copy of the user's data into the app's temporary directory: file
/// encryption and file decryption.
///
/// Both stream through Rust and can only discover a full volume mid-write —
/// after the user has authenticated and waited, and after the volume has already
/// been driven toward zero (storage pressure can jetsam other apps). Refusing up
/// front costs the user nothing and names the one thing they can act on.
///
/// Detached signing is deliberately not covered: it produces a small `.sig`, not
/// a second copy of the payload.
struct DiskSpaceChecker {

    private let diskSpace: any DiskSpaceProvidable

    init(diskSpace: any DiskSpaceProvidable = SystemDiskSpace()) {
        self.diskSpace = diskSpace
    }

    /// Validate that sufficient disk space is available for streaming file encryption.
    ///
    /// Uses a 2x multiplier as a conservative estimate for encryption overhead
    /// (PKESK headers, session key packets, AEAD/MDC tags, potential armor encoding).
    ///
    /// - Parameter inputFileSize: Size of the plaintext input file in bytes.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForEncryption(inputFileSize: UInt64) throws {
        try validate(requiredBytes: inputFileSize * 2)
    }

    /// Validate that sufficient disk space is available for streaming file decryption.
    ///
    /// The decrypted size is unknowable before the message is decrypted, so the
    /// encrypted input size is the estimate, with nothing added on top:
    ///
    /// - CypherAir never compresses what it encrypts, and the foreign payloads
    ///   large enough to matter here (media, archives) are already incompressible,
    ///   so plaintext ≈ ciphertext for the dominant case — slightly under it, once
    ///   packet overhead is subtracted.
    /// - A multiplier would refuse decrypts that would have succeeded, precisely on
    ///   the nearly-full device this guard exists for. Peak usage really is one
    ///   copy: the pipeline writes a sibling temp file and renames it into place on
    ///   the same volume.
    ///
    /// A message that expands far beyond its ciphertext still fails during the
    /// write. That path is already safe — the partial output is destroyed and the
    /// failure is reported — it is merely late, which is what this pre-flight
    /// removes for the common case.
    ///
    /// - Parameter encryptedInputSize: Size of the encrypted input file in bytes.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForDecryption(encryptedInputSize: UInt64) throws {
        try validate(requiredBytes: encryptedInputSize)
    }

    private func validate(requiredBytes: UInt64) throws {
        let available = try diskSpace.availableDiskSpaceBytes()
        guard available >= requiredBytes else {
            throw CypherAirError.insufficientDiskSpace(
                requiredMB: Int(requiredBytes / (1024 * 1024)),
                availableMB: Int(available / (1024 * 1024))
            )
        }
    }
}
