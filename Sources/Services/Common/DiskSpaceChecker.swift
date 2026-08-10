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
/// Both stream through Rust and can only discover a full volume mid-write — after
/// the user has waited, after any private-key step has made them authenticate, and
/// after the volume has already been driven toward zero (storage pressure can
/// jetsam other apps). Refusing up front costs the user nothing and names the one
/// thing they can act on.
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
    /// Requires twice the input size. That figure is not derived from anything: file
    /// encryption writes binary output — it never armors — and the output's overhead
    /// over the plaintext is packet headers and AEAD chunk tags, a small percentage,
    /// nowhere near a second copy. The margin therefore refuses encrypts that would
    /// have succeeded. Correcting it is tracked as #813 and left alone here.
    ///
    /// - Parameter inputFileSize: Size of the plaintext input file in bytes.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForEncryption(inputFileSize: UInt64) throws {
        try validate(requiredBytes: inputFileSize * 2)
    }

    /// Validate that sufficient disk space is available for streaming file decryption.
    ///
    /// The decrypted size is unknowable before the message is decrypted, so the size
    /// of the ciphertext is the estimate, with nothing added on top:
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
    /// Armored input is the same ciphertext in base64, which encodes 3 bytes as 4
    /// characters (RFC 4648 §4), so the file is a third larger than the ciphertext
    /// inside it and the estimate is three quarters of the file size. The armor
    /// headers, the newline every 64 characters, and the footer are not subtracted,
    /// which leaves that marginally on the demanding side — by well under 2%, where
    /// dropping the correction entirely would over-demand by a third and produce
    /// exactly the refusals the paragraph above rejects.
    ///
    /// A message that expands far beyond its ciphertext still fails during the
    /// write. That path is already safe — the partial output is destroyed and the
    /// failure is reported — it is merely late, which is what this pre-flight
    /// removes for the common case.
    ///
    /// - Parameters:
    ///   - encryptedInputSize: Size of the encrypted input file in bytes.
    ///   - isArmored: Whether that file is ASCII-armored rather than binary.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForDecryption(encryptedInputSize: UInt64, isArmored: Bool) throws {
        try validate(
            requiredBytes: isArmored ? encryptedInputSize / 4 * 3 : encryptedInputSize
        )
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
