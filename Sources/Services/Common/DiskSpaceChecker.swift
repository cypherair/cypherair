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
/// The pre-flight owns the whole estimate: it reads the input's size itself, and
/// **an input whose size cannot be read is never a reason to refuse** — this check
/// fails only for missing space, and an unreadable input reports itself through
/// the pipeline's own file error. Both directions estimate one copy of the data
/// with no safety margin, because a multiplier refuses operations that would have
/// succeeded precisely on the nearly-full device the guard exists for; the rare
/// case that squeaks past the estimate still fails safely, merely late, with the
/// partial output destroyed and the failure reported.
///
/// Detached signing is deliberately not covered: it produces a small `.sig`, not
/// a second copy of the payload.
struct DiskSpaceChecker {

    private let diskSpace: any DiskSpaceProvidable

    init(diskSpace: any DiskSpaceProvidable = SystemDiskSpace()) {
        self.diskSpace = diskSpace
    }

    /// Validate that sufficient disk space is available for streaming file
    /// encryption of the file at `inputPath`.
    ///
    /// The estimate is the input size with nothing added: file encryption writes
    /// binary output — it never armors — and the output exceeds the plaintext only
    /// by packet headers and AEAD chunk tags, a small fraction of a percent. The
    /// residual error therefore sits on the permissive side, where the struct
    /// note's safe-but-late failure covers it, instead of on the refusing side.
    ///
    /// - Parameter inputPath: Path of the plaintext input file.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForEncryption(inputPath: String) throws {
        guard let inputFileSize = Self.fileSize(atPath: inputPath) else { return }
        try validate(requiredBytes: inputFileSize)
    }

    /// Validate that sufficient disk space is available for streaming file
    /// decryption of the file at `inputPath`.
    ///
    /// The decrypted size is unknowable before the message is decrypted, so the size
    /// of the ciphertext is the estimate:
    ///
    /// - CypherAir never compresses what it encrypts, and the foreign payloads
    ///   large enough to matter here (media, archives) are already incompressible,
    ///   so plaintext ≈ ciphertext for the dominant case — slightly under it, once
    ///   packet overhead is subtracted.
    ///
    /// Armored input is the same ciphertext in base64, which encodes 3 bytes as 4
    /// characters (RFC 4648 §4), so the file is a third larger than the ciphertext
    /// inside it and the estimate is three quarters of the file size. The armor
    /// headers, the newline every 64 characters, and the footer are not subtracted,
    /// which leaves that marginally on the demanding side — by well under 2%, where
    /// dropping the correction entirely would over-demand by a third and refuse
    /// decrypts that would have succeeded.
    ///
    /// - Parameter inputPath: Path of the encrypted input file.
    /// - Throws: `CypherAirError.insufficientDiskSpace` if available space is insufficient.
    func validateForDecryption(inputPath: String) throws {
        guard let encryptedInputSize = Self.fileSize(atPath: inputPath) else { return }
        try validate(
            requiredBytes: Self.hasArmorHeader(atPath: inputPath)
                ? encryptedInputSize / 4 * 3
                : encryptedInputSize
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

    private static func fileSize(atPath path: String) -> UInt64? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path) else {
            return nil
        }
        return attributes[.size] as? UInt64
    }

    /// Enough bytes for a byte-order mark, a little leading whitespace, and the armor
    /// header line itself.
    private static let armorProbeByteCount = 64

    /// Whether the file's payload is base64 rather than binary, which decides how much
    /// plaintext its size implies. Reads only the head — the answer has to be cheap for
    /// a multi-gigabyte input. Any armor kind counts: the question is the encoding, not
    /// the packet type. Anything unreadable or undecodable counts as binary, the
    /// arithmetic that demands more space.
    private static func hasArmorHeader(atPath path: String) -> Bool {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            return false
        }
        defer { try? handle.close() }

        guard let head = try? handle.read(upToCount: armorProbeByteCount),
              let text = String(data: head, encoding: .utf8) else {
            return false
        }

        var leading = text[...]
        if leading.hasPrefix("\u{FEFF}") {
            leading = leading.dropFirst()
        }
        return leading.drop(while: { $0.isWhitespace }).hasPrefix("-----BEGIN PGP")
    }
}
