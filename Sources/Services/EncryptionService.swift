import Foundation

/// Orchestrates text and file encryption with recipient selection,
/// encrypt-to-self, and optional signing.
///
/// Message format is auto-selected by recipient key versions (handled by Rust engine):
/// - All v4 → SEIPDv1 (MDC)
/// - All v6 → SEIPDv2 (AEAD OCB)
/// - Mixed → SEIPDv1
@Observable
final class EncryptionService {

    private let engine: PgpEngine
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let diskSpaceChecker: DiskSpaceChecker

    init(
        engine: PgpEngine = PgpEngine(),
        keyManagement: KeyManagementService,
        contactService: ContactService,
        diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker()
    ) {
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.diskSpaceChecker = diskSpaceChecker
    }

    // MARK: - Text Encryption

    /// Encrypt text for the specified recipients.
    /// Returns ASCII-armored ciphertext.
    ///
    /// - Parameters:
    ///   - plaintext: The text to encrypt.
    ///   - recipientFingerprints: Fingerprints of recipients to encrypt to.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    /// - Returns: ASCII-armored ciphertext data.
    @concurrent
    func encryptText(
        _ plaintext: String,
        recipientFingerprints: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        let plaintextData = Data(plaintext.utf8)
        return try await encrypt(
            plaintext: plaintextData,
            recipientFingerprints: recipientFingerprints,
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint,
            binary: false
        )
    }

    // MARK: - File Encryption

    /// Encrypt file data for the specified recipients.
    /// Returns binary .gpg ciphertext.
    ///
    /// File size is validated against the 100 MB limit.
    ///
    /// - Parameters:
    ///   - fileData: The file content to encrypt.
    ///   - recipientFingerprints: Fingerprints of recipients.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    /// - Returns: Binary ciphertext data (.gpg format).
    @concurrent
    func encryptFile(
        _ fileData: Data,
        recipientFingerprints: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        // Validate file size (100 MB limit)
        let maxSize = 100 * 1024 * 1024
        guard fileData.count <= maxSize else {
            throw CypherAirError.fileTooLarge(sizeMB: (fileData.count + 1024 * 1024 - 1) / (1024 * 1024))
        }

        return try await encrypt(
            plaintext: fileData,
            recipientFingerprints: recipientFingerprints,
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint,
            binary: true
        )
    }

    // MARK: - Streaming File Encryption

    /// Encrypt a file using streaming I/O (constant memory).
    /// The input file is read from `inputURL`, and the encrypted output is
    /// written to a temp file in `tmp/streaming/`.
    ///
    /// - Parameters:
    ///   - inputURL: URL of the plaintext file.
    ///   - recipientFingerprints: Fingerprints of recipients to encrypt to.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    ///   - progress: Progress reporter for UI updates and cancellation.
    /// - Returns: URL of the encrypted output file (.gpg).
    @concurrent
    func encryptFileStreaming(
        inputURL: URL,
        recipientFingerprints: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        progress: FileProgressReporter?
    ) async throws -> URL {
        guard !recipientFingerprints.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        // Get file size for disk space check
        let inputPath = inputURL.path
        let attrs = try FileManager.default.attributesOfItem(atPath: inputPath)
        let fileSize = attrs[.size] as? UInt64 ?? 0

        // Validate disk space before starting
        try diskSpaceChecker.validateForEncryption(inputFileSize: fileSize)

        // Gather recipient public keys
        let recipientKeys = recipientFingerprints.compactMap { fp in
            contactService.contact(forFingerprint: fp)?.publicKeyData
        }

        guard recipientKeys.count == recipientFingerprints.count else {
            throw CypherAirError.invalidKeyData(
                reason: String(localized: "error.recipientNotFound",
                               defaultValue: "One or more recipients could not be found in contacts.")
            )
        }

        // Get signing key if requested (requires SE unwrap → Face ID)
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            do {
                signingKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFp)
            } catch {
                throw CypherAirError.from(error) { _ in .authenticationFailed }
            }
        }

        // Get encrypt-to-self key
        var selfKey: Data?
        if encryptToSelf {
            if let fp = encryptToSelfFingerprint,
               let key = keyManagement.keys.first(where: { $0.fingerprint == fp }) {
                selfKey = key.publicKeyData
            } else if let defaultKey = keyManagement.defaultKey {
                selfKey = defaultKey.publicKeyData
            } else {
                throw CypherAirError.noKeySelected
            }
        }

        defer {
            // Safety-net zeroing.
            if signingKey != nil {
                signingKey!.resetBytes(in: 0..<signingKey!.count)
                signingKey = nil
            }
        }

        // Prepare output path in tmp/streaming/
        let streamingDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming", isDirectory: true)
        try FileManager.default.createDirectory(at: streamingDir, withIntermediateDirectories: true)
        let outputFilename = inputURL.lastPathComponent + ".gpg"
        let outputURL = streamingDir.appendingPathComponent(outputFilename)

        do {
            try engine.encryptFile(
                inputPath: inputPath,
                outputPath: outputURL.path,
                recipients: recipientKeys,
                signingKey: signingKey,
                encryptToSelf: selfKey,
                progress: progress
            )
        } catch {
            // Clean up partial output on failure
            try? FileManager.default.removeItem(at: outputURL)
            throw CypherAirError.from(error) { .encryptionFailed(reason: $0) }
        }

        // Primary zeroing: immediately after engine call returns
        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }

        return outputURL
    }

    // MARK: - Private

    @concurrent
    private func encrypt(
        plaintext: Data,
        recipientFingerprints: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        binary: Bool
    ) async throws -> Data {
        guard !recipientFingerprints.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        // Gather recipient public keys
        let recipientKeys = recipientFingerprints.compactMap { fp in
            contactService.contact(forFingerprint: fp)?.publicKeyData
        }

        guard recipientKeys.count == recipientFingerprints.count else {
            throw CypherAirError.invalidKeyData(
                reason: String(localized: "error.recipientNotFound",
                               defaultValue: "One or more recipients could not be found in contacts.")
            )
        }

        // Get signing key if requested (requires SE unwrap → Face ID)
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            do {
                signingKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFp)
            } catch {
                throw CypherAirError.from(error) { _ in .authenticationFailed }
            }
        }

        // Get encrypt-to-self key
        var selfKey: Data?
        if encryptToSelf {
            if let fp = encryptToSelfFingerprint,
               let key = keyManagement.keys.first(where: { $0.fingerprint == fp }) {
                selfKey = key.publicKeyData
            } else if let defaultKey = keyManagement.defaultKey {
                selfKey = defaultKey.publicKeyData
            } else {
                throw CypherAirError.noKeySelected
            }
        }

        defer {
            // Safety-net zeroing. Primary zeroing happens inline below.
            if signingKey != nil {
                signingKey!.resetBytes(in: 0..<signingKey!.count)
                signingKey = nil
            }
        }

        let result: Data
        do {
            if binary {
                result = try engine.encryptBinary(
                    plaintext: plaintext,
                    recipients: recipientKeys,
                    signingKey: signingKey,
                    encryptToSelf: selfKey
                )
            } else {
                result = try engine.encrypt(
                    plaintext: plaintext,
                    recipients: recipientKeys,
                    signingKey: signingKey,
                    encryptToSelf: selfKey
                )
            }
        } catch {
            throw CypherAirError.from(error) { .encryptionFailed(reason: $0) }
        }

        // Primary zeroing: immediately after engine call returns, signingKey is most
        // likely uniquely referenced (UniFFI lower() temporaries released). This
        // maximizes the chance that resetBytes mutates the original buffer under COW.
        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }

        return result
    }
}
