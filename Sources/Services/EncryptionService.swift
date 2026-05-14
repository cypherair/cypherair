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

    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let diskSpaceChecker: DiskSpaceChecker
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker(),
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()
    ) {
        self.messageAdapter = messageAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.diskSpaceChecker = diskSpaceChecker
        self.temporaryArtifactStore = temporaryArtifactStore
    }

    // MARK: - Text Encryption

    /// Encrypt text for the specified contact identities.
    /// Returns ASCII-armored ciphertext.
    ///
    /// - Parameters:
    ///   - plaintext: The text to encrypt.
    ///   - recipientContactIds: Contact identity identifiers to encrypt to.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    /// - Returns: ASCII-armored ciphertext data.
    func encryptText(
        _ plaintext: String,
        recipientContactIds: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        let plaintextData = Data(plaintext.utf8)
        return try await encrypt(
            plaintext: plaintextData,
            recipientContactIds: recipientContactIds,
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint,
            binary: false
        )
    }

    // MARK: - File Encryption

    /// Encrypt file data for the specified contact identities.
    /// Returns binary .gpg ciphertext.
    ///
    /// File size is validated against the 100 MB limit.
    ///
    /// - Parameters:
    ///   - fileData: The file content to encrypt.
    ///   - recipientContactIds: Contact identity identifiers to encrypt to.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    /// - Returns: Binary ciphertext data (.gpg format).
    func encryptFile(
        _ fileData: Data,
        recipientContactIds: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        let maxSize = 100 * 1024 * 1024
        guard fileData.count <= maxSize else {
            throw CypherAirError.fileTooLarge(sizeMB: (fileData.count + 1024 * 1024 - 1) / (1024 * 1024))
        }

        return try await encrypt(
            plaintext: fileData,
            recipientContactIds: recipientContactIds,
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
    ///   - recipientContactIds: Contact identity identifiers to encrypt to.
    ///   - signWithFingerprint: Fingerprint of the signing key (nil = don't sign).
    ///   - encryptToSelf: Whether to also encrypt to the sender's own key.
    ///   - progress: Progress reporter for UI updates and cancellation.
    /// - Returns: App-owned encrypted output artifact (.gpg).
    func encryptFileStreaming(
        inputURL: URL,
        recipientContactIds: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        progress: FileProgressReporter?
    ) async throws -> AppTemporaryArtifact {
        try await encryptFileStreaming(
            inputURL: inputURL,
            recipientKeys: try contactService.publicKeysForRecipientContactIDs(recipientContactIds),
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint,
            progress: progress
        )
    }

    private func encryptFileStreaming(
        inputURL: URL,
        recipientKeys: [Data],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        progress: FileProgressReporter?
    ) async throws -> AppTemporaryArtifact {
        guard !recipientKeys.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }
        // Get file size for disk space check
        let inputPath = inputURL.path
        let attrs = try FileManager.default.attributesOfItem(atPath: inputPath)
        let fileSize = attrs[.size] as? UInt64 ?? 0

        // Validate disk space before starting
        try diskSpaceChecker.validateForEncryption(inputFileSize: fileSize)

        // Get signing key if requested (requires SE unwrap → Face ID)
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            do {
                signingKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFp)
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

        let outputArtifact = try temporaryArtifactStore.makeStreamingArtifact(for: inputURL)

        do {
            try await messageAdapter.encryptFile(
                inputPath: inputPath,
                outputPath: outputArtifact.fileURL.path,
                recipientKeys: recipientKeys,
                signingKey: signingKey,
                selfKey: selfKey,
                progress: progress
            )
            try temporaryArtifactStore.applyAndVerifyCompleteProtection(to: outputArtifact.fileURL)
        } catch let error as CypherAirError {
            outputArtifact.cleanup()
            throw error
        } catch {
            outputArtifact.cleanup()
            throw CypherAirError.encryptionFailed(reason: error.localizedDescription)
        }

        // Primary zeroing: immediately after engine call returns
        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }

        return outputArtifact
    }

    // MARK: - Private

    private func encrypt(
        plaintext: Data,
        recipientContactIds: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        binary: Bool
    ) async throws -> Data {
        guard !recipientContactIds.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        return try await encrypt(
            plaintext: plaintext,
            recipientKeys: try contactService.publicKeysForRecipientContactIDs(recipientContactIds),
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint,
            binary: binary
        )
    }

    private func encrypt(
        plaintext: Data,
        recipientKeys: [Data],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil,
        binary: Bool
    ) async throws -> Data {
        guard !recipientKeys.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        // Get signing key if requested (requires SE unwrap → Face ID)
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            do {
                signingKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFp)
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

        let result = try await messageAdapter.encrypt(
            plaintext: plaintext,
            recipientKeys: recipientKeys,
            signingKey: signingKey,
            selfKey: selfKey,
            binary: binary
        )

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
