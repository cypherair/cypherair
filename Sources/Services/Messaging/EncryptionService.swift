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

    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let textEncryptor: any TextMessageEncrypting
    private let fileEncryptor: any StreamingFileEncrypting
    private let diskSpaceChecker: DiskSpaceChecker
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        keyManagement: KeyManagementService,
        contactService: ContactService,
        textEncryptor: any TextMessageEncrypting,
        fileEncryptor: any StreamingFileEncrypting,
        diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker(),
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()
    ) {
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.textEncryptor = textEncryptor
        self.fileEncryptor = fileEncryptor
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
            encryptToSelfFingerprint: encryptToSelfFingerprint
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
        let inputPath = inputURL.path

        // Refuse an encrypt the volume cannot hold before it costs the user
        // anything: ahead of the output artifact, and ahead of any signing or
        // encrypt-to-self key step below.
        try diskSpaceChecker.validateForEncryption(inputPath: inputPath)

        let selfKey = try resolvedEncryptToSelfKey(
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint
        )

        let outputArtifact = try temporaryArtifactStore.makeStreamingArtifact(for: inputURL)

        do {
            try await fileEncryptor.encryptFile(
                inputPath: inputPath,
                outputPath: outputArtifact.fileURL.path,
                recipientKeys: recipientKeys,
                signerFingerprint: signWithFingerprint,
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

        return outputArtifact
    }

    // MARK: - Private

    private func encrypt(
        plaintext: Data,
        recipientContactIds: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        guard !recipientContactIds.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        return try await encrypt(
            plaintext: plaintext,
            recipientKeys: try contactService.publicKeysForRecipientContactIDs(recipientContactIds),
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint
        )
    }

    private func encrypt(
        plaintext: Data,
        recipientKeys: [Data],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String? = nil
    ) async throws -> Data {
        guard !recipientKeys.isEmpty else {
            throw CypherAirError.noRecipientsSelected
        }

        let selfKey = try resolvedEncryptToSelfKey(
            encryptToSelf: encryptToSelf,
            encryptToSelfFingerprint: encryptToSelfFingerprint
        )

        return try await textEncryptor.encryptText(
            plaintext,
            recipientKeys: recipientKeys,
            signerFingerprint: signWithFingerprint,
            selfKey: selfKey
        )
    }

    private func resolvedEncryptToSelfKey(
        encryptToSelf: Bool,
        encryptToSelfFingerprint: String?
    ) throws -> Data? {
        guard encryptToSelf else {
            return nil
        }

        return try keyManagement.encryptToSelfIdentity(
            fingerprint: encryptToSelfFingerprint
        ).publicKeyData
    }
}
