import Foundation

/// Orchestrates outgoing encryption: to recipient keys, with encrypt-to-self and
/// optional signing, or to a password alone.
///
/// The message format is never chosen here. For a key-encrypted message it is
/// the engine's answer — SEIPDv2 (AEAD OCB) when every recipient certificate
/// advertises that capability, SEIPDv1 (MDC) otherwise — and
/// `PGPMessageFormatAdapter` states that same answer before sending. A password
/// message has no certificate to advertise anything, so it takes the container
/// every OpenPGP tool can open (docs/PRODUCT.md §5).
@Observable
final class EncryptionService {

    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let messageAdapter: PGPMessageOperationAdapter
    private let textEncryptor: any TextMessageEncrypting
    private let fileEncryptor: any StreamingFileEncrypting
    private let diskSpaceChecker: DiskSpaceChecker
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        keyManagement: KeyManagementService,
        contactService: ContactService,
        messageAdapter: PGPMessageOperationAdapter,
        textEncryptor: any TextMessageEncrypting,
        fileEncryptor: any StreamingFileEncrypting,
        diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker(),
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()
    ) {
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.messageAdapter = messageAdapter
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

    // MARK: - Password Encryption

    /// Encrypt text under a password alone. Returns ASCII-armored ciphertext.
    ///
    /// None of the sender's keys are involved: the message is not signed, and no
    /// copy is made for the sender. Anyone holding the password can read it, so
    /// the strength of the password is the strength of the message — the screen
    /// refuses one that does not meet `PassphraseRequirements`.
    func encryptTextWithPassword(
        _ plaintext: String,
        password: String
    ) async throws -> Data {
        guard PassphraseRequirements(of: password).isSatisfied else {
            throw CypherAirError.encryptionFailed(
                reason: String(
                    localized: "encrypt.password.tooWeak",
                    defaultValue: "This password does not meet the requirements."
                )
            )
        }

        return try await messageAdapter.encryptWithPassword(
            plaintext: Data(plaintext.utf8),
            password: password
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
