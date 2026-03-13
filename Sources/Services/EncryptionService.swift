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

    init(
        engine: PgpEngine = PgpEngine(),
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) {
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
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
        encryptToSelf: Bool
    ) async throws -> Data {
        let plaintextData = Data(plaintext.utf8)
        return try await encrypt(
            plaintext: plaintextData,
            recipientFingerprints: recipientFingerprints,
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
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
        encryptToSelf: Bool
    ) async throws -> Data {
        // Validate file size (100 MB limit)
        let maxSize = 100 * 1024 * 1024
        guard fileData.count <= maxSize else {
            throw CypherAirError.fileTooLarge(sizeMB: fileData.count / (1024 * 1024))
        }

        return try await encrypt(
            plaintext: fileData,
            recipientFingerprints: recipientFingerprints,
            signWithFingerprint: signWithFingerprint,
            encryptToSelf: encryptToSelf,
            binary: true
        )
    }

    // MARK: - Private

    @concurrent
    private func encrypt(
        plaintext: Data,
        recipientFingerprints: [String],
        signWithFingerprint: String?,
        encryptToSelf: Bool,
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
            throw CypherAirError.noRecipientsSelected
        }

        // Get signing key if requested (requires SE unwrap → Face ID)
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            signingKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFp)
        }

        // Get encrypt-to-self key
        var selfKey: Data?
        if encryptToSelf, let defaultKey = keyManagement.defaultKey {
            selfKey = defaultKey.publicKeyData
        }

        defer {
            // Zeroize signing key (must mutate the original binding, not a copy)
            if signingKey != nil {
                signingKey!.resetBytes(in: 0..<signingKey!.count)
                signingKey = nil
            }
        }

        if binary {
            return try engine.encryptBinary(
                plaintext: plaintext,
                recipients: recipientKeys,
                signingKey: signingKey,
                encryptToSelf: selfKey
            )
        } else {
            return try engine.encrypt(
                plaintext: plaintext,
                recipients: recipientKeys,
                signingKey: signingKey,
                encryptToSelf: selfKey
            )
        }
    }
}
