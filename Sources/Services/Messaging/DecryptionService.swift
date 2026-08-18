import Foundation

/// Two-phase decryption service.
///
/// SECURITY-CRITICAL: The Phase 1 / Phase 2 boundary must never be bypassed.
/// Phase 1 (inspectMessage) runs WITHOUT authentication — it only determines how
/// the message can be opened. Phase 2 triggers device authentication via SE
/// unwrap before accessing a private key, or takes a password and touches no key
/// at all.
@Observable
final class DecryptionService {
    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let messageDecryptor: any RecipientMessageDecrypting
    private let fileDecryptor: any StreamingFileDecrypting
    private let diskSpaceChecker: DiskSpaceChecker
    private let temporaryArtifactStore: AppTemporaryArtifactStore
    private let argon2idMemoryGuard: Argon2idMemoryGuard

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        messageDecryptor: any RecipientMessageDecrypting,
        fileDecryptor: any StreamingFileDecrypting,
        diskSpaceChecker: DiskSpaceChecker = DiskSpaceChecker(),
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore(),
        argon2idMemoryGuard: Argon2idMemoryGuard = Argon2idMemoryGuard()
    ) {
        self.messageAdapter = messageAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.messageDecryptor = messageDecryptor
        self.fileDecryptor = fileDecryptor
        self.diskSpaceChecker = diskSpaceChecker
        self.temporaryArtifactStore = temporaryArtifactStore
        self.argon2idMemoryGuard = argon2idMemoryGuard
    }

    // MARK: - Phase 1: Inspect the message (No Authentication)

    /// Read the message's session-key packets to learn how it can be opened:
    /// which local key it is addressed to, and whether a password would work.
    /// This phase does NOT require authentication — no private key is accessed,
    /// and no key derivation runs.
    ///
    /// - Parameter ciphertext: The encrypted message (armored or binary).
    /// - Throws: `CypherAirError.noMatchingKey` when the message offers this
    ///   device no way in at all.
    func inspectMessage(ciphertext: Data) async throws -> DecryptionPhase1Result {
        let binaryData = try await messageAdapter.dearmorIfNeeded(ciphertext)

        // Recipient matching runs Sequoia's key_handles() on the Rust side, so a
        // PKESK naming an encryption subkey resolves to its certificate's
        // primary fingerprint.
        let localCerts = keyManagement.keys.map { $0.publicKeyData }
        let inspection = try await messageAdapter.inspectMessageProtection(
            ciphertext: binaryData,
            localCerts: localCerts
        )

        let matchedKey = keyManagement.keys.first { identity in
            inspection.matchedFingerprints.contains(identity.fingerprint)
        }

        guard matchedKey != nil || inspection.acceptsPassword else {
            throw CypherAirError.noMatchingKey
        }

        return DecryptionPhase1Result(
            matchedKey: matchedKey,
            acceptsPassword: inspection.acceptsPassword,
            ciphertext: binaryData
        )
    }

    // MARK: - Phase 1: Parse Recipients from File (No Authentication)

    /// Parse recipient headers from an encrypted file WITHOUT loading it into memory.
    /// This phase does NOT require authentication — no private key is accessed.
    ///
    /// Uses `matchRecipientsFromFile` which reads only PKESK headers from the file,
    /// keeping memory usage constant regardless of file size.
    ///
    /// - Parameter fileURL: URL of the encrypted file.
    /// - Returns: FileDecryptionPhase1Result with matched key info.
    /// - Throws: CypherAirError.noMatchingKey if no local key matches.
    func parseRecipientsFromFile(fileURL: URL) async throws -> FileDecryptionPhase1Result {
        let inputPath = fileURL.path
        let localCerts = keyManagement.keys.map { $0.publicKeyData }

        let matchedFingerprints = try await messageAdapter.matchRecipientsFromFile(
            inputPath: inputPath,
            localCerts: localCerts
        )

        let matchedKey = keyManagement.keys.first { identity in
            matchedFingerprints.contains(identity.fingerprint)
        }

        guard matchedKey != nil else {
            throw CypherAirError.noMatchingKey
        }

        return FileDecryptionPhase1Result(
            matchedKey: matchedKey,
            inputPath: inputPath
        )
    }

    // MARK: - Phase 2: Decrypt (Authentication Required)

    /// Decrypt a message using the matched key from Phase 1 while preserving
    /// per-signature detailed verification results.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    func decryptDetailed(
        phase1: DecryptionPhase1Result
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        // Custody-specific private-key access is owned by the router-backed
        // message decryptor: software custody unwraps and zeroizes a secret
        // certificate; Secure Enclave custody uses the external P-256
        // key-agreement route. Payload authentication and success-only plaintext
        // release remain the Sequoia decrypt pipeline's responsibility.
        let context = verificationContext()

        return try await messageDecryptor.decryptDetailed(
            ciphertext: phase1.ciphertext,
            recipientFingerprint: matchedKey.fingerprint,
            verificationContext: context
        )
    }

    // MARK: - Phase 2: Decrypt with a password (No key, no authentication)

    /// Open a password-protected message. No private key is touched and no
    /// authentication prompt is raised — the password is the whole of the
    /// message's protection.
    ///
    /// The Argon2 parameters belong to whoever wrote the message, so the cost
    /// this device can afford is measured now and travels with the call; the
    /// engine refuses a slot beyond it before deriving anything
    /// (docs/SECURITY.md §7). Signatures are still reported: a password message
    /// can carry one, and the app grades it exactly as it grades any other.
    func decryptDetailedWithPassword(
        phase1: DecryptionPhase1Result,
        password: String
    ) async throws -> PasswordMessageDetailedDecryptOutcome {
        guard phase1.acceptsPassword else {
            throw CypherAirError.noMatchingKey
        }

        return try await messageAdapter.decryptWithPassword(
            ciphertext: phase1.ciphertext,
            password: password,
            affordableMemoryKib: argon2idMemoryGuard.affordableMemoryKib(),
            verificationContext: verificationContext()
        )
    }

    // MARK: - Phase 2: Streaming File Decrypt (Authentication Required)

    /// Decrypt a file using streaming I/O while preserving per-signature detailed
    /// verification results.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    func decryptFileStreamingDetailed(
        phase1: FileDecryptionPhase1Result,
        progress: FileProgressReporter?
    ) async throws -> (artifact: AppTemporaryArtifact, verification: DetailedSignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        // Refuse a decrypt the volume cannot hold before it costs the user anything:
        // ahead of the output artifact, and ahead of the private-key route below,
        // which prompts for authentication.
        try diskSpaceChecker.validateForDecryption(inputPath: phase1.inputPath)

        // Custody-specific private-key access is owned by the router-backed streaming
        // file decryptor: software custody unwraps and zeroizes a secret certificate;
        // Secure Enclave custody uses the external P-256 key-agreement route. This
        // service keeps ownership of the temporary output artifact, success-only file
        // protection, and cleanup. Payload authentication and the success-only
        // plaintext-to-output release remain the Sequoia/streaming pipeline's
        // responsibility.
        let context = verificationContext()

        let inputFilename = (phase1.inputPath as NSString).lastPathComponent
        let outputArtifact = try temporaryArtifactStore.makeDecryptedArtifact(for: inputFilename)

        let verification: DetailedSignatureVerification
        do {
            verification = try await fileDecryptor.decryptFile(
                inputPath: phase1.inputPath,
                outputPath: outputArtifact.fileURL.path,
                recipientFingerprint: matchedKey.fingerprint,
                verificationContext: context,
                progress: progress
            )
            try temporaryArtifactStore.applyAndVerifyCompleteProtection(to: outputArtifact.fileURL)
        } catch let error as CypherAirError {
            outputArtifact.cleanup()
            throw error
        } catch {
            outputArtifact.cleanup()
            throw CypherAirError.corruptData(reason: error.localizedDescription)
        }

        return (
            artifact: outputArtifact,
            verification: verification
        )
    }

    // MARK: - Private

    private func verificationContext() -> PGPMessageVerificationContext {
        let contactsContext = contactService.contactsVerificationContext()
        let ownKeys = keyManagement.keys
        return PGPMessageVerificationContext(
            verificationKeys: contactsContext.verificationKeys
                + ownKeys.map(\.publicKeyData),
            contactKeys: contactsContext.contactKeys,
            ownKeys: ownKeys,
            contactsAvailability: contactsContext.availability
        )
    }
}
