import Foundation

/// Two-phase decryption service.
///
/// SECURITY-CRITICAL: The Phase 1 / Phase 2 boundary must never be bypassed.
/// Phase 1 (parseRecipients) runs WITHOUT authentication — it only determines
/// which key is needed. Phase 2 (decrypt) triggers device authentication via
/// SE unwrap before accessing the private key.
///
/// Changes to this file require human review. See SECURITY.md Section 7.
@Observable
final class DecryptionService {

    /// Result of Phase 1 analysis.
    struct Phase1Result {
        /// Recipient key IDs found in the ciphertext header.
        let recipientKeyIds: [String]
        /// Matched local key identity, if any.
        let matchedKey: PGPKeyIdentity?
        /// The ciphertext data (passed through for Phase 2).
        let ciphertext: Data
    }

    /// Result of Phase 1 analysis for file-based decryption.
    /// Unlike Phase1Result, this stores the file path instead of ciphertext Data.
    struct FilePhase1Result {
        /// Recipient key IDs found in the ciphertext header.
        let recipientKeyIds: [String]
        /// Matched local key identity, if any.
        let matchedKey: PGPKeyIdentity?
        /// Path to the encrypted input file (passed through for Phase 2).
        let inputPath: String
    }

    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()
    ) {
        self.messageAdapter = messageAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.temporaryArtifactStore = temporaryArtifactStore
    }

    // MARK: - Phase 1: Parse Recipients (No Authentication)

    /// Parse the ciphertext header and match against local keys.
    /// This phase does NOT require authentication — no private key is accessed.
    ///
    /// - Parameter ciphertext: The encrypted message (armored or binary).
    /// - Returns: Phase1Result with matched key info.
    /// - Throws: CypherAirError.noMatchingKey if no local key matches.
    func parseRecipients(ciphertext: Data) async throws -> Phase1Result {
        let binaryData = try await messageAdapter.dearmorIfNeeded(ciphertext)

        // Match PKESK recipients against local certificates.
        // Uses Rust-side Sequoia key_handles() for correct subkey-to-cert matching,
        // returning primary fingerprints of matched certificates.
        let localCerts = keyManagement.keys.map { $0.publicKeyData }
        let matchedFingerprints = try await messageAdapter.matchRecipients(
            ciphertext: binaryData,
            localCerts: localCerts
        )

        // Look up the matched key identity by primary fingerprint
        let matchedKey = keyManagement.keys.first { identity in
            matchedFingerprints.contains(identity.fingerprint)
        }

        guard matchedKey != nil else {
            throw CypherAirError.noMatchingKey
        }

        return Phase1Result(
            recipientKeyIds: matchedFingerprints,
            matchedKey: matchedKey,
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
    /// - Returns: FilePhase1Result with matched key info.
    /// - Throws: CypherAirError.noMatchingKey if no local key matches.
    func parseRecipientsFromFile(fileURL: URL) async throws -> FilePhase1Result {
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

        return FilePhase1Result(
            recipientKeyIds: matchedFingerprints,
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
        phase1: Phase1Result
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        var secretKey: Data
        do {
            secretKey = try await keyManagement.unwrapPrivateKey(fingerprint: matchedKey.fingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let context = verificationContext()

        return try await messageAdapter.decryptDetailed(
            ciphertext: phase1.ciphertext,
            secretKeys: [secretKey],
            verificationContext: context
        )
    }

    // MARK: - Phase 2: Streaming File Decrypt (Authentication Required)

    /// Decrypt a file using streaming I/O while preserving per-signature detailed
    /// verification results.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    func decryptFileStreamingDetailed(
        phase1: FilePhase1Result,
        progress: FileProgressReporter?
    ) async throws -> (artifact: AppTemporaryArtifact, verification: DetailedSignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        var secretKey: Data
        do {
            secretKey = try await keyManagement.unwrapPrivateKey(fingerprint: matchedKey.fingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        let context = verificationContext()

        let inputFilename = (phase1.inputPath as NSString).lastPathComponent
        let outputArtifact = try temporaryArtifactStore.makeDecryptedArtifact(for: inputFilename)

        let verification: DetailedSignatureVerification
        do {
            verification = try await messageAdapter.decryptFileDetailed(
                inputPath: phase1.inputPath,
                outputPath: outputArtifact.fileURL.path,
                secretKeys: [secretKey],
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

    // MARK: - Convenience: Full Decrypt

    /// Perform both Phase 1 and Phase 2 in sequence while preserving
    /// per-signature detailed verification results.
    func decryptMessageDetailed(
        ciphertext: Data
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        let phase1 = try await parseRecipients(ciphertext: ciphertext)
        return try await decryptDetailed(phase1: phase1)
    }

    // MARK: - Private

    private func verificationContext() -> PGPMessageVerificationContext {
        let contactsContext = contactService.contactsForVerificationContext()
        let contactsAvailability = contactsContext.availability
        let contacts = contactsContext.contacts
        let ownKeys = keyManagement.keys
        return PGPMessageVerificationContext(
            verificationKeys: contacts.map { $0.publicKeyData }
                + ownKeys.map { $0.publicKeyData },
            contacts: contacts,
            ownKeys: ownKeys,
            contactsAvailability: contactsAvailability
        )
    }
}
