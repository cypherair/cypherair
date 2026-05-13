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

    private let engine: PgpEngine
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let temporaryArtifactStore: AppTemporaryArtifactStore

    init(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        temporaryArtifactStore: AppTemporaryArtifactStore = AppTemporaryArtifactStore()
    ) {
        self.engine = engine
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
        // Dearmor if needed
        let binaryData: Data
        do {
            if let firstChar = ciphertext.first, firstChar == 0x2D { // '-' = ASCII armor
                binaryData = try engine.dearmor(armored: ciphertext)
            } else {
                binaryData = ciphertext
            }
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        // Match PKESK recipients against local certificates.
        // Uses Rust-side Sequoia key_handles() for correct subkey-to-cert matching,
        // returning primary fingerprints of matched certificates.
        let localCerts = keyManagement.keys.map { $0.publicKeyData }
        let matchedFingerprints: [String]
        do {
            matchedFingerprints = try engine.matchRecipients(
                ciphertext: binaryData,
                localCerts: localCerts
            )
        } catch let error as PgpError {
            switch error {
            case .CorruptData(let reason):
                throw CypherAirError.corruptData(reason: reason)
            case .UnsupportedAlgorithm(let algo):
                throw CypherAirError.unsupportedAlgorithm(algo: algo)
            default:
                throw CypherAirError.noMatchingKey
            }
        } catch {
            throw CypherAirError.noMatchingKey
        }

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

        let matchedFingerprints: [String]
        do {
            matchedFingerprints = try engine.matchRecipientsFromFile(
                inputPath: inputPath,
                localCerts: localCerts
            )
        } catch let error as PgpError {
            switch error {
            case .CorruptData(let reason):
                throw CypherAirError.corruptData(reason: reason)
            case .UnsupportedAlgorithm(let algo):
                throw CypherAirError.unsupportedAlgorithm(algo: algo)
            default:
                throw CypherAirError.noMatchingKey
            }
        } catch {
            throw CypherAirError.noMatchingKey
        }

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

        let result: DecryptDetailedResult
        do {
            result = try await Self.performDecryptDetailed(
                engine: engine,
                ciphertext: phase1.ciphertext,
                secretKeys: [secretKey],
                verificationKeys: context.verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return (
            plaintext: result.plaintext,
            verification: DetailedSignatureVerification.from(
                legacyStatus: result.legacyStatus,
                legacySignerFingerprint: result.legacySignerFingerprint,
                summaryState: result.summaryState,
                summaryEntryIndex: result.summaryEntryIndex,
                signatures: result.signatures,
                contacts: context.contacts,
                ownKeys: keyManagement.keys,
                contactsAvailability: context.contactsAvailability
            )
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

        let fileResult: FileDecryptDetailedResult
        do {
            fileResult = try await Self.performDecryptFileDetailed(
                engine: engine,
                inputPath: phase1.inputPath,
                outputPath: outputArtifact.fileURL.path,
                secretKeys: [secretKey],
                verificationKeys: context.verificationKeys,
                progress: progress
            )
            try temporaryArtifactStore.applyAndVerifyCompleteProtection(to: outputArtifact.fileURL)
        } catch {
            outputArtifact.cleanup()
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return (
            artifact: outputArtifact,
            verification: DetailedSignatureVerification.from(
                legacyStatus: fileResult.legacyStatus,
                legacySignerFingerprint: fileResult.legacySignerFingerprint,
                summaryState: fileResult.summaryState,
                summaryEntryIndex: fileResult.summaryEntryIndex,
                signatures: fileResult.signatures,
                contacts: context.contacts,
                ownKeys: keyManagement.keys,
                contactsAvailability: context.contactsAvailability
            )
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

    private struct VerificationContext {
        let verificationKeys: [Data]
        let contacts: [Contact]
        let contactsAvailability: ContactsAvailability
    }

    private func verificationContext() -> VerificationContext {
        let contactsContext = contactService.contactsForVerificationContext()
        let contactsAvailability = contactsContext.availability
        let contacts = contactsContext.contacts
        return VerificationContext(
            verificationKeys: contacts.map { $0.publicKeyData }
                + keyManagement.keys.map { $0.publicKeyData },
            contacts: contacts,
            contactsAvailability: contactsAvailability
        )
    }

    // MARK: - Off-Main-Actor Engine Helpers

    /// Run detailed decryption off the main actor.
    @concurrent
    private static func performDecryptDetailed(
        engine: PgpEngine,
        ciphertext: Data,
        secretKeys: [Data],
        verificationKeys: [Data]
    ) async throws -> DecryptDetailedResult {
        try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys
        )
    }

    /// Run streaming file detailed decryption off the main actor.
    @concurrent
    private static func performDecryptFileDetailed(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        secretKeys: [Data],
        verificationKeys: [Data],
        progress: FileProgressReporter?
    ) async throws -> FileDecryptDetailedResult {
        try engine.decryptFileDetailed(
            inputPath: inputPath,
            outputPath: outputPath,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }
}
