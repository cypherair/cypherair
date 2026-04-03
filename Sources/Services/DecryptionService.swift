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

    init(
        engine: PgpEngine,
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) {
        self.engine = engine
        self.keyManagement = keyManagement
        self.contactService = contactService
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

    /// Decrypt a message using the matched key from Phase 1.
    /// This phase triggers device authentication (Face ID / Touch ID) via SE unwrap.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    ///
    /// - Parameter phase1: The result from parseRecipients().
    /// - Returns: Decrypted plaintext and signature verification result.
    func decrypt(phase1: Phase1Result) async throws -> (plaintext: Data, signature: SignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        // SE unwrap triggers Face ID / Touch ID
        var secretKey: Data
        do {
            secretKey = try keyManagement.unwrapPrivateKey(fingerprint: matchedKey.fingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            // Note: passing secretKey into [secretKey] below may trigger a CoW copy.
            // This defer zeros this variable's buffer; the array's copy is freed
            // (but not zeroed) when the engine call returns. This is an inherent
            // limitation of Swift value semantics. See EncryptionService for the
            // detailed mitigation analysis.
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        // Gather verification keys (all contacts + own public keys)
        let verificationKeys = contactService.contacts.map { $0.publicKeyData }
            + keyManagement.keys.map { $0.publicKeyData }

        // Decrypt via Rust engine — off main thread
        let result: DecryptResult
        do {
            result = try await Self.performDecrypt(
                engine: engine,
                ciphertext: phase1.ciphertext,
                secretKeys: [secretKey],
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        // Build signature verification result
        let signerContact = result.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: result.signerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )
        let sigVerification = SignatureVerification(
            status: result.signatureStatus ?? .notSigned,
            signerFingerprint: result.signerFingerprint,
            signerContact: signerContact,
            signerIdentity: signerIdentity
        )

        return (plaintext: result.plaintext, signature: sigVerification)
    }

    // MARK: - Phase 2: Streaming File Decrypt (Authentication Required)

    /// Decrypt a file using streaming I/O (constant memory).
    /// This phase triggers device authentication (Face ID / Touch ID) via SE unwrap.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    ///
    /// - Parameters:
    ///   - phase1: The result from parseRecipientsFromFile().
    ///   - progress: Progress reporter for UI updates and cancellation.
    /// - Returns: URL of the decrypted output file and signature verification result.
    func decryptFileStreaming(
        phase1: FilePhase1Result,
        progress: FileProgressReporter?
    ) async throws -> (outputURL: URL, signature: SignatureVerification) {
        guard let matchedKey = phase1.matchedKey else {
            throw CypherAirError.noMatchingKey
        }

        // SE unwrap triggers Face ID / Touch ID
        var secretKey: Data
        do {
            secretKey = try keyManagement.unwrapPrivateKey(fingerprint: matchedKey.fingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        // Gather verification keys (all contacts + own public keys)
        let verificationKeys = contactService.contacts.map { $0.publicKeyData }
            + keyManagement.keys.map { $0.publicKeyData }

        // Prepare output path in tmp/decrypted/
        let decryptedDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("decrypted", isDirectory: true)
        try FileManager.default.createDirectory(at: decryptedDir, withIntermediateDirectories: true)

        // Strip .gpg/.pgp/.asc extension for output filename
        let inputFilename = (phase1.inputPath as NSString).lastPathComponent
        let outputFilename: String
        let ext = (inputFilename as NSString).pathExtension.lowercased()
        if ["gpg", "pgp", "asc"].contains(ext) {
            outputFilename = (inputFilename as NSString).deletingPathExtension
        } else {
            outputFilename = inputFilename + ".decrypted"
        }
        let outputURL = decryptedDir.appendingPathComponent(outputFilename)

        // Decrypt via Rust engine (streaming) — off main thread
        let fileResult: FileDecryptResult
        do {
            fileResult = try await Self.performDecryptFile(
                engine: engine,
                inputPath: phase1.inputPath,
                outputPath: outputURL.path,
                secretKeys: [secretKey],
                verificationKeys: verificationKeys,
                progress: progress
            )
        } catch {
            // Clean up partial output on failure
            try? FileManager.default.removeItem(at: outputURL)
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        // Build signature verification result
        let signerContact = fileResult.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: fileResult.signerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )
        let sigVerification = SignatureVerification(
            status: fileResult.signatureStatus ?? .notSigned,
            signerFingerprint: fileResult.signerFingerprint,
            signerContact: signerContact,
            signerIdentity: signerIdentity
        )

        return (outputURL: outputURL, signature: sigVerification)
    }

    // MARK: - Convenience: Full Decrypt

    /// Perform both Phase 1 and Phase 2 in sequence.
    /// Phase 2 is only reached if Phase 1 finds a matching key.
    func decryptMessage(ciphertext: Data) async throws -> (plaintext: Data, signature: SignatureVerification) {
        let phase1 = try await parseRecipients(ciphertext: ciphertext)
        return try await decrypt(phase1: phase1)
    }

    // MARK: - Off-Main-Actor Engine Helpers

    /// Run decryption off the main actor.
    @concurrent
    private static func performDecrypt(
        engine: PgpEngine,
        ciphertext: Data,
        secretKeys: [Data],
        verificationKeys: [Data]
    ) async throws -> DecryptResult {
        try engine.decrypt(
            ciphertext: ciphertext,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys
        )
    }

    /// Run streaming file decryption off the main actor.
    @concurrent
    private static func performDecryptFile(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        secretKeys: [Data],
        verificationKeys: [Data],
        progress: FileProgressReporter?
    ) async throws -> FileDecryptResult {
        try engine.decryptFile(
            inputPath: inputPath,
            outputPath: outputPath,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }
}
