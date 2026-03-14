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

    // MARK: - Phase 1: Parse Recipients (No Authentication)

    /// Parse the ciphertext header and match against local keys.
    /// This phase does NOT require authentication — no private key is accessed.
    ///
    /// - Parameter ciphertext: The encrypted message (armored or binary).
    /// - Returns: Phase1Result with matched key info.
    /// - Throws: CypherAirError.noMatchingKey if no local key matches.
    @concurrent
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

    // MARK: - Phase 2: Decrypt (Authentication Required)

    /// Decrypt a message using the matched key from Phase 1.
    /// This phase triggers device authentication (Face ID / Touch ID) via SE unwrap.
    ///
    /// SECURITY: This method must only be called after Phase 1 has identified the key.
    /// The private key exists in memory only during the decrypt call and is zeroized immediately after.
    ///
    /// - Parameter phase1: The result from parseRecipients().
    /// - Returns: Decrypted plaintext and signature verification result.
    @concurrent
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

        // Decrypt via Rust engine
        let result: DecryptResult
        do {
            result = try engine.decrypt(
                ciphertext: phase1.ciphertext,
                secretKeys: [secretKey],
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        // Build signature verification result
        let sigVerification = SignatureVerification(
            status: result.signatureStatus ?? .notSigned,
            signerFingerprint: result.signerFingerprint,
            signerContact: result.signerFingerprint.flatMap {
                contactService.contact(forFingerprint: $0)
            }
        )

        return (plaintext: result.plaintext, signature: sigVerification)
    }

    // MARK: - Convenience: Full Decrypt

    /// Perform both Phase 1 and Phase 2 in sequence.
    /// Phase 2 is only reached if Phase 1 finds a matching key.
    @concurrent
    func decryptMessage(ciphertext: Data) async throws -> (plaintext: Data, signature: SignatureVerification) {
        let phase1 = try await parseRecipients(ciphertext: ciphertext)
        return try await decrypt(phase1: phase1)
    }
}
