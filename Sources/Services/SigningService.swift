import Foundation

/// Handles cleartext text signatures, detached file signatures, and verification.
@Observable
final class SigningService {

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

    // MARK: - Signing

    /// Create a cleartext signature for text.
    /// Triggers device authentication via SE unwrap.
    ///
    /// - Parameters:
    ///   - text: The text to sign.
    ///   - signerFingerprint: Fingerprint of the signing key.
    /// - Returns: The cleartext-signed message data.
    @concurrent
    func signCleartext(_ text: String, signerFingerprint: String) async throws -> Data {
        var secretKey: Data
        do {
            secretKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        do {
            return try engine.signCleartext(
                text: Data(text.utf8),
                signerCert: secretKey
            )
        } catch {
            throw CypherAirError.from(error) { .signingFailed(reason: $0) }
        }
    }

    /// Create a detached signature for file data.
    /// Triggers device authentication via SE unwrap.
    ///
    /// - Parameters:
    ///   - data: The file data to sign.
    ///   - signerFingerprint: Fingerprint of the signing key.
    /// - Returns: The detached signature data (.sig).
    @concurrent
    func signDetached(_ data: Data, signerFingerprint: String) async throws -> Data {
        var secretKey: Data
        do {
            secretKey = try keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            secretKey.resetBytes(in: 0..<secretKey.count)
        }

        do {
            return try engine.signDetached(
                data: data,
                signerCert: secretKey
            )
        } catch {
            throw CypherAirError.from(error) { .signingFailed(reason: $0) }
        }
    }

    // MARK: - Verification

    /// Verify a cleartext-signed message.
    ///
    /// - Parameter signedMessage: The cleartext-signed message data.
    /// - Returns: Verification result with signer info and the original text.
    @concurrent
    func verifyCleartext(_ signedMessage: Data) async throws -> (text: Data?, verification: SignatureVerification) {
        let verificationKeys = allVerificationKeys()

        let result: VerifyResult
        do {
            result = try engine.verifyCleartext(
                signedMessage: signedMessage,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { _ in .badSignature }
        }

        let sigVerification = SignatureVerification(
            status: result.status,
            signerFingerprint: result.signerFingerprint,
            signerContact: result.signerFingerprint.flatMap {
                contactService.contact(forFingerprint: $0)
            }
        )

        return (text: result.content, verification: sigVerification)
    }

    /// Verify a detached signature against the original data.
    ///
    /// - Parameters:
    ///   - data: The original data.
    ///   - signature: The detached signature data.
    /// - Returns: Verification result with signer info.
    @concurrent
    func verifyDetached(data: Data, signature: Data) async throws -> SignatureVerification {
        let verificationKeys = allVerificationKeys()

        let result: VerifyResult
        do {
            result = try engine.verifyDetached(
                data: data,
                signature: signature,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { _ in .badSignature }
        }

        return SignatureVerification(
            status: result.status,
            signerFingerprint: result.signerFingerprint,
            signerContact: result.signerFingerprint.flatMap {
                contactService.contact(forFingerprint: $0)
            }
        )
    }

    // MARK: - Private

    /// Collect all public keys for signature verification
    /// (contacts + own keys).
    private func allVerificationKeys() -> [Data] {
        contactService.contacts.map { $0.publicKeyData }
            + keyManagement.keys.map { $0.publicKeyData }
    }
}
