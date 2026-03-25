import Foundation

/// Handles cleartext text signatures, detached file signatures, and verification.
@Observable
final class SigningService {

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

    // MARK: - Signing

    /// Create a cleartext signature for text.
    /// Triggers device authentication via SE unwrap.
    ///
    /// - Parameters:
    ///   - text: The text to sign.
    ///   - signerFingerprint: Fingerprint of the signing key.
    /// - Returns: The cleartext-signed message data.
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
            return try await Self.performSignCleartext(
                engine: engine, text: Data(text.utf8), signerCert: secretKey
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
            return try await Self.performSignDetached(
                engine: engine, data: data, signerCert: secretKey
            )
        } catch {
            throw CypherAirError.from(error) { .signingFailed(reason: $0) }
        }
    }

    // MARK: - Streaming File Signing

    /// Create a detached signature for a file using streaming I/O.
    /// Triggers device authentication via SE unwrap.
    ///
    /// - Parameters:
    ///   - fileURL: URL of the file to sign.
    ///   - signerFingerprint: Fingerprint of the signing key.
    ///   - progress: Progress reporter for UI updates and cancellation.
    /// - Returns: The detached signature data (.sig, ASCII-armored).
    func signDetachedStreaming(
        fileURL: URL,
        signerFingerprint: String,
        progress: FileProgressReporter?
    ) async throws -> Data {
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
            return try await Self.performSignDetachedFile(
                engine: engine, inputPath: fileURL.path,
                signerCert: secretKey, progress: progress
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
    func verifyCleartext(_ signedMessage: Data) async throws -> (text: Data?, verification: SignatureVerification) {
        let verificationKeys = allVerificationKeys()

        let result: VerifyResult
        do {
            result = try await Self.performVerifyCleartext(
                engine: engine, signedMessage: signedMessage,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
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
    func verifyDetached(data: Data, signature: Data) async throws -> SignatureVerification {
        let verificationKeys = allVerificationKeys()

        let result: VerifyResult
        do {
            result = try await Self.performVerifyDetached(
                engine: engine, data: data, signature: signature,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return SignatureVerification(
            status: result.status,
            signerFingerprint: result.signerFingerprint,
            signerContact: result.signerFingerprint.flatMap {
                contactService.contact(forFingerprint: $0)
            }
        )
    }

    // MARK: - Streaming File Verification

    /// Verify a detached signature against a file using streaming I/O.
    ///
    /// - Parameters:
    ///   - fileURL: URL of the data file.
    ///   - signature: The detached signature data.
    ///   - progress: Progress reporter for UI updates and cancellation.
    /// - Returns: Verification result with signer info.
    func verifyDetachedStreaming(
        fileURL: URL,
        signature: Data,
        progress: FileProgressReporter?
    ) async throws -> SignatureVerification {
        let verificationKeys = allVerificationKeys()

        let result: VerifyResult
        do {
            result = try await Self.performVerifyDetachedFile(
                engine: engine, dataPath: fileURL.path,
                signature: signature, verificationKeys: verificationKeys,
                progress: progress
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
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

    // MARK: - Off-Main-Actor Engine Helpers

    @concurrent
    private static func performSignCleartext(
        engine: PgpEngine, text: Data, signerCert: Data
    ) async throws -> Data {
        try engine.signCleartext(text: text, signerCert: signerCert)
    }

    @concurrent
    private static func performSignDetached(
        engine: PgpEngine, data: Data, signerCert: Data
    ) async throws -> Data {
        try engine.signDetached(data: data, signerCert: signerCert)
    }

    @concurrent
    private static func performSignDetachedFile(
        engine: PgpEngine, inputPath: String,
        signerCert: Data, progress: FileProgressReporter?
    ) async throws -> Data {
        try engine.signDetachedFile(
            inputPath: inputPath, signerCert: signerCert, progress: progress
        )
    }

    @concurrent
    private static func performVerifyCleartext(
        engine: PgpEngine, signedMessage: Data, verificationKeys: [Data]
    ) async throws -> VerifyResult {
        try engine.verifyCleartext(
            signedMessage: signedMessage, verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performVerifyDetached(
        engine: PgpEngine, data: Data, signature: Data, verificationKeys: [Data]
    ) async throws -> VerifyResult {
        try engine.verifyDetached(
            data: data, signature: signature, verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performVerifyDetachedFile(
        engine: PgpEngine, dataPath: String, signature: Data,
        verificationKeys: [Data], progress: FileProgressReporter?
    ) async throws -> VerifyResult {
        try engine.verifyDetachedFile(
            dataPath: dataPath, signature: signature,
            verificationKeys: verificationKeys, progress: progress
        )
    }
}
