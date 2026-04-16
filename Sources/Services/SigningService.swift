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

        let signerContact = result.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: result.signerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )
        let sigVerification = SignatureVerification(
            status: result.status,
            signerFingerprint: result.signerFingerprint,
            signerContact: signerContact,
            signerIdentity: signerIdentity
        )

        return (text: result.content, verification: sigVerification)
    }

    /// Verify a cleartext-signed message while preserving per-signature detailed results.
    ///
    /// - Parameter signedMessage: The cleartext-signed message data.
    /// - Returns: Original text plus detailed verification result.
    func verifyCleartextDetailed(
        _ signedMessage: Data
    ) async throws -> (text: Data?, verification: DetailedSignatureVerification) {
        let verificationKeys = allVerificationKeys()

        let result: VerifyDetailedResult
        do {
            result = try await Self.performVerifyCleartextDetailed(
                engine: engine,
                signedMessage: signedMessage,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return (
            text: result.content,
            verification: makeDetailedVerification(
                legacyStatus: result.legacyStatus,
                legacySignerFingerprint: result.legacySignerFingerprint,
                signatures: result.signatures
            )
        )
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

        let signerContact = result.signerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: result.signerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )
        return SignatureVerification(
            status: result.status,
            signerFingerprint: result.signerFingerprint,
            signerContact: signerContact,
            signerIdentity: signerIdentity
        )
    }

    /// Verify a detached signature against the original data while preserving
    /// per-signature detailed results.
    func verifyDetachedDetailed(
        data: Data,
        signature: Data
    ) async throws -> DetailedSignatureVerification {
        let verificationKeys = allVerificationKeys()

        let result: VerifyDetailedResult
        do {
            result = try await Self.performVerifyDetachedDetailed(
                engine: engine,
                data: data,
                signature: signature,
                verificationKeys: verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return makeDetailedVerification(
            legacyStatus: result.legacyStatus,
            legacySignerFingerprint: result.legacySignerFingerprint,
            signatures: result.signatures
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

        let result: FileVerifyDetailedResult
        do {
            result = try await Self.performVerifyDetachedFileDetailed(
                engine: engine, dataPath: fileURL.path,
                signature: signature, verificationKeys: verificationKeys,
                progress: progress
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        let signerContact = result.legacySignerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: result.legacySignerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )
        return SignatureVerification(
            status: result.legacyStatus,
            signerFingerprint: result.legacySignerFingerprint,
            signerContact: signerContact,
            signerIdentity: signerIdentity
        )
    }

    /// Verify a detached signature against a file using streaming I/O while preserving
    /// per-signature detailed results.
    func verifyDetachedStreamingDetailed(
        fileURL: URL,
        signature: Data,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let verificationKeys = allVerificationKeys()

        let result: FileVerifyDetailedResult
        do {
            result = try await Self.performVerifyDetachedFileDetailed(
                engine: engine,
                dataPath: fileURL.path,
                signature: signature,
                verificationKeys: verificationKeys,
                progress: progress
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return makeDetailedVerification(
            legacyStatus: result.legacyStatus,
            legacySignerFingerprint: result.legacySignerFingerprint,
            signatures: result.signatures
        )
    }

    // MARK: - Private

    /// Collect all public keys for signature verification
    /// (contacts + own keys).
    private func allVerificationKeys() -> [Data] {
        contactService.contacts.map { $0.publicKeyData }
            + keyManagement.keys.map { $0.publicKeyData }
    }

    private func makeDetailedVerification(
        legacyStatus: SignatureStatus,
        legacySignerFingerprint: String?,
        signatures: [DetailedSignatureEntry]
    ) -> DetailedSignatureVerification {
        let legacySignerContact = legacySignerFingerprint.flatMap {
            contactService.contact(forFingerprint: $0)
        }
        let legacySignerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: legacySignerFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )

        return DetailedSignatureVerification(
            legacyStatus: legacyStatus,
            legacySignerFingerprint: legacySignerFingerprint,
            legacySignerContact: legacySignerContact,
            legacySignerIdentity: legacySignerIdentity,
            signatures: signatures.map(makeDetailedEntry(from:))
        )
    }

    private func makeDetailedEntry(
        from entry: DetailedSignatureEntry
    ) -> DetailedSignatureVerification.Entry {
        let signerIdentity = SignatureVerification.SignerIdentity.resolve(
            fingerprint: entry.signerPrimaryFingerprint,
            contacts: contactService.contacts,
            ownKeys: keyManagement.keys
        )

        return DetailedSignatureVerification.Entry(
            status: makeDetailedStatus(from: entry.status),
            signerPrimaryFingerprint: entry.signerPrimaryFingerprint,
            signerIdentity: signerIdentity
        )
    }

    private func makeDetailedStatus(
        from status: DetailedSignatureStatus
    ) -> DetailedSignatureVerification.Entry.Status {
        switch status {
        case .valid:
            .valid
        case .unknownSigner:
            .unknownSigner
        case .bad:
            .bad
        case .expired:
            .expired
        }
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
    private static func performVerifyCleartextDetailed(
        engine: PgpEngine,
        signedMessage: Data,
        verificationKeys: [Data]
    ) async throws -> VerifyDetailedResult {
        try engine.verifyCleartextDetailed(
            signedMessage: signedMessage,
            verificationKeys: verificationKeys
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
    private static func performVerifyDetachedDetailed(
        engine: PgpEngine,
        data: Data,
        signature: Data,
        verificationKeys: [Data]
    ) async throws -> VerifyDetailedResult {
        try engine.verifyDetachedDetailed(
            data: data,
            signature: signature,
            verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performVerifyDetachedFileDetailed(
        engine: PgpEngine, dataPath: String, signature: Data,
        verificationKeys: [Data], progress: FileProgressReporter?
    ) async throws -> FileVerifyDetailedResult {
        try engine.verifyDetachedFileDetailed(
            dataPath: dataPath, signature: signature,
            verificationKeys: verificationKeys, progress: progress
        )
    }
}
