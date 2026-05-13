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
            secretKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
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
            secretKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
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
            secretKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
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

    /// Verify a cleartext-signed message while preserving per-signature detailed results.
    ///
    /// - Parameter signedMessage: The cleartext-signed message data.
    /// - Returns: Original text plus detailed verification result.
    func verifyCleartextDetailed(
        _ signedMessage: Data
    ) async throws -> (text: Data?, verification: DetailedSignatureVerification) {
        let context = verificationContext()

        let result: VerifyDetailedResult
        do {
            result = try await Self.performVerifyCleartextDetailed(
                engine: engine,
                signedMessage: signedMessage,
                verificationKeys: context.verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return (
            text: result.content,
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

    /// Verify a detached signature against the original data while preserving
    /// per-signature detailed results.
    func verifyDetachedDetailed(
        data: Data,
        signature: Data
    ) async throws -> DetailedSignatureVerification {
        let context = verificationContext()

        let result: VerifyDetailedResult
        do {
            result = try await Self.performVerifyDetachedDetailed(
                engine: engine,
                data: data,
                signature: signature,
                verificationKeys: context.verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return DetailedSignatureVerification.from(
            legacyStatus: result.legacyStatus,
            legacySignerFingerprint: result.legacySignerFingerprint,
            summaryState: result.summaryState,
            summaryEntryIndex: result.summaryEntryIndex,
            signatures: result.signatures,
            contacts: context.contacts,
            ownKeys: keyManagement.keys,
            contactsAvailability: context.contactsAvailability
        )
    }

    // MARK: - Streaming File Verification

    /// Verify a detached signature against a file using streaming I/O while preserving
    /// per-signature detailed results.
    func verifyDetachedStreamingDetailed(
        fileURL: URL,
        signature: Data,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let context = verificationContext()

        let result: FileVerifyDetailedResult
        do {
            result = try await Self.performVerifyDetachedFileDetailed(
                engine: engine,
                dataPath: fileURL.path,
                signature: signature,
                verificationKeys: context.verificationKeys,
                progress: progress
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return DetailedSignatureVerification.from(
            legacyStatus: result.legacyStatus,
            legacySignerFingerprint: result.legacySignerFingerprint,
            summaryState: result.summaryState,
            summaryEntryIndex: result.summaryEntryIndex,
            signatures: result.signatures,
            contacts: context.contacts,
            ownKeys: keyManagement.keys,
            contactsAvailability: context.contactsAvailability
        )
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
