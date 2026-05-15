import Foundation

/// Handles cleartext text signatures, detached file signatures, and verification.
@Observable
final class SigningService {

    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) {
        self.messageAdapter = messageAdapter
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
            return try await messageAdapter.signCleartext(
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
            return try await messageAdapter.signDetached(
                data: data,
                signerCert: secretKey
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
            return try await messageAdapter.signDetachedFile(
                inputPath: fileURL.path,
                signerCert: secretKey,
                progress: progress
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
        return try await messageAdapter.verifyCleartextDetailed(
            signedMessage: signedMessage,
            verificationContext: context
        )
    }

    /// Verify a detached signature against the original data while preserving
    /// per-signature detailed results.
    func verifyDetachedDetailed(
        data: Data,
        signature: Data
    ) async throws -> DetailedSignatureVerification {
        let context = verificationContext()
        return try await messageAdapter.verifyDetachedDetailed(
            data: data,
            signature: signature,
            verificationContext: context
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
        return try await messageAdapter.verifyDetachedFileDetailed(
            dataPath: fileURL.path,
            signature: signature,
            verificationContext: context,
            progress: progress
        )
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
