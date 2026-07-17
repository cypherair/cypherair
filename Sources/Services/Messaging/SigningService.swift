import Foundation

/// Handles cleartext text signatures, detached file signatures, and verification.
@Observable
final class SigningService {

    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let cleartextSigner: any CleartextMessageSigning
    private let detachedFileSigner: any DetachedFileSigning

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        cleartextSigner: any CleartextMessageSigning,
        detachedFileSigner: any DetachedFileSigning
    ) {
        self.messageAdapter = messageAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.cleartextSigner = cleartextSigner
        self.detachedFileSigner = detachedFileSigner
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
        try await cleartextSigner.signCleartext(
            Data(text.utf8),
            signerFingerprint: signerFingerprint
        )
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
        try await detachedFileSigner.signDetachedFile(
            inputPath: fileURL.path,
            signerFingerprint: signerFingerprint,
            progress: progress
        )
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
