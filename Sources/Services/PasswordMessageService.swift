import Foundation

/// Orchestrates password-based OpenPGP message encryption and decryption.
///
/// This service is intentionally separate from recipient-key encryption and
/// the two-phase `DecryptionService` flow. Its password-decrypt path does not
/// use Secure Enclave unwrapping or PKESK recipient matching. If optional
/// signing is requested during password-message encryption, it authenticates
/// through `KeyManagementService.unwrapPrivateKey(...)` first.
@Observable
final class PasswordMessageService {
    typealias DetailedDecryptOutcome = PasswordMessageDetailedDecryptOutcome

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

    func encryptText(
        _ plaintext: String,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signWithFingerprint: String?
    ) async throws -> Data {
        try await encrypt(
            plaintext: Data(plaintext.utf8),
            password: password,
            format: format,
            signWithFingerprint: signWithFingerprint,
            binary: false
        )
    }

    func encryptBinary(
        _ plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signWithFingerprint: String?
    ) async throws -> Data {
        try await encrypt(
            plaintext: plaintext,
            password: password,
            format: format,
            signWithFingerprint: signWithFingerprint,
            binary: true
        )
    }

    func decryptMessageDetailed(ciphertext: Data, password: String) async throws -> DetailedDecryptOutcome {
        let context = verificationContext()
        return try await messageAdapter.decryptWithPassword(
            ciphertext: ciphertext,
            password: password,
            verificationContext: context
        )
    }

    private func encrypt(
        plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signWithFingerprint: String?,
        binary: Bool
    ) async throws -> Data {
        var signingKey: Data?
        if let signerFp = signWithFingerprint {
            do {
                signingKey = try await keyManagement.unwrapPrivateKey(fingerprint: signerFp)
            } catch {
                throw CypherAirError.from(error) { _ in .authenticationFailed }
            }
        }

        defer {
            if signingKey != nil {
                signingKey!.resetBytes(in: 0..<signingKey!.count)
                signingKey = nil
            }
        }

        let result = try await messageAdapter.encryptWithPassword(
            plaintext: plaintext,
            password: password,
            format: format,
            signingKey: signingKey,
            binary: binary
        )

        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }

        return result
    }

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
