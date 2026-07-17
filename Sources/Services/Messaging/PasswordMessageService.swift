import Foundation

/// Orchestrates password-based OpenPGP message encryption and decryption.
///
/// This service is intentionally separate from recipient-key encryption and
/// the two-phase `DecryptionService` flow. Its password-decrypt path does not
/// use Secure Enclave unwrapping or PKESK recipient matching. If optional
/// signing is requested during password-message encryption, private-key
/// dispatch is delegated through the key-management router.
@Observable
final class PasswordMessageService {
    typealias DetailedDecryptOutcome = PasswordMessageDetailedDecryptOutcome

    private let messageAdapter: PGPMessageOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService
    private let passwordEncryptor: any PasswordMessageEncrypting

    init(
        messageAdapter: PGPMessageOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        passwordEncryptor: any PasswordMessageEncrypting
    ) {
        self.messageAdapter = messageAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.passwordEncryptor = passwordEncryptor
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
        try await passwordEncryptor.encrypt(
            plaintext: plaintext,
            password: password,
            format: format,
            signerFingerprint: signWithFingerprint,
            binary: binary
        )
    }

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
