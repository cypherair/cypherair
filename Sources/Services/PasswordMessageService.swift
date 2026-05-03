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

    enum DecryptOutcome {
        case decrypted(plaintext: Data, signature: SignatureVerification)
        case noSkesk
        case passwordRejected
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

    func encryptText(
        _ plaintext: String,
        password: String,
        format: PasswordMessageFormat,
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
        format: PasswordMessageFormat,
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

    func decryptMessage(ciphertext: Data, password: String) async throws -> DecryptOutcome {
        let context = verificationContext()

        let result: PasswordDecryptResult
        do {
            result = try await Self.performDecrypt(
                engine: engine,
                ciphertext: ciphertext,
                password: password,
                verificationKeys: context.verificationKeys
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        switch result.status {
        case .decrypted:
            guard let plaintext = result.plaintext else {
                throw CypherAirError.internalError(
                    reason: "Password decrypt returned decrypted status without plaintext."
                )
            }

            let verification = DetailedSignatureVerification.from(
                legacyStatus: result.signatureStatus ?? .notSigned,
                legacySignerFingerprint: result.signerFingerprint,
                summaryState: result.summaryState,
                summaryEntryIndex: result.summaryEntryIndex,
                signatures: result.signatures,
                contacts: context.contacts,
                ownKeys: keyManagement.keys,
                contactsAvailability: context.contactsAvailability
            )
            return .decrypted(plaintext: plaintext, signature: verification.legacyVerification)

        case .noSkesk:
            return .noSkesk

        case .passwordRejected:
            return .passwordRejected
        }
    }

    private func encrypt(
        plaintext: Data,
        password: String,
        format: PasswordMessageFormat,
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

        let result: Data
        do {
            result = try await Self.performEncrypt(
                engine: engine,
                plaintext: plaintext,
                password: password,
                format: format,
                signingKey: signingKey,
                binary: binary
            )
        } catch {
            throw CypherAirError.from(error) { .encryptionFailed(reason: $0) }
        }

        if signingKey != nil {
            signingKey!.resetBytes(in: 0..<signingKey!.count)
            signingKey = nil
        }

        return result
    }

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

    @concurrent
    private static func performEncrypt(
        engine: PgpEngine,
        plaintext: Data,
        password: String,
        format: PasswordMessageFormat,
        signingKey: Data?,
        binary: Bool
    ) async throws -> Data {
        if binary {
            return try engine.encryptBinaryWithPassword(
                plaintext: plaintext,
                password: password,
                format: format,
                signingKey: signingKey
            )
        } else {
            return try engine.encryptWithPassword(
                plaintext: plaintext,
                password: password,
                format: format,
                signingKey: signingKey
            )
        }
    }

    @concurrent
    private static func performDecrypt(
        engine: PgpEngine,
        ciphertext: Data,
        password: String,
        verificationKeys: [Data]
    ) async throws -> PasswordDecryptResult {
        try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: password,
            verificationKeys: verificationKeys
        )
    }
}
