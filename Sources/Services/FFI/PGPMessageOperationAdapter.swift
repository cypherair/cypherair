import Foundation

struct PGPMessageVerificationContext {
    let verificationKeys: [Data]
    let contactKeys: [ContactKeyRecord]
    let ownKeys: [PGPKeyIdentity]
    let contactsAvailability: ContactsAvailability
}

final class PGPMessageOperationAdapter: @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func dearmorIfNeeded(_ ciphertext: Data) async throws -> Data {
        guard ciphertext.first == 0x2D else {
            return ciphertext
        }

        do {
            return try await Self.performDearmor(engine: engine, armored: ciphertext)
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    /// Phase 1: how this message can be opened — which of `localCerts` it is
    /// addressed to, and whether a password can open it. No secret key, no
    /// password, and no key derivation; an empty match with
    /// `acceptsPassword == false` is an answer, not an error.
    func inspectMessageProtection(
        ciphertext: Data,
        localCerts: [Data]
    ) async throws -> (matchedFingerprints: [String], acceptsPassword: Bool) {
        do {
            let inspection = try await Self.performInspectMessageProtection(
                engine: engine,
                ciphertext: ciphertext,
                localCerts: localCerts
            )
            return (
                inspection.matchedCertificateFingerprints,
                inspection.acceptsPassword
            )
        } catch {
            throw PGPErrorMapper.mapRecipientMatching(error)
        }
    }

    func matchRecipientsFromFile(
        inputPath: String,
        localCerts: [Data]
    ) async throws -> [String] {
        do {
            return try await Self.performMatchRecipientsFromFile(
                engine: engine,
                inputPath: inputPath,
                localCerts: localCerts
            )
        } catch {
            throw PGPErrorMapper.mapRecipientMatching(error)
        }
    }

    func encrypt(
        plaintext: Data,
        recipientKeys: [Data],
        signingKey: Data?,
        selfKey: Data?,
        binary: Bool
    ) async throws -> Data {
        do {
            return try await Self.performEncrypt(
                engine: engine,
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingKey: signingKey,
                selfKey: selfKey,
                binary: binary
            )
        } catch {
            throw PGPErrorMapper.map(error) { .encryptionFailed(reason: $0) }
        }
    }

    func encryptWithExternalP256Signer(
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithExternalP256Signer(
                engine: engine,
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                selfKey: selfKey
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingKey: Data?,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            try await Self.performEncryptFile(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingKey: signingKey,
                selfKey: selfKey,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.map(error) { .encryptionFailed(reason: $0) }
        }
    }

    func encryptFileWithExternalP256Signer(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            try await Self.performEncryptFileWithExternalP256Signer(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                selfKey: selfKey,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func decryptDetailed(
        ciphertext: Data,
        secretKeys: [Data],
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        do {
            let result = try await Self.performDecryptDetailed(
                engine: engine,
                ciphertext: ciphertext,
                secretKeys: secretKeys,
                verificationKeys: verificationContext.verificationKeys
            )
            return PGPMessageResultMapper.decryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func decryptDetailedWithExternalP256KeyAgreement(
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        keyAgreementProvider: ExternalP256KeyAgreementProvider,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        do {
            let result = try await Self.performDecryptDetailedWithExternalP256KeyAgreement(
                engine: engine,
                ciphertext: ciphertext,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                keyAgreementProvider: keyAgreementProvider,
                verificationKeys: verificationContext.verificationKeys
            )
            return PGPMessageResultMapper.decryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256KeyAgreement(error)
        }
    }

    func decryptFileDetailed(
        inputPath: String,
        outputPath: String,
        secretKeys: [Data],
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            let result = try await Self.performDecryptFileDetailed(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                secretKeys: secretKeys,
                verificationKeys: verificationContext.verificationKeys,
                progress: progressBridge
            )
            return PGPMessageResultMapper.fileDecryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func decryptFileWithExternalP256KeyAgreement(
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        keyAgreementProvider: ExternalP256KeyAgreementProvider,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            let result = try await Self.performDecryptFileWithExternalP256KeyAgreement(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                keyAgreementProvider: keyAgreementProvider,
                verificationKeys: verificationContext.verificationKeys,
                progress: progressBridge
            )
            return PGPMessageResultMapper.fileDecryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256KeyAgreement(error)
        }
    }

    /// Encrypt text under a password alone, ASCII-armored.
    ///
    /// The envelope is SEIPDv1 and is not a choice. Every other message takes
    /// the format its recipient certificates advertise; a password message has
    /// no certificate to advertise anything, so it gets the container every
    /// OpenPGP tool can open — which is the point of sending one
    /// (docs/PRODUCT.md §5). No signing key is threaded through: a password
    /// message involves none of the sender's keys.
    func encryptWithPassword(
        plaintext: Data,
        password: String
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithPassword(
                engine: engine,
                plaintext: plaintext,
                password: password
            )
        } catch {
            throw PGPErrorMapper.map(error) { .encryptionFailed(reason: $0) }
        }
    }

    /// Open a password-encrypted message.
    ///
    /// `affordableMemoryKib` bounds the Argon2 cost the engine will derive
    /// under, per password slot and before any derivation runs — the sender
    /// chose those parameters, so they are untrusted input
    /// (`Argon2idMemoryGuard`, docs/SECURITY.md §7).
    func decryptWithPassword(
        ciphertext: Data,
        password: String,
        affordableMemoryKib: UInt64,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> PasswordMessageDetailedDecryptOutcome {
        do {
            let result = try await Self.performDecryptWithPassword(
                engine: engine,
                ciphertext: ciphertext,
                password: password,
                verificationKeys: verificationContext.verificationKeys,
                affordableMemoryKib: affordableMemoryKib
            )
            return try PGPMessageResultMapper.passwordDecryptResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func signCleartext(
        text: Data,
        signerCert: Data
    ) async throws -> Data {
        do {
            return try await Self.performSignCleartext(
                engine: engine,
                text: text,
                signerCert: signerCert
            )
        } catch {
            throw PGPErrorMapper.map(error) { .signingFailed(reason: $0) }
        }
    }

    func signCleartextWithExternalP256Signer(
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider
    ) async throws -> Data {
        do {
            return try await Self.performSignCleartextWithExternalP256Signer(
                engine: engine,
                text: text,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func signDetachedFile(
        inputPath: String,
        signerCert: Data,
        progress: FileProgressReporter?
    ) async throws -> Data {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            return try await Self.performSignDetachedFile(
                engine: engine,
                inputPath: inputPath,
                signerCert: signerCert,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.map(error) { .signingFailed(reason: $0) }
        }
    }

    func signDetachedFileWithExternalP256Signer(
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        progress: FileProgressReporter?
    ) async throws -> Data {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            return try await Self.performSignDetachedFileWithExternalP256Signer(
                engine: engine,
                inputPath: inputPath,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func verifyCleartextDetailed(
        signedMessage: Data,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (text: Data?, verification: DetailedSignatureVerification) {
        do {
            let result = try await Self.performVerifyCleartextDetailed(
                engine: engine,
                signedMessage: signedMessage,
                verificationKeys: verificationContext.verificationKeys
            )
            return PGPMessageResultMapper.verifyDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func verifyDetachedFileDetailed(
        dataPath: String,
        signature: Data,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            let result = try await Self.performVerifyDetachedFileDetailed(
                engine: engine,
                dataPath: dataPath,
                signature: signature,
                verificationKeys: verificationContext.verificationKeys,
                progress: progressBridge
            )
            return PGPMessageResultMapper.fileVerifyDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    @concurrent
    private static func performDearmor(engine: PgpEngine, armored: Data) async throws -> Data {
        try engine.dearmor(armored: armored)
    }

    @concurrent
    private static func performInspectMessageProtection(
        engine: PgpEngine,
        ciphertext: Data,
        localCerts: [Data]
    ) async throws -> MessageProtectionInspection {
        try engine.inspectMessageProtection(ciphertext: ciphertext, localCerts: localCerts)
    }

    @concurrent
    private static func performMatchRecipientsFromFile(
        engine: PgpEngine,
        inputPath: String,
        localCerts: [Data]
    ) async throws -> [String] {
        try engine.matchRecipientsFromFile(inputPath: inputPath, localCerts: localCerts)
    }

    @concurrent
    private static func performEncrypt(
        engine: PgpEngine,
        plaintext: Data,
        recipientKeys: [Data],
        signingKey: Data?,
        selfKey: Data?,
        binary: Bool
    ) async throws -> Data {
        if binary {
            return try engine.encryptBinary(
                plaintext: plaintext,
                recipients: recipientKeys,
                signingKey: signingKey,
                encryptToSelf: selfKey
            )
        }
        return try engine.encrypt(
            plaintext: plaintext,
            recipients: recipientKeys,
            signingKey: signingKey,
            encryptToSelf: selfKey
        )
    }

    @concurrent
    private static func performEncryptWithExternalP256Signer(
        engine: PgpEngine,
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        try engine.encryptWithExternalP256Signer(
            plaintext: plaintext,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            encryptToSelf: selfKey
        )
    }

    @concurrent
    private static func performEncryptFile(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingKey: Data?,
        selfKey: Data?,
        progress: StreamingProgressReporter?
    ) async throws {
        try engine.encryptFile(
            inputPath: inputPath,
            outputPath: outputPath,
            recipients: recipientKeys,
            signingKey: signingKey,
            encryptToSelf: selfKey,
            progress: progress
        )
    }

    @concurrent
    private static func performEncryptFileWithExternalP256Signer(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selfKey: Data?,
        progress: StreamingProgressReporter?
    ) async throws {
        try engine.encryptFileWithExternalP256Signer(
            inputPath: inputPath,
            outputPath: outputPath,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            encryptToSelf: selfKey,
            progress: progress
        )
    }

    @concurrent
    private static func performDecryptDetailed(
        engine: PgpEngine,
        ciphertext: Data,
        secretKeys: [Data],
        verificationKeys: [Data]
    ) async throws -> DecryptDetailedResult {
        try engine.decryptDetailed(
            ciphertext: ciphertext,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performDecryptDetailedWithExternalP256KeyAgreement(
        engine: PgpEngine,
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        keyAgreementProvider: ExternalP256KeyAgreementProvider,
        verificationKeys: [Data]
    ) async throws -> DecryptDetailedResult {
        try engine.decryptDetailedWithExternalP256KeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            keyAgreementProvider: keyAgreementProvider,
            verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performDecryptFileDetailed(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        secretKeys: [Data],
        verificationKeys: [Data],
        progress: StreamingProgressReporter?
    ) async throws -> FileDecryptDetailedResult {
        try engine.decryptFileDetailed(
            inputPath: inputPath,
            outputPath: outputPath,
            secretKeys: secretKeys,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }

    @concurrent
    private static func performDecryptFileWithExternalP256KeyAgreement(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        keyAgreementProvider: ExternalP256KeyAgreementProvider,
        verificationKeys: [Data],
        progress: StreamingProgressReporter?
    ) async throws -> FileDecryptDetailedResult {
        try engine.decryptFileDetailedWithExternalP256KeyAgreement(
            inputPath: inputPath,
            outputPath: outputPath,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            keyAgreementProvider: keyAgreementProvider,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }

    @concurrent
    private static func performEncryptWithPassword(
        engine: PgpEngine,
        plaintext: Data,
        password: String
    ) async throws -> Data {
        try engine.encryptWithPassword(
            plaintext: plaintext,
            password: password,
            format: .seipdv1,
            signingKey: nil
        )
    }

    // MARK: - Device-Bound Post-Quantum split-custody twins

    func encryptWithExternalCompositeSigner(
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithExternalCompositeSigner(
                engine: engine,
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                selfKey: selfKey
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func encryptFileWithExternalCompositeSigner(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            try await Self.performEncryptFileWithExternalCompositeSigner(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                selfKey: selfKey,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func decryptDetailedWithExternalCompositeKeyAgreement(
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem768DecapsulationProvider,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        do {
            let result = try await Self.performDecryptDetailedWithExternalCompositeKeyAgreement(
                engine: engine,
                ciphertext: ciphertext,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                classicalEcdhSecret: classicalEcdhSecret,
                decapsulationProvider: decapsulationProvider,
                verificationKeys: verificationContext.verificationKeys
            )
            return PGPMessageResultMapper.decryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeKeyAgreement(error)
        }
    }

    func decryptFileWithExternalCompositeKeyAgreement(
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem768DecapsulationProvider,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            let result = try await Self.performDecryptFileWithExternalCompositeKeyAgreement(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                classicalEcdhSecret: classicalEcdhSecret,
                decapsulationProvider: decapsulationProvider,
                verificationKeys: verificationContext.verificationKeys,
                progress: progressBridge
            )
            return PGPMessageResultMapper.fileDecryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeKeyAgreement(error)
        }
    }

    func signCleartextWithExternalCompositeSigner(
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider
    ) async throws -> Data {
        do {
            return try await Self.performSignCleartextWithExternalCompositeSigner(
                engine: engine,
                text: text,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func signDetachedFileWithExternalCompositeSigner(
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        progress: FileProgressReporter?
    ) async throws -> Data {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            return try await Self.performSignDetachedFileWithExternalCompositeSigner(
                engine: engine,
                inputPath: inputPath,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    @concurrent
    private static func performEncryptWithExternalCompositeSigner(
        engine: PgpEngine,
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        try engine.encryptWithExternalCompositeSigner(
            plaintext: plaintext,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            encryptToSelf: selfKey
        )
    }

    @concurrent
    private static func performEncryptFileWithExternalCompositeSigner(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selfKey: Data?,
        progress: StreamingProgressReporter?
    ) async throws {
        try engine.encryptFileWithExternalCompositeSigner(
            inputPath: inputPath,
            outputPath: outputPath,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            encryptToSelf: selfKey,
            progress: progress
        )
    }

    @concurrent
    private static func performDecryptDetailedWithExternalCompositeKeyAgreement(
        engine: PgpEngine,
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem768DecapsulationProvider,
        verificationKeys: [Data]
    ) async throws -> DecryptDetailedResult {
        try engine.decryptDetailedWithExternalCompositeKeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: classicalEcdhSecret,
            decapsulationProvider: decapsulationProvider,
            verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performDecryptFileWithExternalCompositeKeyAgreement(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem768DecapsulationProvider,
        verificationKeys: [Data],
        progress: StreamingProgressReporter?
    ) async throws -> FileDecryptDetailedResult {
        try engine.decryptFileDetailedWithExternalCompositeKeyAgreement(
            inputPath: inputPath,
            outputPath: outputPath,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: classicalEcdhSecret,
            decapsulationProvider: decapsulationProvider,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }

    @concurrent
    private static func performSignCleartextWithExternalCompositeSigner(
        engine: PgpEngine,
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider
    ) async throws -> Data {
        try engine.signCleartextWithExternalCompositeSigner(
            text: text,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider
        )
    }

    @concurrent
    private static func performSignDetachedFileWithExternalCompositeSigner(
        engine: PgpEngine,
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        progress: StreamingProgressReporter?
    ) async throws -> Data {
        try engine.signDetachedFileWithExternalCompositeSigner(
            inputPath: inputPath,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            progress: progress
        )
    }

    // MARK: - Device-Bound Post-Quantum · High (ML-DSA-87 + ML-KEM-1024)

    func encryptWithExternalCompositeHighSigner(
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithExternalCompositeHighSigner(
                engine: engine,
                plaintext: plaintext,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                selfKey: selfKey
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func encryptFileWithExternalCompositeHighSigner(
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        selfKey: Data?,
        progress: FileProgressReporter?
    ) async throws {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            try await Self.performEncryptFileWithExternalCompositeHighSigner(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientKeys: recipientKeys,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                selfKey: selfKey,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func decryptDetailedWithExternalCompositeHighKeyAgreement(
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem1024DecapsulationProvider,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> (plaintext: Data, verification: DetailedSignatureVerification) {
        do {
            let result = try await Self.performDecryptDetailedWithExternalCompositeHighKeyAgreement(
                engine: engine,
                ciphertext: ciphertext,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                classicalEcdhSecret: classicalEcdhSecret,
                decapsulationProvider: decapsulationProvider,
                verificationKeys: verificationContext.verificationKeys
            )
            return PGPMessageResultMapper.decryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeKeyAgreement(error)
        }
    }

    func decryptFileWithExternalCompositeHighKeyAgreement(
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem1024DecapsulationProvider,
        verificationContext: PGPMessageVerificationContext,
        progress: FileProgressReporter?
    ) async throws -> DetailedSignatureVerification {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            let result = try await Self.performDecryptFileWithExternalCompositeHighKeyAgreement(
                engine: engine,
                inputPath: inputPath,
                outputPath: outputPath,
                recipientPublicCert: recipientPublicCert,
                keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
                classicalEcdhSecret: classicalEcdhSecret,
                decapsulationProvider: decapsulationProvider,
                verificationKeys: verificationContext.verificationKeys,
                progress: progressBridge
            )
            return PGPMessageResultMapper.fileDecryptDetailedResult(
                result,
                context: verificationContext
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeKeyAgreement(error)
        }
    }

    func signCleartextWithExternalCompositeHighSigner(
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider
    ) async throws -> Data {
        do {
            return try await Self.performSignCleartextWithExternalCompositeHighSigner(
                engine: engine,
                text: text,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func signDetachedFileWithExternalCompositeHighSigner(
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        progress: FileProgressReporter?
    ) async throws -> Data {
        let progressBridge = progress.map { PGPProgressReporterBridge(reporter: $0) }
        do {
            return try await Self.performSignDetachedFileWithExternalCompositeHighSigner(
                engine: engine,
                inputPath: inputPath,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                progress: progressBridge
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    @concurrent
    private static func performEncryptWithExternalCompositeHighSigner(
        engine: PgpEngine,
        plaintext: Data,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        selfKey: Data?
    ) async throws -> Data {
        try engine.encryptWithExternalCompositeHighSigner(
            plaintext: plaintext,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            encryptToSelf: selfKey
        )
    }

    @concurrent
    private static func performEncryptFileWithExternalCompositeHighSigner(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientKeys: [Data],
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        selfKey: Data?,
        progress: StreamingProgressReporter?
    ) async throws {
        try engine.encryptFileWithExternalCompositeHighSigner(
            inputPath: inputPath,
            outputPath: outputPath,
            recipients: recipientKeys,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            encryptToSelf: selfKey,
            progress: progress
        )
    }

    @concurrent
    private static func performDecryptDetailedWithExternalCompositeHighKeyAgreement(
        engine: PgpEngine,
        ciphertext: Data,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem1024DecapsulationProvider,
        verificationKeys: [Data]
    ) async throws -> DecryptDetailedResult {
        try engine.decryptDetailedWithExternalCompositeHighKeyAgreement(
            ciphertext: ciphertext,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: classicalEcdhSecret,
            decapsulationProvider: decapsulationProvider,
            verificationKeys: verificationKeys
        )
    }

    @concurrent
    private static func performDecryptFileWithExternalCompositeHighKeyAgreement(
        engine: PgpEngine,
        inputPath: String,
        outputPath: String,
        recipientPublicCert: Data,
        keyAgreementSubkeyFingerprint: String,
        classicalEcdhSecret: Data,
        decapsulationProvider: ExternalMlKem1024DecapsulationProvider,
        verificationKeys: [Data],
        progress: StreamingProgressReporter?
    ) async throws -> FileDecryptDetailedResult {
        try engine.decryptFileDetailedWithExternalCompositeHighKeyAgreement(
            inputPath: inputPath,
            outputPath: outputPath,
            recipientPublicCert: recipientPublicCert,
            keyAgreementSubkeyFingerprint: keyAgreementSubkeyFingerprint,
            classicalEcdhSecret: classicalEcdhSecret,
            decapsulationProvider: decapsulationProvider,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }

    @concurrent
    private static func performSignCleartextWithExternalCompositeHighSigner(
        engine: PgpEngine,
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider
    ) async throws -> Data {
        try engine.signCleartextWithExternalCompositeHighSigner(
            text: text,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider
        )
    }

    @concurrent
    private static func performSignDetachedFileWithExternalCompositeHighSigner(
        engine: PgpEngine,
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa87SigningProvider,
        progress: StreamingProgressReporter?
    ) async throws -> Data {
        try engine.signDetachedFileWithExternalCompositeHighSigner(
            inputPath: inputPath,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            progress: progress
        )
    }

    @concurrent
    private static func performDecryptWithPassword(
        engine: PgpEngine,
        ciphertext: Data,
        password: String,
        verificationKeys: [Data],
        affordableMemoryKib: UInt64
    ) async throws -> PasswordDecryptResult {
        try engine.decryptWithPassword(
            ciphertext: ciphertext,
            password: password,
            verificationKeys: verificationKeys,
            affordableMemoryKib: affordableMemoryKib
        )
    }

    @concurrent
    private static func performSignCleartext(
        engine: PgpEngine,
        text: Data,
        signerCert: Data
    ) async throws -> Data {
        try engine.signCleartext(text: text, signerCert: signerCert)
    }

    @concurrent
    private static func performSignCleartextWithExternalP256Signer(
        engine: PgpEngine,
        text: Data,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider
    ) async throws -> Data {
        try engine.signCleartextWithExternalP256Signer(
            text: text,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider
        )
    }

    @concurrent
    private static func performSignDetachedFile(
        engine: PgpEngine,
        inputPath: String,
        signerCert: Data,
        progress: StreamingProgressReporter?
    ) async throws -> Data {
        try engine.signDetachedFile(
            inputPath: inputPath,
            signerCert: signerCert,
            progress: progress
        )
    }

    @concurrent
    private static func performSignDetachedFileWithExternalP256Signer(
        engine: PgpEngine,
        inputPath: String,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        progress: StreamingProgressReporter?
    ) async throws -> Data {
        try engine.signDetachedFileWithExternalP256Signer(
            inputPath: inputPath,
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            progress: progress
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
    private static func performVerifyDetachedFileDetailed(
        engine: PgpEngine,
        dataPath: String,
        signature: Data,
        verificationKeys: [Data],
        progress: StreamingProgressReporter?
    ) async throws -> FileVerifyDetailedResult {
        try engine.verifyDetachedFileDetailed(
            dataPath: dataPath,
            signature: signature,
            verificationKeys: verificationKeys,
            progress: progress
        )
    }
}

private final class PGPProgressReporterBridge: StreamingProgressReporter, @unchecked Sendable {
    private let reporter: FileProgressReporter

    init(reporter: FileProgressReporter) {
        self.reporter = reporter
    }

    func onProgress(bytesProcessed: UInt64, totalBytes: UInt64) -> Bool {
        reporter.onProgress(bytesProcessed: bytesProcessed, totalBytes: totalBytes)
    }
}
