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

    func matchRecipients(
        ciphertext: Data,
        localCerts: [Data]
    ) async throws -> [String] {
        do {
            return try await Self.performMatchRecipients(
                engine: engine,
                ciphertext: ciphertext,
                localCerts: localCerts
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

    func encryptWithPassword(
        plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signingKey: Data?,
        binary: Bool
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithPassword(
                engine: engine,
                plaintext: plaintext,
                password: password,
                format: format.ffiValue,
                signingKey: signingKey,
                binary: binary
            )
        } catch {
            throw PGPErrorMapper.map(error) { .encryptionFailed(reason: $0) }
        }
    }

    func encryptWithPasswordAndExternalP256Signer(
        plaintext: Data,
        password: String,
        format: PasswordMessageEnvelopeFormat,
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        binary: Bool
    ) async throws -> Data {
        do {
            return try await Self.performEncryptWithPasswordAndExternalP256Signer(
                engine: engine,
                plaintext: plaintext,
                password: password,
                format: format.ffiValue,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                binary: binary
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func decryptWithPassword(
        ciphertext: Data,
        password: String,
        verificationContext: PGPMessageVerificationContext
    ) async throws -> PasswordMessageDetailedDecryptOutcome {
        do {
            let result = try await Self.performDecryptWithPassword(
                engine: engine,
                ciphertext: ciphertext,
                password: password,
                verificationKeys: verificationContext.verificationKeys
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
    private static func performMatchRecipients(
        engine: PgpEngine,
        ciphertext: Data,
        localCerts: [Data]
    ) async throws -> [String] {
        try engine.matchRecipients(ciphertext: ciphertext, localCerts: localCerts)
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
        }
        return try engine.encryptWithPassword(
            plaintext: plaintext,
            password: password,
            format: format,
            signingKey: signingKey
        )
    }

    @concurrent
    private static func performEncryptWithPasswordAndExternalP256Signer(
        engine: PgpEngine,
        plaintext: Data,
        password: String,
        format: PasswordMessageFormat,
        signingPublicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        binary: Bool
    ) async throws -> Data {
        if binary {
            return try engine.encryptBinaryWithPasswordAndExternalP256Signer(
                plaintext: plaintext,
                password: password,
                format: format,
                signingPublicCert: signingPublicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signer: signingProvider
            )
        }
        return try engine.encryptWithPasswordAndExternalP256Signer(
            plaintext: plaintext,
            password: password,
            format: format,
            signingPublicCert: signingPublicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider
        )
    }

    @concurrent
    private static func performDecryptWithPassword(
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

private extension PasswordMessageEnvelopeFormat {
    var ffiValue: PasswordMessageFormat {
        switch self {
        case .seipdv1:
            return .seipdv1
        case .seipdv2:
            return .seipdv2
        }
    }
}
