import Foundation

struct PGPCertificateVerificationContext {
    let contactKeys: [ContactKeyRecord]
    let ownKeys: [PGPKeyIdentity]
}

/// FFI-owned certificate signature, certification, and revocation operations.
final class PGPCertificateOperationAdapter: @unchecked Sendable {
    private let engine: PgpEngine

    init(engine: PgpEngine) {
        self.engine = engine
    }

    func selectionCatalog(targetCert: Data) throws -> CertificateSelectionCatalog {
        try PGPCertificateSelectionAdapter.selectionCatalog(
            engine: engine,
            certData: targetCert
        )
    }

    func validatedCatalog(
        certData: Data,
        expectedFingerprint: String
    ) throws -> CertificateSelectionCatalog {
        try PGPCertificateSelectionAdapter.validatedCatalog(
            engine: engine,
            certData: certData,
            expectedFingerprint: expectedFingerprint
        )
    }

    func validateUserIdSelection(
        _ selectedUserId: UserIdSelectionOption,
        in catalog: CertificateSelectionCatalog
    ) throws -> UserIdSelectionOption {
        try PGPCertificateSelectionAdapter.validateUserIdSelection(
            selectedUserId,
            in: catalog
        )
    }

    func verifyDirectKeySignature(
        signature: Data,
        targetCert: Data,
        candidateSigners: [Data],
        verificationContext: PGPCertificateVerificationContext
    ) async throws -> CertificateSignatureVerification {
        do {
            let result = try await Self.performVerifyDirectKeySignature(
                engine: engine,
                signature: signature,
                targetCert: targetCert,
                candidateSigners: candidateSigners
            )
            return verification(from: result, context: verificationContext)
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func verifyUserIdBindingSignature(
        signature: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        candidateSigners: [Data],
        verificationContext: PGPCertificateVerificationContext
    ) async throws -> CertificateSignatureVerification {
        do {
            let result = try await PGPCertificateSelectionAdapter.verifyUserIdBindingSignature(
                engine: engine,
                signature: signature,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                candidateSigners: candidateSigners
            )
            return verification(from: result, context: verificationContext)
        } catch {
            throw PGPErrorMapper.map(error) { .corruptData(reason: $0) }
        }
    }

    func generateUserIdCertification(
        signerSecretCert: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data {
        do {
            return try await PGPCertificateSelectionAdapter.generateUserIdCertification(
                engine: engine,
                signerSecretCert: signerSecretCert,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind.ffiValue
            )
        } catch {
            throw PGPErrorMapper.map(error) { .signingFailed(reason: $0) }
        }
    }

    func generateUserIdCertificationWithExternalP256Signer(
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data {
        do {
            return try await Self.performGenerateUserIdCertificationWithExternalP256Signer(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind.ffiValue
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func canonicalSignatureData(from signature: Data) async -> Data {
        (try? await Self.performDearmor(engine: engine, armored: signature)) ?? signature
    }

    func armorSignature(_ signature: Data) async throws -> Data {
        do {
            return try await Self.performArmorSignature(
                engine: engine,
                data: signature
            )
        } catch {
            throw PGPErrorMapper.map(error) { .armorError(reason: $0) }
        }
    }

    func armorSignatureForExport(_ signature: Data) throws -> Data {
        do {
            return try engine.armor(data: signature, kind: .signature)
        } catch {
            throw PGPErrorMapper.map(error) { .armorError(reason: $0) }
        }
    }

    func generateKeyRevocation(secretCert: Data) async throws -> Data {
        do {
            return try await Self.performGenerateKeyRevocation(
                engine: engine,
                secretCert: secretCert
            )
        } catch {
            throw PGPErrorMapper.map(error) { .revocationError(reason: $0) }
        }
    }

    func generateSubkeyRevocation(
        secretCert: Data,
        subkeyFingerprint: String
    ) async throws -> Data {
        do {
            return try await Self.performGenerateSubkeyRevocation(
                engine: engine,
                secretCert: secretCert,
                subkeyFingerprint: subkeyFingerprint
            )
        } catch {
            throw PGPErrorMapper.map(error) { .revocationError(reason: $0) }
        }
    }

    func generateSubkeyRevocationWithExternalP256Signer(
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        subkeyFingerprint: String
    ) async throws -> Data {
        do {
            return try await Self.performGenerateSubkeyRevocationWithExternalP256Signer(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                subkeyFingerprint: subkeyFingerprint
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    func generateUserIdRevocation(
        secretCert: Data,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        do {
            return try await PGPCertificateSelectionAdapter.generateUserIdRevocation(
                engine: engine,
                secretCert: secretCert,
                selectedUserId: selectedUserId
            )
        } catch {
            throw PGPErrorMapper.map(error) { .revocationError(reason: $0) }
        }
    }

    func generateUserIdRevocationWithExternalP256Signer(
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        do {
            return try await Self.performGenerateUserIdRevocationWithExternalP256Signer(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                signingProvider: signingProvider,
                selectedUserId: selectedUserId
            )
        } catch {
            throw PGPErrorMapper.mapExternalP256Signing(error)
        }
    }

    private func verification(
        from result: CertificateSignatureResult,
        context: PGPCertificateVerificationContext
    ) -> CertificateSignatureVerification {
        CertificateSignatureVerification(
            status: CertificateSignatureVerificationStatus(from: result.status),
            certificationKind: result.certificationKind.map(OpenPGPCertificationKind.init(from:)),
            signerPrimaryFingerprint: result.signerPrimaryFingerprint,
            signingKeyFingerprint: result.signingKeyFingerprint,
            signerIdentity: CertificateSignatureSignerIdentity.resolve(
                fingerprint: result.signerPrimaryFingerprint,
                contactKeys: context.contactKeys,
                ownKeys: context.ownKeys
            )
        )
    }

    @concurrent
    private static func performVerifyDirectKeySignature(
        engine: PgpEngine,
        signature: Data,
        targetCert: Data,
        candidateSigners: [Data]
    ) async throws -> CertificateSignatureResult {
        try engine.verifyDirectKeySignature(
            signature: signature,
            targetCert: targetCert,
            candidateSigners: candidateSigners
        )
    }

    @concurrent
    private static func performDearmor(
        engine: PgpEngine,
        armored: Data
    ) async throws -> Data {
        try engine.dearmor(armored: armored)
    }

    @concurrent
    private static func performArmorSignature(
        engine: PgpEngine,
        data: Data
    ) async throws -> Data {
        try engine.armor(data: data, kind: .signature)
    }

    @concurrent
    private static func performGenerateKeyRevocation(
        engine: PgpEngine,
        secretCert: Data
    ) async throws -> Data {
        try engine.generateKeyRevocation(secretCert: secretCert)
    }

    @concurrent
    private static func performGenerateSubkeyRevocation(
        engine: PgpEngine,
        secretCert: Data,
        subkeyFingerprint: String
    ) async throws -> Data {
        try engine.generateSubkeyRevocation(
            secretCert: secretCert,
            subkeyFingerprint: subkeyFingerprint
        )
    }

    // MARK: - Device-Bound Post-Quantum split-custody twins

    func generateUserIdCertificationWithExternalCompositeSigner(
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data {
        do {
            return try await Self.performGenerateUserIdCertificationWithExternalCompositeSigner(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                targetCert: targetCert,
                selectedUserId: selectedUserId,
                certificationKind: certificationKind.ffiValue
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func generateSubkeyRevocationWithExternalCompositeSigner(
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        subkeyFingerprint: String
    ) async throws -> Data {
        do {
            return try await Self.performGenerateSubkeyRevocationWithExternalCompositeSigner(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                subkeyFingerprint: subkeyFingerprint
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    func generateUserIdRevocationWithExternalCompositeSigner(
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        do {
            return try await Self.performGenerateUserIdRevocationWithExternalCompositeSigner(
                engine: engine,
                publicCert: publicCert,
                signingKeyFingerprint: signingKeyFingerprint,
                classicalEddsaSecret: classicalEddsaSecret,
                signingProvider: signingProvider,
                selectedUserId: selectedUserId
            )
        } catch {
            throw PGPErrorMapper.mapExternalCompositeSigning(error)
        }
    }

    @concurrent
    private static func performGenerateUserIdCertificationWithExternalCompositeSigner(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        try engine.generateUserIdCertificationBySelectorWithExternalCompositeSigner(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            targetCert: targetCert,
            userIdSelector: PGPCertificateSelectionAdapter.userIdSelectorInput(
                for: selectedUserId
            ),
            certificationKind: certificationKind
        )
    }

    @concurrent
    private static func performGenerateSubkeyRevocationWithExternalCompositeSigner(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        subkeyFingerprint: String
    ) async throws -> Data {
        try engine.generateSubkeyRevocationWithExternalCompositeSigner(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            subkeyFingerprint: subkeyFingerprint
        )
    }

    @concurrent
    private static func performGenerateUserIdRevocationWithExternalCompositeSigner(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        classicalEddsaSecret: Data,
        signingProvider: ExternalMlDsa65SigningProvider,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        try engine.generateUserIdRevocationBySelectorWithExternalCompositeSigner(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            classicalEddsaSecret: classicalEddsaSecret,
            signer: signingProvider,
            userIdSelector: PGPCertificateSelectionAdapter.userIdSelectorInput(
                for: selectedUserId
            )
        )
    }

    @concurrent
    private static func performGenerateSubkeyRevocationWithExternalP256Signer(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        subkeyFingerprint: String
    ) async throws -> Data {
        try engine.generateSubkeyRevocationWithExternalP256Signer(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            subkeyFingerprint: subkeyFingerprint
        )
    }

    @concurrent
    private static func performGenerateUserIdRevocationWithExternalP256Signer(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        try engine.generateUserIdRevocationBySelectorWithExternalP256Signer(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            userIdSelector: PGPCertificateSelectionAdapter.userIdSelectorInput(
                for: selectedUserId
            )
        )
    }

    @concurrent
    private static func performGenerateUserIdCertificationWithExternalP256Signer(
        engine: PgpEngine,
        publicCert: Data,
        signingKeyFingerprint: String,
        signingProvider: ExternalP256SigningProvider,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        try engine.generateUserIdCertificationBySelectorWithExternalP256Signer(
            publicCert: publicCert,
            signingKeyFingerprint: signingKeyFingerprint,
            signer: signingProvider,
            targetCert: targetCert,
            userIdSelector: PGPCertificateSelectionAdapter.userIdSelectorInput(
                for: selectedUserId
            ),
            certificationKind: certificationKind
        )
    }
}

private extension CertificateSignatureVerificationStatus {
    init(from status: CertificateSignatureStatus) {
        switch status {
        case .valid:
            self = .valid
        case .invalid:
            self = .invalid
        case .signerMissing:
            self = .signerMissing
        }
    }
}

private extension OpenPGPCertificationKind {
    var ffiValue: CertificationKind {
        switch self {
        case .generic:
            return .generic
        case .persona:
            return .persona
        case .casual:
            return .casual
        case .positive:
            return .positive
        }
    }

    init(from kind: CertificationKind) {
        switch kind {
        case .generic:
            self = .generic
        case .persona:
            self = .persona
        case .casual:
            self = .casual
        case .positive:
            self = .positive
        }
    }
}
