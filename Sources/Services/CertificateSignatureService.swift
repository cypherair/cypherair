import Foundation

struct ContactCertificationArtifactValidation: Equatable {
    let verification: CertificateSignatureVerification
    let artifact: VerifiedContactCertificationArtifact?

    var canSave: Bool {
        artifact != nil
    }
}

@dynamicMemberLookup
struct VerifiedContactCertificationArtifact: Equatable, Sendable {
    let reference: ContactCertificationArtifactReference

    fileprivate init(reference: ContactCertificationArtifactReference) {
        self.reference = reference
    }

    subscript<Value>(
        dynamicMember keyPath: KeyPath<ContactCertificationArtifactReference, Value>
    ) -> Value {
        reference[keyPath: keyPath]
    }
}

/// Handles certificate-signature verification and User ID certification generation.
@Observable
final class CertificateSignatureService {

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

    /// Discover selector-bearing metadata for arbitrary target certificate bytes.
    func selectionCatalog(targetCert: Data) throws -> CertificateSelectionCatalog {
        try PGPCertificateSelectionAdapter.selectionCatalog(
            engine: engine,
            certData: targetCert
        )
    }

    func verifyDirectKeySignature(
        signature: Data,
        targetCert: Data
    ) async throws -> CertificateSignatureVerification {
        let result: CertificateSignatureResult
        do {
            result = try await Self.performVerifyDirectKeySignature(
                engine: engine,
                signature: signature,
                targetCert: targetCert,
                candidateSigners: try candidateSignerCertificates()
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return makeVerification(from: result)
    }

    func verifyUserIdBindingSignature(
        signature: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption
    ) async throws -> CertificateSignatureVerification {
        let validatedUserId = try validatedUserIdSelection(
            targetCert: targetCert,
            selectedUserId: selectedUserId
        )

        let result: CertificateSignatureResult
        do {
            result = try await Self.performVerifyUserIdBindingSignatureBySelector(
                engine: engine,
                signature: signature,
                targetCert: targetCert,
                selectedUserId: validatedUserId,
                candidateSigners: try candidateSignerCertificates()
            )
        } catch {
            throw CypherAirError.from(error) { .corruptData(reason: $0) }
        }

        return makeVerification(from: result)
    }

    func generateUserIdCertification(
        signerFingerprint: String,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        let validatedUserId = try validatedUserIdSelection(
            targetCert: targetCert,
            selectedUserId: selectedUserId
        )

        var signerSecretCert: Data
        do {
            signerSecretCert = try await keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
        } catch {
            throw CypherAirError.from(error) { _ in .authenticationFailed }
        }
        defer {
            signerSecretCert.resetBytes(in: 0..<signerSecretCert.count)
        }

        do {
            return try await Self.performGenerateUserIdCertificationBySelector(
                engine: engine,
                signerSecretCert: signerSecretCert,
                targetCert: targetCert,
                selectedUserId: validatedUserId,
                certificationKind: certificationKind
            )
        } catch {
            throw CypherAirError.from(error) { .signingFailed(reason: $0) }
        }
    }

    func generateArmoredUserIdCertification(
        signerFingerprint: String,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        let rawSignature = try await generateUserIdCertification(
            signerFingerprint: signerFingerprint,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            certificationKind: certificationKind
        )

        do {
            return try engine.armor(data: rawSignature, kind: .signature)
        } catch {
            throw CypherAirError.from(error) { .armorError(reason: $0) }
        }
    }

    func canonicalSignatureData(from signature: Data) -> Data {
        (try? engine.dearmor(armored: signature)) ?? signature
    }

    func validateDirectKeyCertificationArtifact(
        signature: Data,
        targetKey: ContactKeySummary,
        targetCert: Data,
        source: ContactCertificationArtifactSource,
        exportFilename: String? = nil
    ) async throws -> ContactCertificationArtifactValidation {
        let canonicalSignature = canonicalSignatureData(from: signature)
        let verification = try await verifyDirectKeySignature(
            signature: canonicalSignature,
            targetCert: targetCert
        )
        guard verification.status == .valid else {
            return ContactCertificationArtifactValidation(
                verification: verification,
                artifact: nil
            )
        }

        return ContactCertificationArtifactValidation(
            verification: verification,
            artifact: makeCertificationArtifact(
                canonicalSignatureData: canonicalSignature,
                source: source,
                targetKey: targetKey,
                targetCert: targetCert,
                targetSelector: .directKey,
                userId: nil,
                verification: verification,
                exportFilename: exportFilename
            )
        )
    }

    func validateUserIdCertificationArtifact(
        signature: Data,
        targetKey: ContactKeySummary,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        source: ContactCertificationArtifactSource,
        exportFilename: String? = nil
    ) async throws -> ContactCertificationArtifactValidation {
        let canonicalSignature = canonicalSignatureData(from: signature)
        let verification = try await verifyUserIdBindingSignature(
            signature: canonicalSignature,
            targetCert: targetCert,
            selectedUserId: selectedUserId
        )
        guard verification.status == .valid else {
            return ContactCertificationArtifactValidation(
                verification: verification,
                artifact: nil
            )
        }

        return ContactCertificationArtifactValidation(
            verification: verification,
            artifact: makeCertificationArtifact(
                canonicalSignatureData: canonicalSignature,
                source: source,
                targetKey: targetKey,
                targetCert: targetCert,
                targetSelector: .userId(
                    data: selectedUserId.userIdData,
                    displayText: selectedUserId.displayText,
                    occurrenceIndex: selectedUserId.occurrenceIndex
                ),
                userId: selectedUserId.displayText,
                verification: verification,
                exportFilename: exportFilename
            )
        )
    }

    func candidateSignerCertificates() throws -> [Data] {
        try contactService.requireContactsAvailable()
        return contactService.availableContacts.map(\.publicKeyData)
            + keyManagement.keys.map(\.publicKeyData)
    }

    func resolveSignerIdentity(
        primaryFingerprint: String?
    ) -> CertificateSignatureSignerIdentity? {
        CertificateSignatureSignerIdentity.resolve(
            fingerprint: primaryFingerprint,
            contacts: contactService.contactsForVerificationContext().contacts,
            ownKeys: keyManagement.keys
        )
    }

    private func makeVerification(
        from result: CertificateSignatureResult
    ) -> CertificateSignatureVerification {
        CertificateSignatureVerification(
            status: result.status,
            certificationKind: result.certificationKind,
            signerPrimaryFingerprint: result.signerPrimaryFingerprint,
            signingKeyFingerprint: result.signingKeyFingerprint,
            signerIdentity: resolveSignerIdentity(
                primaryFingerprint: result.signerPrimaryFingerprint
            )
        )
    }

    private func makeCertificationArtifact(
        canonicalSignatureData: Data,
        source: ContactCertificationArtifactSource,
        targetKey: ContactKeySummary,
        targetCert: Data,
        targetSelector: ContactCertificationTargetSelector,
        userId: String?,
        verification: CertificateSignatureVerification,
        exportFilename: String?
    ) -> VerifiedContactCertificationArtifact {
        let now = Date()
        let reference = ContactCertificationArtifactReference(
            artifactId: "cert-artifact-\(UUID().uuidString)",
            keyId: targetKey.keyId,
            userId: userId,
            createdAt: now,
            storageHint: "protected-contacts-domain",
            canonicalSignatureData: canonicalSignatureData,
            signatureDigest: ContactCertificationArtifactReference.sha256Hex(
                for: canonicalSignatureData
            ),
            source: source,
            targetKeyFingerprint: targetKey.fingerprint,
            targetSelector: targetSelector,
            signerPrimaryFingerprint: verification.signerPrimaryFingerprint,
            signingKeyFingerprint: verification.signingKeyFingerprint,
            certificationKind: verification.certificationKind,
            validationStatus: .valid,
            targetCertificateDigest: ContactCertificationArtifactReference.sha256Hex(
                for: targetCert
            ),
            lastValidatedAt: now,
            updatedAt: now,
            exportFilename: exportFilename
        )
        return VerifiedContactCertificationArtifact(reference: reference)
    }

    private func validatedUserIdSelection(
        targetCert: Data,
        selectedUserId: UserIdSelectionOption
    ) throws -> UserIdSelectionOption {
        let catalog = try selectionCatalog(targetCert: targetCert)

        return try PGPCertificateSelectionAdapter.validateUserIdSelection(
            selectedUserId,
            in: catalog
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
    private static func performVerifyUserIdBindingSignatureBySelector(
        engine: PgpEngine,
        signature: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        candidateSigners: [Data]
    ) async throws -> CertificateSignatureResult {
        try await PGPCertificateSelectionAdapter.verifyUserIdBindingSignature(
            engine: engine,
            signature: signature,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            candidateSigners: candidateSigners
        )
    }

    @concurrent
    private static func performGenerateUserIdCertificationBySelector(
        engine: PgpEngine,
        signerSecretCert: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        try await PGPCertificateSelectionAdapter.generateUserIdCertification(
            engine: engine,
            signerSecretCert: signerSecretCert,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            certificationKind: certificationKind
        )
    }
}
