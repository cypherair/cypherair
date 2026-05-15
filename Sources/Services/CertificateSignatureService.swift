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

    private let certificateAdapter: PGPCertificateOperationAdapter
    private let keyManagement: KeyManagementService
    private let contactService: ContactService

    init(
        certificateAdapter: PGPCertificateOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService
    ) {
        self.certificateAdapter = certificateAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
    }

    /// Discover selector-bearing metadata for arbitrary target certificate bytes.
    func selectionCatalog(targetCert: Data) throws -> CertificateSelectionCatalog {
        try certificateAdapter.selectionCatalog(targetCert: targetCert)
    }

    func verifyDirectKeySignature(
        signature: Data,
        targetCert: Data
    ) async throws -> CertificateSignatureVerification {
        try await certificateAdapter.verifyDirectKeySignature(
            signature: signature,
            targetCert: targetCert,
            candidateSigners: try candidateSignerCertificates(),
            verificationContext: verificationContext()
        )
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

        return try await certificateAdapter.verifyUserIdBindingSignature(
            signature: signature,
            targetCert: targetCert,
            selectedUserId: validatedUserId,
            candidateSigners: try candidateSignerCertificates(),
            verificationContext: verificationContext()
        )
    }

    func generateUserIdCertification(
        signerFingerprint: String,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: OpenPGPCertificationKind
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
            return try await certificateAdapter.generateUserIdCertification(
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
        certificationKind: OpenPGPCertificationKind
    ) async throws -> Data {
        let rawSignature = try await generateUserIdCertification(
            signerFingerprint: signerFingerprint,
            targetCert: targetCert,
            selectedUserId: selectedUserId,
            certificationKind: certificationKind
        )

        return try await certificateAdapter.armorSignature(rawSignature)
    }

    func canonicalSignatureData(from signature: Data) async -> Data {
        await certificateAdapter.canonicalSignatureData(from: signature)
    }

    func validateDirectKeyCertificationArtifact(
        signature: Data,
        targetKey: ContactKeySummary,
        targetCert: Data,
        source: ContactCertificationArtifactSource,
        exportFilename: String? = nil
    ) async throws -> ContactCertificationArtifactValidation {
        let canonicalSignature = await canonicalSignatureData(from: signature)
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
        let canonicalSignature = await canonicalSignatureData(from: signature)
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

        return try certificateAdapter.validateUserIdSelection(
            selectedUserId,
            in: catalog
        )
    }

    private func verificationContext() -> PGPCertificateVerificationContext {
        PGPCertificateVerificationContext(
            contacts: contactService.contactsForVerificationContext().contacts,
            ownKeys: keyManagement.keys
        )
    }
}
