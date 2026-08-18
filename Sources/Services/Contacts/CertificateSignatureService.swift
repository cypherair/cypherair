import Foundation

/// The result of offering a signature to the app as a certification of a
/// contact key: what the engine made of the signature, and — only when the
/// signature is a certification somebody else made — the artifact that may be
/// saved. `verification` always describes the signature and never the key's
/// standing; a valid signature with no artifact is a normal outcome.
struct ContactCertificationArtifactValidation: Equatable {
    let verification: CertificateSignatureVerification
    let artifact: VerifiedContactCertificationArtifact?
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
    private let certificationSigner: any ContactCertificationSigning

    init(
        certificateAdapter: PGPCertificateOperationAdapter,
        keyManagement: KeyManagementService,
        contactService: ContactService,
        certificationSigner: any ContactCertificationSigning
    ) {
        self.certificateAdapter = certificateAdapter
        self.keyManagement = keyManagement
        self.contactService = contactService
        self.certificationSigner = certificationSigner
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
            candidateSigners: try candidateSignerCertificates()
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
            candidateSigners: try candidateSignerCertificates()
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

        return try await certificationSigner.generateUserIdCertification(
            signerFingerprint: signerFingerprint,
            targetCert: targetCert,
            selectedUserId: validatedUserId,
            certificationKind: certificationKind
        )
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
        guard isThirdPartyCertification(verification, of: targetKey) else {
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
        guard isThirdPartyCertification(verification, of: targetKey) else {
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
                verification: verification,
                exportFilename: exportFilename
            )
        )
    }

    func candidateSignerCertificates() throws -> [Data] {
        let contactKeys = try contactService.candidateSignerPublicKeyData()
        return contactKeys + keyManagement.keys.map(\.publicKeyData)
    }

    /// Whether the verified signature is a certification *somebody else* made
    /// over this key, and so something the app can record as one.
    ///
    /// A key's own signature over its own User ID is a self-signature: it is
    /// part of what an OpenPGP certificate is, every certificate worth importing
    /// carries one, and it attests nothing beyond the certificate's own claim
    /// about itself. Recording it as a certification would let any key vouch for
    /// itself, which is how a key with nothing but self-signatures came to read
    /// as certified. The signature is still valid and the screen still says so —
    /// what it is not is somebody's word about the key.
    private func isThirdPartyCertification(
        _ verification: CertificateSignatureVerification,
        of targetKey: ContactKeySummary
    ) -> Bool {
        guard verification.status == .valid else {
            return false
        }
        return verification.signerPrimaryFingerprint?.lowercased()
            != targetKey.fingerprint.lowercased()
    }

    private func makeCertificationArtifact(
        canonicalSignatureData: Data,
        source: ContactCertificationArtifactSource,
        targetKey: ContactKeySummary,
        targetCert: Data,
        targetSelector: ContactCertificationTargetSelector,
        verification: CertificateSignatureVerification,
        exportFilename: String?
    ) -> VerifiedContactCertificationArtifact {
        let now = Date()
        let reference = ContactCertificationArtifactReference(
            artifactId: "cert-artifact-\(UUID().uuidString)",
            keyId: targetKey.keyId,
            createdAt: now,
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
}
