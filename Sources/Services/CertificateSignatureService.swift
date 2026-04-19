import Foundation

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
        try CertificateSelectionCatalogDiscovery.discover(
            engine: engine,
            certData: targetCert
        ).catalog
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
                candidateSigners: candidateSignerCertificates()
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
        let selectorInput = try validatedSelectorInput(
            targetCert: targetCert,
            selectedUserId: selectedUserId
        )

        let result: CertificateSignatureResult
        do {
            result = try await Self.performVerifyUserIdBindingSignatureBySelector(
                engine: engine,
                signature: signature,
                targetCert: targetCert,
                userIdSelector: selectorInput,
                candidateSigners: candidateSignerCertificates()
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
        let selectorInput = try validatedSelectorInput(
            targetCert: targetCert,
            selectedUserId: selectedUserId
        )

        var signerSecretCert: Data
        do {
            signerSecretCert = try keyManagement.unwrapPrivateKey(fingerprint: signerFingerprint)
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
                userIdSelector: selectorInput,
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

    func candidateSignerCertificates() -> [Data] {
        contactService.contacts.map(\.publicKeyData)
            + keyManagement.keys.map(\.publicKeyData)
    }

    func resolveSignerIdentity(
        primaryFingerprint: String?
    ) -> CertificateSignatureSignerIdentity? {
        CertificateSignatureSignerIdentity.resolve(
            fingerprint: primaryFingerprint,
            contacts: contactService.contacts,
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

    private func validatedSelectorInput(
        targetCert: Data,
        selectedUserId: UserIdSelectionOption
    ) throws -> UserIdSelectorInput {
        let catalog = try selectionCatalog(targetCert: targetCert)

        guard catalog.userIds.contains(where: {
            $0.occurrenceIndex == selectedUserId.occurrenceIndex
                && $0.userIdData == selectedUserId.userIdData
        }) else {
            throw CypherAirError.invalidKeyData(
                reason: "Selected User ID does not match the target certificate."
            )
        }

        return selectedUserId.selectorInput
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
        userIdSelector: UserIdSelectorInput,
        candidateSigners: [Data]
    ) async throws -> CertificateSignatureResult {
        try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: targetCert,
            userIdSelector: userIdSelector,
            candidateSigners: candidateSigners
        )
    }

    @concurrent
    private static func performGenerateUserIdCertificationBySelector(
        engine: PgpEngine,
        signerSecretCert: Data,
        targetCert: Data,
        userIdSelector: UserIdSelectorInput,
        certificationKind: CertificationKind
    ) async throws -> Data {
        try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signerSecretCert,
            targetCert: targetCert,
            userIdSelector: userIdSelector,
            certificationKind: certificationKind
        )
    }
}
