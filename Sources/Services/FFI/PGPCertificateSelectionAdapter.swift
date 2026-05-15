import Foundation

/// FFI-owned selector discovery, validation, and by-selector call mapping.
enum PGPCertificateSelectionAdapter {
    static func selectionCatalog(
        engine: PgpEngine,
        certData: Data
    ) throws -> CertificateSelectionCatalog {
        let discovered: DiscoveredCertificateSelectors
        do {
            discovered = try engine.discoverCertificateSelectors(certData: certData)
        } catch {
            throw PGPErrorMapper.map(error) { .invalidKeyData(reason: $0) }
        }

        return map(discovered)
    }

    static func validatedCatalog(
        engine: PgpEngine,
        certData: Data,
        expectedFingerprint: String
    ) throws -> CertificateSelectionCatalog {
        let catalog = try selectionCatalog(engine: engine, certData: certData)

        guard catalog.certificateFingerprint == expectedFingerprint else {
            throw CypherAirError.invalidKeyData(
                reason: "Stored key metadata fingerprint does not match certificate data"
            )
        }

        return catalog
    }

    static func validateUserIdSelection(
        _ selectedUserId: UserIdSelectionOption,
        in catalog: CertificateSelectionCatalog
    ) throws -> UserIdSelectionOption {
        guard catalog.userIds.contains(where: {
            $0.occurrenceIndex == selectedUserId.occurrenceIndex
                && $0.userIdData == selectedUserId.userIdData
        }) else {
            throw CypherAirError.invalidKeyData(
                reason: "Selected User ID does not match the target certificate."
            )
        }

        return selectedUserId
    }

    static func validateUserIdSelection(
        _ selectedUserId: UserIdSelectionOption,
        engine: PgpEngine,
        certData: Data,
        expectedFingerprint: String? = nil
    ) throws -> UserIdSelectionOption {
        let catalog: CertificateSelectionCatalog
        if let expectedFingerprint {
            catalog = try validatedCatalog(
                engine: engine,
                certData: certData,
                expectedFingerprint: expectedFingerprint
            )
        } else {
            catalog = try selectionCatalog(engine: engine, certData: certData)
        }

        return try validateUserIdSelection(selectedUserId, in: catalog)
    }

    static func userIdSelectorInput(
        for selectedUserId: UserIdSelectionOption
    ) -> UserIdSelectorInput {
        UserIdSelectorInput(
            userIdData: selectedUserId.userIdData,
            occurrenceIndex: UInt64(selectedUserId.occurrenceIndex)
        )
    }

    @concurrent
    static func verifyUserIdBindingSignature(
        engine: PgpEngine,
        signature: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        candidateSigners: [Data]
    ) async throws -> CertificateSignatureResult {
        try engine.verifyUserIdBindingSignatureBySelector(
            signature: signature,
            targetCert: targetCert,
            userIdSelector: userIdSelectorInput(for: selectedUserId),
            candidateSigners: candidateSigners
        )
    }

    @concurrent
    static func generateUserIdCertification(
        engine: PgpEngine,
        signerSecretCert: Data,
        targetCert: Data,
        selectedUserId: UserIdSelectionOption,
        certificationKind: CertificationKind
    ) async throws -> Data {
        try engine.generateUserIdCertificationBySelector(
            signerSecretCert: signerSecretCert,
            targetCert: targetCert,
            userIdSelector: userIdSelectorInput(for: selectedUserId),
            certificationKind: certificationKind
        )
    }

    @concurrent
    static func generateUserIdRevocation(
        engine: PgpEngine,
        secretCert: Data,
        selectedUserId: UserIdSelectionOption
    ) async throws -> Data {
        try engine.generateUserIdRevocationBySelector(
            secretCert: secretCert,
            userIdSelector: userIdSelectorInput(for: selectedUserId)
        )
    }

    private static func map(
        _ discovered: DiscoveredCertificateSelectors
    ) -> CertificateSelectionCatalog {
        CertificateSelectionCatalog(
            certificateFingerprint: discovered.certificateFingerprint,
            subkeys: discovered.subkeys.map { discoveredSubkey in
                SubkeySelectionOption(
                    fingerprint: discoveredSubkey.fingerprint,
                    algorithmDisplay: discoveredSubkey.algorithmDisplay,
                    isCurrentlyTransportEncryptionCapable: discoveredSubkey.isCurrentlyTransportEncryptionCapable,
                    isCurrentlyRevoked: discoveredSubkey.isCurrentlyRevoked,
                    isCurrentlyExpired: discoveredSubkey.isCurrentlyExpired
                )
            },
            userIds: discovered.userIds.map { discoveredUserId in
                UserIdSelectionOption(
                    occurrenceIndex: Int(discoveredUserId.occurrenceIndex),
                    userIdData: discoveredUserId.userIdData,
                    displayText: discoveredUserId.displayText,
                    isCurrentlyPrimary: discoveredUserId.isCurrentlyPrimary,
                    isCurrentlyRevoked: discoveredUserId.isCurrentlyRevoked
                )
            }
        )
    }
}
