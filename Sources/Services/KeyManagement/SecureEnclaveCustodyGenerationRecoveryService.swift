import Foundation

protocol SecureEnclaveCustodyGenerationRecoveryClassifying: Sendable {
    func classify(
        identities: [PGPKeyIdentity]
    ) -> SecureEnclaveCustodyGenerationRecoveryReport
}

final class SecureEnclaveCustodyGenerationRecoveryService: SecureEnclaveCustodyGenerationRecoveryClassifying, @unchecked Sendable {
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let handleStore: SecureEnclaveCustodyHandleStore

    init(
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        handleStore: SecureEnclaveCustodyHandleStore
    ) {
        self.publicBindingInspector = publicBindingInspector
        self.handleStore = handleStore
    }

    func classify(
        identities: [PGPKeyIdentity]
    ) -> SecureEnclaveCustodyGenerationRecoveryReport {
        // The handle inventory runs first and unconditionally — before the
        // `.appleSecureEnclavePrivateOperations` filter below — so the report can
        // surface `handle-only` orphan states: Secure Enclave handles that exist
        // with no corresponding metadata identity (e.g. from interrupted/partial
        // generation). Do NOT gate the inventory on the presence of Secure Enclave
        // identities; that would hide orphan handles whenever no such identity
        // exists. See docs/SECURE_ENCLAVE_CUSTODY.md.
        let inventorySummary: SecureEnclaveCustodyHandleInventorySummary
        let inventoryFailureCategory: PGPKeyOperationFailureCategory?
        do {
            inventorySummary = try handleStore.inventorySummaryForLocalRecovery()
            inventoryFailureCategory = nil
        } catch let error as SecureEnclaveCustodyHandleError {
            inventorySummary = .empty
            inventoryFailureCategory = error.failureCategory
        } catch {
            inventorySummary = .empty
            inventoryFailureCategory = .privateHandleInaccessible
        }

        var secureEnclaveOrdinal = 0
        let assessments = identities.compactMap { identity -> SecureEnclaveCustodyGenerationRecoveryAssessment? in
            guard identity.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations else {
                return nil
            }
            defer { secureEnclaveOrdinal += 1 }
            return classifyIdentity(
                identity,
                ordinal: secureEnclaveOrdinal,
                inventoryFailureCategory: inventoryFailureCategory
            )
        }

        return SecureEnclaveCustodyGenerationRecoveryReport(
            assessments: assessments,
            inventorySummary: inventorySummary,
            inventoryFailureCategory: inventoryFailureCategory
        )
    }

    private func classifyIdentity(
        _ identity: PGPKeyIdentity,
        ordinal: Int,
        inventoryFailureCategory: PGPKeyOperationFailureCategory?
    ) -> SecureEnclaveCustodyGenerationRecoveryAssessment {
        let revocationAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability =
            identity.revocationCert.isEmpty
                ? .unavailable(.revocationArtifactUnavailable)
                : .available

        let configuration = identity.openPGPConfiguration
        guard configuration.algorithmSuite == .p256,
              configuration.keyVersion == identity.keyVersion else {
            return assessment(
                identity: identity,
                ordinal: ordinal,
                publicMaterialAvailability: .unavailable(.invalidConfigurationCustody),
                revocationArtifactAvailability: revocationAvailability,
                handleAvailability: .unavailable(.invalidConfigurationCustody)
            )
        }

        guard !identity.publicKeyData.isEmpty else {
            return assessment(
                identity: identity,
                ordinal: ordinal,
                publicMaterialAvailability: .unavailable(.publicMaterialUnavailable),
                revocationArtifactAvailability: revocationAvailability,
                handleAvailability: .unavailable(.publicMaterialUnavailable)
            )
        }

        let inspection: PGPSecureEnclaveCustodyPublicBindingInspection
        do {
            inspection = try publicBindingInspector.inspectPublicBindings(
                publicKeyData: identity.publicKeyData
            )
        } catch {
            let category = PGPKeyOperationFailureMapper.publicCertificateAssociationCategory(for: error)
            return assessment(
                identity: identity,
                ordinal: ordinal,
                publicMaterialAvailability: .unavailable(category),
                revocationArtifactAvailability: revocationAvailability,
                handleAvailability: .unavailable(category)
            )
        }

        guard inspection.fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame,
              inspection.keyVersion == identity.keyVersion else {
            return assessment(
                identity: identity,
                ordinal: ordinal,
                publicMaterialAvailability: .unavailable(.metadataAssociationMismatch),
                revocationArtifactAvailability: revocationAvailability,
                handleAvailability: .unavailable(.metadataAssociationMismatch)
            )
        }

        let handleAvailability: SecureEnclaveCustodyHandleAvailability
        if let inventoryFailureCategory {
            handleAvailability = .unavailable(inventoryFailureCategory)
        } else {
            handleAvailability = locateHandlePair(inspection)
        }

        return assessment(
            identity: identity,
            ordinal: ordinal,
            publicMaterialAvailability: .available,
            revocationArtifactAvailability: revocationAvailability,
            handleAvailability: handleAvailability
        )
    }

    private func locateHandlePair(
        _ inspection: PGPSecureEnclaveCustodyPublicBindingInspection
    ) -> SecureEnclaveCustodyHandleAvailability {
        do {
            _ = try handleStore.locateHandlePair(
                signingPublicKeyX963: inspection.signingPublicKeyX963,
                keyAgreementPublicKeyX963: inspection.keyAgreementPublicKeyX963
            )
            return .available
        } catch let error as SecureEnclaveCustodyHandleError {
            return .unavailable(error.failureCategory)
        } catch {
            return .unavailable(.privateHandleInaccessible)
        }
    }

    private func assessment(
        identity: PGPKeyIdentity,
        ordinal: Int,
        publicMaterialAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability,
        revocationArtifactAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability,
        handleAvailability: SecureEnclaveCustodyHandleAvailability
    ) -> SecureEnclaveCustodyGenerationRecoveryAssessment {
        SecureEnclaveCustodyGenerationRecoveryAssessment(
            identityOrdinal: ordinal,
            publicMaterialAvailability: publicMaterialAvailability,
            revocationArtifactAvailability: revocationArtifactAvailability,
            handleAvailability: handleAvailability
        )
    }
}
