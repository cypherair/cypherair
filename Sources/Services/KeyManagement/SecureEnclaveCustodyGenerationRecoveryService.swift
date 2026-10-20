import Foundation
import Stores

protocol SecureEnclaveCustodyGenerationRecoveryClassifying: Sendable {
    func classify(identities: [PGPKeyIdentity]) -> SecureEnclaveCustodyGenerationRecoveryReport
}

/// Classifies every device-bound identity against what the custody rows and
/// the split-custody rows actually hold, without any prompt.
final class SecureEnclaveCustodyGenerationRecoveryService: SecureEnclaveCustodyGenerationRecoveryClassifying, @unchecked Sendable {
    private let publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting
    private let vault: AppVault
    private let compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)?

    init(
        publicBindingInspector: any SecureEnclaveCustodyPublicBindingInspecting,
        vault: AppVault,
        compositeBindingInspector: (any SecureEnclaveCompositeBindingInspecting)? = nil
    ) {
        self.publicBindingInspector = publicBindingInspector
        self.vault = vault
        self.compositeBindingInspector = compositeBindingInspector
    }

    func classify(identities: [PGPKeyIdentity]) -> SecureEnclaveCustodyGenerationRecoveryReport {
        let inventorySummary: SecureEnclaveCustodyHandleInventorySummary
        let inventoryFailureCategory: PGPKeyOperationFailureCategory?
        do {
            inventorySummary = SecureEnclaveCustodyHandleInventorySummary(inventory: try vault.custody.inventory())
            inventoryFailureCategory = nil
        } catch {
            inventorySummary = .empty
            inventoryFailureCategory = error.failureCategory
        }
        var ordinal = 0
        let assessments = identities.compactMap { identity -> SecureEnclaveCustodyGenerationRecoveryAssessment? in
            guard identity.privateKeyCustodyKind == .appleSecureEnclavePrivateOperations else { return nil }
            defer { ordinal += 1 }
            return classifyIdentity(identity, ordinal: ordinal, inventoryFailureCategory: inventoryFailureCategory)
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
        let revocation: SecureEnclaveCustodyRecoveryMaterialAvailability =
            identity.revocationCert.isEmpty ? .unavailable(.revocationArtifactUnavailable) : .available
        guard let tier = identity.keyFamily.deviceBoundCustodyTier else {
            return assessment(ordinal, .unavailable(.invalidFamilyCustody), revocation, .unavailable(.invalidFamilyCustody), nil)
        }
        let classical: SecureEnclaveCustodyRecoveryMaterialAvailability? = tier == .classicalP256 ? nil
            : ((try? vault.splitCustody.contains(fingerprint: identity.fingerprint)) == true ? .available : .unavailable(.classicalComponentFailed))
        guard !identity.publicKeyData.isEmpty else {
            return assessment(ordinal, .unavailable(.publicMaterialUnavailable), revocation, .unavailable(.publicMaterialUnavailable), classical)
        }
        let signing: Data
        let keyAgreement: Data
        let fingerprint: String
        let keyVersion: UInt8
        do {
            switch tier {
            case .classicalP256:
                let inspection = try publicBindingInspector.inspectPublicBindings(publicKeyData: identity.publicKeyData)
                (signing, keyAgreement, fingerprint, keyVersion) = (inspection.signingPublicKeyX963, inspection.keyAgreementPublicKeyX963, inspection.fingerprint, inspection.keyVersion)
            case .postQuantum, .postQuantumHigh:
                guard let compositeBindingInspector else {
                    return assessment(ordinal, .unavailable(.operationUnavailableByPolicy), revocation, .unavailable(.operationUnavailableByPolicy), classical)
                }
                let inspection = try compositeBindingInspector.inspectCompositeBindings(publicKeyData: identity.publicKeyData, tier: tier)
                (signing, keyAgreement, fingerprint, keyVersion) = (inspection.signingComponentPublicKey, inspection.keyAgreementComponentPublicKey, inspection.fingerprint, inspection.keyVersion)
            }
        } catch {
            let category = PGPKeyOperationFailureMapper.publicCertificateAssociationCategory(for: error)
            return assessment(ordinal, .unavailable(category), revocation, .unavailable(category), classical)
        }
        guard fingerprint.caseInsensitiveCompare(identity.fingerprint) == .orderedSame, keyVersion == identity.keyVersion else {
            return assessment(ordinal, .unavailable(.metadataAssociationMismatch), revocation, .unavailable(.metadataAssociationMismatch), classical)
        }
        let handles: SecureEnclaveCustodyHandleAvailability
        if let inventoryFailureCategory {
            handles = .unavailable(inventoryFailureCategory)
        } else {
            do {
                _ = try vault.custody.locatePair(tier: tier, signingPublicKeyRaw: signing, keyAgreementPublicKeyRaw: keyAgreement)
                handles = .available
            } catch {
                handles = .unavailable(error.failureCategory)
            }
        }
        return assessment(ordinal, .available, revocation, handles, classical)
    }

    private func assessment(
        _ ordinal: Int,
        _ publicMaterial: SecureEnclaveCustodyRecoveryMaterialAvailability,
        _ revocation: SecureEnclaveCustodyRecoveryMaterialAvailability,
        _ handles: SecureEnclaveCustodyHandleAvailability,
        _ classical: SecureEnclaveCustodyRecoveryMaterialAvailability?
    ) -> SecureEnclaveCustodyGenerationRecoveryAssessment {
        SecureEnclaveCustodyGenerationRecoveryAssessment(
            identityOrdinal: ordinal,
            publicMaterialAvailability: publicMaterial,
            revocationArtifactAvailability: revocation,
            handleAvailability: handles,
            classicalComponentAvailability: classical
        )
    }
}
