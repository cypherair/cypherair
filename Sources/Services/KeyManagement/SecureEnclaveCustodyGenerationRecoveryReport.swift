import Foundation

struct SecureEnclaveCustodyGenerationRecoveryReport: Equatable, Sendable {
    let assessments: [SecureEnclaveCustodyGenerationRecoveryAssessment]
    let inventorySummary: SecureEnclaveCustodyHandleInventorySummary
    let inventoryFailureCategory: PGPKeyOperationFailureCategory?

    static let empty = SecureEnclaveCustodyGenerationRecoveryReport(
        assessments: [],
        inventorySummary: .empty,
        inventoryFailureCategory: nil
    )
}

struct SecureEnclaveCustodyGenerationRecoveryAssessment: Equatable, Sendable {
    let identityOrdinal: Int
    let publicMaterialAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability
    let revocationArtifactAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability
    let handleAvailability: SecureEnclaveCustodyHandleAvailability
    /// Split-custody only: whether the sealed classical component is still
    /// present. `nil` for tiers that have no classical component, which is a
    /// different statement from "present" and must not read as degraded.
    let classicalComponentAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability?

    init(
        identityOrdinal: Int,
        publicMaterialAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability,
        revocationArtifactAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability,
        handleAvailability: SecureEnclaveCustodyHandleAvailability,
        classicalComponentAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability? = nil
    ) {
        self.identityOrdinal = identityOrdinal
        self.publicMaterialAvailability = publicMaterialAvailability
        self.revocationArtifactAvailability = revocationArtifactAvailability
        self.handleAvailability = handleAvailability
        self.classicalComponentAvailability = classicalComponentAvailability
    }
}

enum SecureEnclaveCustodyRecoveryMaterialAvailability: Equatable, Sendable {
    case available
    case unavailable(PGPKeyOperationFailureCategory)
}
