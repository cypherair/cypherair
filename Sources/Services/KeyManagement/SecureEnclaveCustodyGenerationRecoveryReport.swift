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
    let configurationIdentity: PGPKeyConfiguration.Identity
    let publicMaterialAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability
    let revocationArtifactAvailability: SecureEnclaveCustodyRecoveryMaterialAvailability
    let handleAvailability: SecureEnclaveCustodyHandleAvailability
}

enum SecureEnclaveCustodyRecoveryMaterialAvailability: Equatable, Sendable {
    case available
    case unavailable(PGPKeyOperationFailureCategory)
}
