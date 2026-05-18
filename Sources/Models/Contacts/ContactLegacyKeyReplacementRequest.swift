import Foundation

struct ContactLegacyKeyReplacementRequest: Equatable, Sendable {
    let newContact: ContactIdentitySummary
    let newKey: ContactKeySummary
    let existingContact: ContactIdentitySummary
    let existingKey: ContactKeySummary
    let keyData: Data
}
