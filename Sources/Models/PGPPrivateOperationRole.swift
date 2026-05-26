import Foundation

/// Private-operation roles that must remain distinct for device-bound custody.
enum PGPPrivateOperationRole: String, CaseIterable, Codable, Hashable, Sendable {
    case signing
    case keyAgreement
}
