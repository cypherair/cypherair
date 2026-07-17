import Foundation

/// App-owned private-operation vocabulary used by custody routing.
enum PGPPrivateOperationKind: String, CaseIterable, Codable, Hashable, Sendable {
    case sign
    case decrypt
    case certify
    case revoke
    case modifyExpiry

    var keyOperationKind: PGPKeyOperationKind {
        switch self {
        case .sign:
            .sign
        case .decrypt:
            .decrypt
        case .certify:
            .certify
        case .revoke:
            .revoke
        case .modifyExpiry:
            .modifyExpiry
        }
    }

    var requiredRole: PGPPrivateOperationRole {
        switch self {
        case .decrypt:
            .keyAgreement
        case .sign,
             .certify,
             .revoke,
             .modifyExpiry:
            .signing
        }
    }
}
