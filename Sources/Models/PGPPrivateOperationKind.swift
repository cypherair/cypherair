import Foundation

/// App-owned private-operation vocabulary used by custody routing.
enum PGPPrivateOperationKind: String, CaseIterable, Codable, Hashable, Sendable {
    case sign
    case decrypt
    case certify
    case revoke
    case modifyExpiry
    case refreshBinding

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
        case .refreshBinding:
            .refreshBinding
        }
    }

    var requiredRole: PGPPrivateOperationRole {
        switch self {
        case .decrypt:
            .keyAgreement
        case .sign,
             .certify,
             .revoke,
             .modifyExpiry,
             .refreshBinding:
            .signing
        }
    }
}
