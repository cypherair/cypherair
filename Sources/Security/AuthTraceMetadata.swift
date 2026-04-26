import Foundation
import LocalAuthentication
import Security

enum AuthTraceMetadata {
    static func keychainServiceKind(for service: String) -> String {
        if service.hasPrefix(KeychainConstants.metadataPrefix) {
            return "metadata"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).pending-se-key.") {
            return "pendingSeKey"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).pending-salt.") {
            return "pendingSalt"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).pending-sealed-key.") {
            return "pendingSealedKey"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).se-key.") {
            return "seKey"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).salt.") {
            return "salt"
        }
        if service.hasPrefix("\(KeychainConstants.prefix).sealed-key.") {
            return "sealedKey"
        }
        if service == ProtectedDataRightIdentifiers.productionSharedRightIdentifier {
            return "protectedDataRootSecret"
        }
        return "unknown"
    }

    static func keychainServiceKind(forPrefix servicePrefix: String) -> String {
        if servicePrefix == KeychainConstants.metadataPrefix {
            return "metadata"
        }
        if servicePrefix.hasPrefix(KeychainConstants.prefix) {
            return "cypherair"
        }
        return "unknown"
    }

    static func statusMetadata(_ status: OSStatus, extra: [String: String] = [:]) -> [String: String] {
        var metadata = extra
        metadata["status"] = String(status)
        metadata["statusName"] = statusName(status)
        return metadata
    }

    static func errorMetadata(_ error: Error, extra: [String: String] = [:]) -> [String: String] {
        var metadata = extra
        metadata["errorType"] = String(describing: type(of: error))
        if let keychainError = error as? KeychainError {
            metadata["keychainError"] = keychainError.traceName
        }
        if let laError = error as? LAError {
            metadata["laCode"] = String(laError.errorCode)
            metadata["laCodeName"] = String(describing: laError.code)
        }
        return metadata
    }

    static func statusName(_ status: OSStatus) -> String {
        switch status {
        case errSecSuccess:
            return "success"
        case errSecItemNotFound:
            return "itemNotFound"
        case errSecDuplicateItem:
            return "duplicateItem"
        case errSecUserCanceled:
            return "userCanceled"
        case errSecAuthFailed:
            return "authFailed"
        case errSecInteractionNotAllowed:
            return "interactionNotAllowed"
        case errSecInternalError:
            return "internalError"
        default:
            return "unhandled"
        }
    }
}

extension KeychainError {
    var traceName: String {
        switch self {
        case .itemNotFound:
            return "itemNotFound"
        case .duplicateItem:
            return "duplicateItem"
        case .userCancelled:
            return "userCancelled"
        case .authenticationFailed:
            return "authenticationFailed"
        case .interactionNotAllowed:
            return "interactionNotAllowed"
        case .unhandledError(let status):
            return "unhandledStatus.\(status)"
        }
    }
}
