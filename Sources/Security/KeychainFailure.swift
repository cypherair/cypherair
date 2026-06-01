import Foundation

enum KeychainFailureKind: Equatable, Sendable {
    case itemNotFound
    case duplicateItem
    case userCancelled
    case authenticationFailed
    case interactionNotAllowed
    case unhandled

    var isAuthorizationCancellationOrDenial: Bool {
        switch self {
        case .userCancelled, .authenticationFailed, .interactionNotAllowed:
            return true
        case .itemNotFound, .duplicateItem, .unhandled:
            return false
        }
    }

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
        case .unhandled:
            return "unhandled"
        }
    }
}

protocol KeychainFailureRepresentable: Error {
    var keychainFailureKind: KeychainFailureKind { get }
}

enum KeychainFailureClassifier {
    static func kind(for error: Error) -> KeychainFailureKind? {
        (error as? any KeychainFailureRepresentable)?.keychainFailureKind
    }

    static func isItemNotFound(_ error: Error) -> Bool {
        kind(for: error) == .itemNotFound
    }

    static func isDuplicateItem(_ error: Error) -> Bool {
        kind(for: error) == .duplicateItem
    }

    static func isAuthorizationCancellationOrDenial(_ error: Error) -> Bool {
        kind(for: error)?.isAuthorizationCancellationOrDenial == true
    }

    static func traceName(for error: Error) -> String? {
        if let keychainError = error as? KeychainError {
            return keychainError.traceName
        }
        return kind(for: error)?.traceName
    }
}
