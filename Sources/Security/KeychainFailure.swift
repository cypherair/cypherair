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
}
