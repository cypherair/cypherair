import Foundation

enum KeychainFailureKind: Equatable, Sendable {
    case itemNotFound
    case duplicateItem
    case userCancelled
    case authenticationFailed
    case interactionNotAllowed
    case unhandled
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
}
