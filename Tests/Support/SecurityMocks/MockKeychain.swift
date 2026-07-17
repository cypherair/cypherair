import Foundation
import LocalAuthentication
import Security
@testable import CypherAir

/// In-memory mock Keychain for testing.
/// Records all operations for verification in tests.
///
/// **Note on error types:** This mock throws `MockKeychainError`, not the
/// production `KeychainError`. Shared production logic must classify keychain
/// failures through `KeychainFailureRepresentable` rather than checking this
/// concrete mock error type.
///
/// - Warning: Not thread-safe. Only use from test methods on a single actor.
final class MockKeychain: KeychainManageable, @unchecked Sendable {
    /// In-memory storage: key = "service:account"
    private var storage: [String: Data] = [:]

    /// Tracking flags for test verification.
    private(set) var saveCallCount = 0
    private(set) var deleteCallCount = 0
    private(set) var listItemsCallCount = 0
    private(set) var loadCalls: [(service: String, account: String, hasAuthenticationContext: Bool)] = []
    private(set) var saveCalls: [(service: String, account: String, hasAccessControl: Bool)] = []
    private(set) var updateCalls: [(service: String, account: String, hasAuthenticationContext: Bool)] = []
    private(set) var listItemsCalls: [(servicePrefix: String, account: String, hasAuthenticationContext: Bool)] = []

    /// If set, the next save operation will throw this error (one-shot).
    var saveError: MockKeychainError?
    /// If set, the next delete operation will throw this error (one-shot).
    var deleteError: MockKeychainError?

    /// If non-zero, the save at this call count (1-based) will throw `saveError ?? MockKeychainError.saveFailed`.
    /// Example: `failOnSaveNumber = 4` means the 4th save call will fail.
    var failOnSaveNumber: Int = 0

    /// When true (default), saving to an existing key throws `duplicateItem`,
    /// matching real Keychain behavior (`errSecDuplicateItem`).
    /// Set to false only when testing code that intentionally overwrites.
    var throwOnDuplicate = true

    /// If non-zero, the delete at this call count (1-based) will throw
    /// `deleteError ?? MockKeychainError.deleteFailed`.
    var failOnDeleteNumber: Int = 0

    private func storageKey(service: String, account: String) -> String {
        "\(service):\(account)"
    }

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        // Increment FIRST so saveCallCount reflects every save attempt,
        // including those that throw (duplicate, saveError, failOnSaveNumber).
        // This matches real Keychain semantics where a duplicate is still an API call.
        saveCallCount += 1
        if let error = saveError {
            saveError = nil
            throw error
        }
        let key = storageKey(service: service, account: account)
        if throwOnDuplicate && storage[key] != nil {
            throw MockKeychainError.duplicateItem
        }
        // Fail on specific save call number (1-based).
        if failOnSaveNumber > 0 && saveCallCount == failOnSaveNumber {
            throw MockKeychainError.saveFailed
        }
        saveCalls.append((service: service, account: account, hasAccessControl: accessControl != nil))
        storage[key] = data
    }

    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data {
        loadCalls.append(
            (
                service: service,
                account: account,
                hasAuthenticationContext: authenticationContext != nil
            )
        )
        let key = storageKey(service: service, account: account)
        guard let data = storage[key] else {
            throw MockKeychainError.itemNotFound
        }
        return data
    }

    func update(_ data: Data, service: String, account: String, authenticationContext: LAContext?) throws {
        updateCalls.append(
            (
                service: service,
                account: account,
                hasAuthenticationContext: authenticationContext != nil
            )
        )
        if let error = saveError {
            saveError = nil
            throw error
        }
        let key = storageKey(service: service, account: account)
        guard storage[key] != nil else {
            throw MockKeychainError.itemNotFound
        }
        storage[key] = data
    }

    func delete(service: String, account: String, authenticationContext: LAContext?) throws {
        _ = authenticationContext
        deleteCallCount += 1
        if let error = deleteError {
            deleteError = nil
            throw error
        }
        if failOnDeleteNumber > 0 && deleteCallCount == failOnDeleteNumber {
            throw MockKeychainError.deleteFailed
        }
        let key = storageKey(service: service, account: account)
        // Match real Keychain behavior: throw if item doesn't exist (errSecItemNotFound)
        guard storage.removeValue(forKey: key) != nil else {
            throw MockKeychainError.itemNotFound
        }
    }

    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool {
        _ = authenticationContext
        return storage[storageKey(service: service, account: account)] != nil
    }

    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String] {
        listItemsCallCount += 1
        listItemsCalls.append(
            (
                servicePrefix: servicePrefix,
                account: account,
                hasAuthenticationContext: authenticationContext != nil
            )
        )
        let suffix = ":\(account)"
        return storage.keys.compactMap { key in
            guard key.hasSuffix(suffix) else { return nil }
            let service = String(key.dropLast(suffix.count))
            guard service.hasPrefix(servicePrefix) else { return nil }
            return service
        }
    }

    /// Reset all state for clean test setup.
    func reset() {
        storage.removeAll()
        resetCallHistory()
        saveError = nil
        deleteError = nil
        throwOnDuplicate = true
        failOnSaveNumber = 0
        failOnDeleteNumber = 0
    }

    func resetCallHistory() {
        saveCallCount = 0
        deleteCallCount = 0
        listItemsCallCount = 0
        loadCalls.removeAll()
        saveCalls.removeAll()
        updateCalls.removeAll()
        listItemsCalls.removeAll()
    }
}

enum MockKeychainError: Error, KeychainFailureRepresentable {
    case itemNotFound
    case duplicateItem
    case userCancelled
    case authenticationFailed
    case interactionNotAllowed
    case saveFailed
    case deleteFailed

    var keychainFailureKind: KeychainFailureKind {
        switch self {
        case .itemNotFound:
            .itemNotFound
        case .duplicateItem:
            .duplicateItem
        case .userCancelled:
            .userCancelled
        case .authenticationFailed:
            .authenticationFailed
        case .interactionNotAllowed:
            .interactionNotAllowed
        case .saveFailed, .deleteFailed:
            .unhandled
        }
    }
}
