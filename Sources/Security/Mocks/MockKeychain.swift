import Foundation
import Security

/// In-memory mock Keychain for testing.
/// Records all operations for verification in tests.
final class MockKeychain: KeychainManageable {
    /// In-memory storage: key = "service:account"
    private var storage: [String: Data] = [:]

    /// Tracking flags for test verification.
    private(set) var saveCallCount = 0
    private(set) var loadCallCount = 0
    private(set) var deleteCallCount = 0
    private(set) var lastSavedService: String?
    private(set) var lastDeletedService: String?

    /// If set, the next save operation will throw this error.
    var saveError: Error?
    /// If set, the next load operation will throw this error.
    var loadError: Error?

    /// When true (default), saving to an existing key throws `duplicateItem`,
    /// matching real Keychain behavior (`errSecDuplicateItem`).
    /// Set to false only when testing code that intentionally overwrites.
    var throwOnDuplicate = true

    private func storageKey(service: String, account: String) -> String {
        "\(service):\(account)"
    }

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        if let error = saveError {
            saveError = nil
            throw error
        }
        let key = storageKey(service: service, account: account)
        if throwOnDuplicate && storage[key] != nil {
            throw MockKeychainError.duplicateItem
        }
        saveCallCount += 1
        lastSavedService = service
        storage[key] = data
    }

    func load(service: String, account: String) throws -> Data {
        if let error = loadError {
            loadError = nil
            throw error
        }
        loadCallCount += 1
        let key = storageKey(service: service, account: account)
        guard let data = storage[key] else {
            throw MockKeychainError.itemNotFound
        }
        return data
    }

    func delete(service: String, account: String) throws {
        deleteCallCount += 1
        lastDeletedService = service
        let key = storageKey(service: service, account: account)
        // Match real Keychain behavior: throw if item doesn't exist (errSecItemNotFound)
        guard storage.removeValue(forKey: key) != nil else {
            throw MockKeychainError.itemNotFound
        }
    }

    func exists(service: String, account: String) -> Bool {
        storage[storageKey(service: service, account: account)] != nil
    }

    /// Reset all state for clean test setup.
    func reset() {
        storage.removeAll()
        saveCallCount = 0
        loadCallCount = 0
        deleteCallCount = 0
        lastSavedService = nil
        lastDeletedService = nil
        saveError = nil
        loadError = nil
        throwOnDuplicate = true
    }
}

enum MockKeychainError: Error {
    case itemNotFound
    case duplicateItem
}
