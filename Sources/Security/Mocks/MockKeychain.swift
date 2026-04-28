import Foundation
import LocalAuthentication
import Security

/// In-memory mock Keychain for testing.
/// Records all operations for verification in tests.
///
/// **Note on error types:** This mock throws `MockKeychainError`, which is a
/// different type from the production `KeychainError`. If consuming code uses
/// `catch let error as KeychainError` to distinguish error cases, mock errors
/// will not match. Currently `AuthenticationManager.switchMode` catches generic
/// `Error` and wraps it, so this is not a problem — but keep this in mind if
/// adding typed error handling in consuming code.
///
/// - Warning: Not thread-safe. Only use from test methods on a single actor.
final class MockKeychain: KeychainManageable, @unchecked Sendable {
    /// In-memory storage: key = "service:account"
    private var storage: [String: Data] = [:]

    /// Tracking flags for test verification.
    private(set) var saveCallCount = 0
    private(set) var loadCallCount = 0
    private(set) var deleteCallCount = 0
    private(set) var listItemsCallCount = 0
    private(set) var lastSavedService: String?
    private(set) var lastDeletedService: String?
    private(set) var loadCalls: [(service: String, account: String, hasAuthenticationContext: Bool)] = []
    private(set) var listItemsCalls: [(servicePrefix: String, account: String, hasAuthenticationContext: Bool)] = []

    /// If set, the next save operation will throw this error (one-shot).
    var saveError: Error?
    /// If set, the next load operation will throw this error (one-shot).
    var loadError: Error?
    /// If set, the next delete operation will throw this error (one-shot).
    var deleteError: Error?
    /// If set, the next list operation will throw this error (one-shot).
    var listItemsError: Error?

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
        lastSavedService = service
        storage[key] = data
    }

    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data {
        loadCallCount += 1
        loadCalls.append(
            (
                service: service,
                account: account,
                hasAuthenticationContext: authenticationContext != nil
            )
        )
        if let error = loadError {
            loadError = nil
            throw error
        }
        let key = storageKey(service: service, account: account)
        guard let data = storage[key] else {
            throw MockKeychainError.itemNotFound
        }
        return data
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
        lastDeletedService = service
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
        if let error = listItemsError {
            listItemsError = nil
            throw error
        }
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
        loadError = nil
        deleteError = nil
        listItemsError = nil
        throwOnDuplicate = true
        failOnSaveNumber = 0
        failOnDeleteNumber = 0
    }

    func resetCallHistory() {
        saveCallCount = 0
        loadCallCount = 0
        deleteCallCount = 0
        listItemsCallCount = 0
        lastSavedService = nil
        lastDeletedService = nil
        loadCalls.removeAll()
        listItemsCalls.removeAll()
    }
}

enum MockKeychainError: Error {
    case itemNotFound
    case duplicateItem
    case saveFailed
    case deleteFailed
}

/// In-memory root-secret store used by unit tests and UI-test containers.
final class MockProtectedDataRootSecretStore: ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    struct StoredSecret {
        var data: Data
        var policy: AppSessionAuthenticationPolicy
    }

    private var storage: [String: StoredSecret] = [:]

    private(set) var saveCallCount = 0
    private(set) var loadCallCount = 0
    private(set) var deleteCallCount = 0
    private(set) var existsCallCount = 0
    private(set) var reprotectCallCount = 0
    private(set) var lastLoadedIdentifier: String?
    private(set) var lastAuthenticationContext: LAContext?

    var saveError: Error?
    var loadError: Error?
    var deleteError: Error?
    var reprotectError: Error?
    var throwOnDuplicate = true

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        saveCallCount += 1
        if let saveError {
            self.saveError = nil
            throw saveError
        }
        if throwOnDuplicate && storage[identifier] != nil {
            throw MockKeychainError.duplicateItem
        }
        storage[identifier] = StoredSecret(data: secretData, policy: policy)
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        minimumEnvelopeVersion: Int?
    ) throws -> ProtectedDataRootSecretLoadResult {
        _ = minimumEnvelopeVersion
        loadCallCount += 1
        lastLoadedIdentifier = identifier
        lastAuthenticationContext = authenticationContext
        if let loadError {
            self.loadError = nil
            throw loadError
        }
        guard let storedSecret = storage[identifier] else {
            throw KeychainError.itemNotFound
        }
        return ProtectedDataRootSecretLoadResult(
            secretData: storedSecret.data,
            storageFormat: .envelopeV2,
            didMigrate: false
        )
    }

    func deleteRootSecret(identifier: String) throws {
        deleteCallCount += 1
        if let deleteError {
            self.deleteError = nil
            throw deleteError
        }
        guard storage.removeValue(forKey: identifier) != nil else {
            throw KeychainError.itemNotFound
        }
    }

    func rootSecretExists(identifier: String) -> Bool {
        existsCallCount += 1
        return storage[identifier] != nil
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = currentPolicy
        reprotectCallCount += 1
        lastAuthenticationContext = authenticationContext
        if let reprotectError {
            self.reprotectError = nil
            throw reprotectError
        }
        guard var storedSecret = storage[identifier] else {
            throw KeychainError.itemNotFound
        }
        storedSecret.policy = newPolicy
        storage[identifier] = storedSecret
    }

    func storedPolicy(identifier: String) -> AppSessionAuthenticationPolicy? {
        storage[identifier]?.policy
    }

    func reset() {
        storage.removeAll()
        saveCallCount = 0
        loadCallCount = 0
        deleteCallCount = 0
        existsCallCount = 0
        reprotectCallCount = 0
        lastLoadedIdentifier = nil
        lastAuthenticationContext = nil
        saveError = nil
        loadError = nil
        deleteError = nil
        reprotectError = nil
        throwOnDuplicate = true
    }
}
