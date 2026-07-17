import Foundation
import LocalAuthentication
@testable import CypherAir

/// In-memory root-secret store used by unit tests.
final class MockProtectedDataRootSecretStore: ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    struct StoredSecret {
        var data: Data
        var policy: AppSessionAuthenticationPolicy
    }

    private var storage: [String: StoredSecret] = [:]

    private(set) var loadCallCount = 0
    private(set) var lastAuthenticationContext: LAContext?

    var loadError: MockKeychainError?
    var throwOnDuplicate = true

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        if throwOnDuplicate && storage[identifier] != nil {
            throw MockKeychainError.duplicateItem
        }
        storage[identifier] = StoredSecret(data: secretData, policy: policy)
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        loadCallCount += 1
        lastAuthenticationContext = authenticationContext
        if let loadError {
            self.loadError = nil
            throw loadError
        }
        guard let storedSecret = storage[identifier] else {
            throw MockKeychainError.itemNotFound
        }
        return storedSecret.data
    }

    func deleteRootSecret(identifier: String) throws {
        guard storage.removeValue(forKey: identifier) != nil else {
            throw MockKeychainError.itemNotFound
        }
    }

    func rootSecretExists(identifier: String) -> Bool {
        storage[identifier] != nil
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = currentPolicy
        lastAuthenticationContext = authenticationContext
        guard var storedSecret = storage[identifier] else {
            throw MockKeychainError.itemNotFound
        }
        storedSecret.policy = newPolicy
        storage[identifier] = storedSecret
    }

}
