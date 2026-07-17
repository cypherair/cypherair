#if DEBUG
import Foundation
import LocalAuthentication

/// Errors from the ephemeral root-secret store.
///
/// Containment: the store's own error type, classified through
/// `KeychainFailureRepresentable`; it never impersonates the production
/// `KeychainError`.
enum EphemeralProtectedDataRootSecretStoreError: Error, KeychainFailureRepresentable {
    case itemNotFound
    case duplicateItem

    var keychainFailureKind: KeychainFailureKind {
        switch self {
        case .itemNotFound:
            .itemNotFound
        case .duplicateItem:
            .duplicateItem
        }
    }
}

/// In-memory ProtectedData root-secret store for the DEBUG UI-test container.
///
/// The production `KeychainProtectedDataRootSecretStore` persists an
/// access-controlled system-keychain row bound to the device; a UI-test app
/// session needs the same save/load/exists/reprotect surface with real
/// duplicate/not-found semantics but promptless access and zero rows outside
/// process memory. Compiled only in DEBUG; `AppContainer.makeUITest` is its
/// only consumer.
final class EphemeralProtectedDataRootSecretStore: ProtectedDataRootSecretStoreProtocol, @unchecked Sendable {
    private struct StoredSecret {
        var data: Data
        var policy: AppSessionAuthenticationPolicy
    }

    private var storage: [String: StoredSecret] = [:]

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        guard storage[identifier] == nil else {
            throw EphemeralProtectedDataRootSecretStoreError.duplicateItem
        }
        storage[identifier] = StoredSecret(data: secretData, policy: policy)
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        guard let storedSecret = storage[identifier] else {
            throw EphemeralProtectedDataRootSecretStoreError.itemNotFound
        }
        return storedSecret.data
    }

    func deleteRootSecret(identifier: String) throws {
        guard storage.removeValue(forKey: identifier) != nil else {
            throw EphemeralProtectedDataRootSecretStoreError.itemNotFound
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
        guard var storedSecret = storage[identifier] else {
            throw EphemeralProtectedDataRootSecretStoreError.itemNotFound
        }
        storedSecret.policy = newPolicy
        storage[identifier] = storedSecret
    }
}
#endif
