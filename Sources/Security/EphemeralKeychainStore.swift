import Foundation
import LocalAuthentication
import Security

/// Errors from the ephemeral keychain store.
///
/// Containment: this is the store's own error type. It classifies through
/// `KeychainFailureRepresentable` and never impersonates the production
/// `KeychainError`, so shared logic cannot mistake an ephemeral-store failure
/// for a Security.framework one.
enum EphemeralKeychainStoreError: Error, KeychainFailureRepresentable {
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

/// In-memory keychain for ephemeral sandboxes: the guided tutorial dependency
/// graph and the DEBUG UI-test container.
///
/// Reproduces the real Keychain's row semantics — saving an existing
/// (service, account) throws a duplicate-item error, and load/update/delete of
/// a missing row throws item-not-found — so production callers exercise their
/// real error paths. Rows exist only in process memory: nothing reaches the
/// system keychain, and `wipe()` zeroizes every stored payload before dropping
/// it. Access control and authentication contexts are accepted and ignored;
/// prompting is a production behavior the ephemeral sandbox does not reproduce.
///
/// - Warning: Not thread-safe. Confine to a single actor, matching the
///   container lifecycles that own it.
final class EphemeralKeychainStore: KeychainManageable, @unchecked Sendable {
    /// In-memory storage: key = "service:account".
    private var storage: [String: Data] = [:]

    private func storageKey(service: String, account: String) -> String {
        "\(service):\(account)"
    }

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        let key = storageKey(service: service, account: account)
        guard storage[key] == nil else {
            throw EphemeralKeychainStoreError.duplicateItem
        }
        storage[key] = data
    }

    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data {
        guard let data = storage[storageKey(service: service, account: account)] else {
            throw EphemeralKeychainStoreError.itemNotFound
        }
        return data
    }

    func update(_ data: Data, service: String, account: String, authenticationContext: LAContext?) throws {
        let key = storageKey(service: service, account: account)
        guard storage[key] != nil else {
            throw EphemeralKeychainStoreError.itemNotFound
        }
        storage[key] = data
    }

    func delete(service: String, account: String, authenticationContext: LAContext?) throws {
        guard storage.removeValue(forKey: storageKey(service: service, account: account)) != nil else {
            throw EphemeralKeychainStoreError.itemNotFound
        }
    }

    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool {
        storage[storageKey(service: service, account: account)] != nil
    }

    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String] {
        let suffix = ":\(account)"
        return storage.keys.compactMap { key in
            guard key.hasSuffix(suffix) else { return nil }
            let service = String(key.dropLast(suffix.count))
            guard service.hasPrefix(servicePrefix) else { return nil }
            return service
        }
    }

    /// Zeroize every stored payload, then remove all rows. Called from the
    /// owning container's cleanup so envelope rows and ProtectedData support
    /// rows do not linger in memory after the sandbox ends.
    func wipe() {
        for key in storage.keys {
            storage[key]?.zeroize()
        }
        storage.removeAll()
    }
}
