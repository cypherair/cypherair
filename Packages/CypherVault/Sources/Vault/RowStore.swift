import Foundation
import Security

/// Rows under one service, each an opaque value. A row has no attribute of its
/// own, so nothing about it is readable but its name and the public fields of
/// its value. Production is the data-protection Keychain; tests keep rows in
/// memory.
public protocol RowStore: Sendable {
    func read(account: String) throws(VaultError) -> Data?
    /// Creates the row, or replaces its value atomically.
    func write(account: String, data: Data) throws(VaultError)
    func delete(account: String) throws(VaultError)
}

/// Every Keychain item of the app, across services.
public protocol Keychain: Sendable {
    func rows(service: String) -> any RowStore
    /// Deletes every item of the app, whatever its service or name. Part of
    /// Reset All Local Data.
    func deleteEverything() throws(VaultError)
}

/// The app's items in the data-protection Keychain.
public struct SystemKeychain: Keychain {
    public init() {}

    public func rows(service: String) -> any RowStore {
        KeychainRowStore(service: service)
    }

    public func deleteEverything() throws(VaultError) {
        let classes = [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey, kSecClassIdentity]
        for itemClass in classes {
            let query: [String: Any] = [
                kSecClass as String: itemClass,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            ]
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw .storage("delete failed: \(status)")
            }
        }
    }
}

/// Plain rows in the data-protection Keychain: passcode-set, this-device-only,
/// never synchronized, no access control. Every gate is an enclave key, so a row
/// is only ever an inert blob.
public struct KeychainRowStore: RowStore {
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public func read(account: String) throws(VaultError) -> Data? {
        var query = base(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw .storage("row without data") }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw .storage("read failed: \(status)")
        }
    }

    public func write(account: String, data: Data) throws(VaultError) {
        let update: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(base(account: account) as CFDictionary, update as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var attributes = base(account: account)
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            let status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else { throw .storage("add failed: \(status)") }
        default:
            throw .storage("update failed: \(updateStatus)")
        }
    }

    public func delete(account: String) throws(VaultError) {
        let status = SecItemDelete(base(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw .storage("delete failed: \(status)")
        }
    }

    private func base(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        #if os(macOS)
        query[kSecAttrSynchronizable as String] = false
        #endif
        return query
    }
}
