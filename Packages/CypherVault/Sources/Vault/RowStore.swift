import Foundation
import Security

/// Rows under one service: an opaque value plus an optional public attribute
/// readable without the value, used for custody handle bindings. Production is
/// the data-protection Keychain; tests keep rows in memory.
public protocol RowStore: Sendable {
    func read(account: String) throws(VaultError) -> Data?
    /// Creates the row, or replaces its value and attribute atomically.
    func write(account: String, data: Data, attribute: Data?) throws(VaultError)
    func delete(account: String) throws(VaultError)
    /// Every account under the service with its public attribute, no values.
    func accounts() throws(VaultError) -> [(account: String, attribute: Data?)]
}

public extension RowStore {
    func write(account: String, data: Data) throws(VaultError) {
        try write(account: account, data: data, attribute: nil)
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

    public func write(account: String, data: Data, attribute: Data?) throws(VaultError) {
        var update: [String: Any] = [kSecValueData as String: data]
        update[kSecAttrGeneric as String] = attribute ?? Data()
        let updateStatus = SecItemUpdate(base(account: account) as CFDictionary, update as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var attributes = base(account: account)
            attributes[kSecValueData as String] = data
            attributes[kSecAttrGeneric as String] = attribute ?? Data()
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

    public func accounts() throws(VaultError) -> [(account: String, attribute: Data?)] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        #if os(macOS)
        query[kSecAttrSynchronizable as String] = false
        #endif
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            return (result as? [[String: Any]])?.compactMap { row in
                guard let account = row[kSecAttrAccount as String] as? String else { return nil }
                let attribute = row[kSecAttrGeneric as String] as? Data
                return (account, attribute.flatMap { $0.isEmpty ? nil : $0 })
            } ?? []
        case errSecItemNotFound:
            return []
        default:
            throw .storage("list failed: \(status)")
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
