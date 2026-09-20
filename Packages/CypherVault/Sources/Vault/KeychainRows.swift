import Foundation
import Security

/// Plain rows in the data-protection Keychain: passcode-set, this-device-only,
/// never synchronized, no access control. Every gate is an enclave key, so a row
/// is only ever an inert blob.
public struct KeychainRows: Sendable {
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

    /// Creates the row, or replaces its value atomically if it exists.
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

    /// Every account under this service.
    public func accounts() throws(VaultError) -> [String] {
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
            return (result as? [[String: Any]])?.compactMap { $0[kSecAttrAccount as String] as? String } ?? []
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
