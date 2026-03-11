import Foundation
import Security

/// Errors from Keychain operations.
enum KeychainError: Error {
    /// The item was not found in the Keychain (errSecItemNotFound).
    case itemNotFound
    /// A duplicate item already exists (errSecDuplicateItem).
    case duplicateItem
    /// User cancelled the authentication prompt (errSecUserCanceled).
    case userCancelled
    /// Authentication failed (errSecAuthFailed).
    case authenticationFailed
    /// An unspecified Keychain error occurred.
    case unhandledError(OSStatus)
}

/// Production Keychain implementation using Security.framework.
///
/// All items use `kSecClassGenericPassword` with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` to ensure:
/// - Items are only accessible while the device is unlocked.
/// - Items are not included in backups or migrated to other devices.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 7.
struct SystemKeychain: KeychainManageable {

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]

        // kSecAttrAccessControl and kSecAttrAccessible are mutually exclusive.
        // When accessControl is provided (SE key items), it embeds the accessibility level.
        // When nil (salt, sealed box), use kSecAttrAccessible directly.
        if let accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        let status = SecItemAdd(query as CFDictionary, nil)

        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicateItem
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func load(service: String, account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.unhandledError(errSecInternalError)
            }
            return data
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        case errSecUserCanceled:
            throw KeychainError.userCancelled
        case errSecAuthFailed:
            throw KeychainError.authenticationFailed
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func delete(service: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let status = SecItemDelete(query as CFDictionary)

        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func exists(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
