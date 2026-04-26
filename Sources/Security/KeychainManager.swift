import Foundation
import LocalAuthentication
import Security

/// Errors from Keychain operations.
enum KeychainError: Error, Equatable {
    /// The item was not found in the Keychain (errSecItemNotFound).
    case itemNotFound
    /// A duplicate item already exists (errSecDuplicateItem).
    case duplicateItem
    /// User cancelled the authentication prompt (errSecUserCanceled).
    case userCancelled
    /// Authentication failed (errSecAuthFailed).
    case authenticationFailed
    /// UI interaction was required but the supplied context forbade it.
    case interactionNotAllowed
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
    private let traceStore: AuthLifecycleTraceStore?

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    func save(_ data: Data, service: String, account: String, accessControl: SecAccessControl?) throws {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: service)
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "keychain.save.start",
            metadata: [
                "serviceKind": serviceKind,
                "accountKind": accountKind,
                "accessControl": accessControl == nil ? "false" : "true"
            ]
        )
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecUseDataProtectionKeychain as String: true
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
        traceStore?.record(
            category: .operation,
            name: "keychain.save.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: ["serviceKind": serviceKind, "accountKind": accountKind]
            )
        )

        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicateItem
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func load(service: String, account: String, authenticationContext: LAContext?) throws -> Data {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: service)
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "keychain.load.start",
            metadata: [
                "serviceKind": serviceKind,
                "accountKind": accountKind,
                "hasAuthenticationContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        traceStore?.record(
            category: .operation,
            name: "keychain.load.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: ["serviceKind": serviceKind, "accountKind": accountKind]
            )
        )

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
        case errSecInteractionNotAllowed:
            throw KeychainError.interactionNotAllowed
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func delete(service: String, account: String, authenticationContext: LAContext?) throws {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: service)
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "keychain.delete.start",
            metadata: [
                "serviceKind": serviceKind,
                "accountKind": accountKind,
                "hasAuthenticationContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }

        let status = SecItemDelete(query as CFDictionary)
        traceStore?.record(
            category: .operation,
            name: "keychain.delete.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: ["serviceKind": serviceKind, "accountKind": accountKind]
            )
        )

        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        case errSecUserCanceled:
            throw KeychainError.userCancelled
        case errSecAuthFailed:
            throw KeychainError.authenticationFailed
        case errSecInteractionNotAllowed:
            throw KeychainError.interactionNotAllowed
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func exists(service: String, account: String, authenticationContext: LAContext?) -> Bool {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: service)
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "keychain.exists.start",
            metadata: [
                "serviceKind": serviceKind,
                "accountKind": accountKind,
                "hasAuthenticationContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        traceStore?.record(
            category: .operation,
            name: "keychain.exists.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: [
                    "serviceKind": serviceKind,
                    "accountKind": accountKind,
                    "exists": status == errSecSuccess ? "true" : "false"
                ]
            )
        )
        return status == errSecSuccess
    }

    func listItems(servicePrefix: String, account: String, authenticationContext: LAContext?) throws -> [String] {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(forPrefix: servicePrefix)
        let accountKind = AuthTraceMetadata.keychainAccountKind(for: account)
        traceStore?.record(
            category: .operation,
            name: "keychain.listItems.start",
            metadata: [
                "serviceKind": serviceKind,
                "accountKind": accountKind,
                "hasAuthenticationContext": authenticationContext == nil ? "false" : "true"
            ]
        )
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else {
                traceStore?.record(
                    category: .operation,
                    name: "keychain.listItems.finish",
                    metadata: AuthTraceMetadata.statusMetadata(
                        status,
                        extra: [
                            "serviceKind": serviceKind,
                            "accountKind": accountKind,
                            "result": "invalidResult",
                            "count": "0"
                        ]
                    )
                )
                return []
            }
            let services: [String] = items.compactMap { item -> String? in
                guard let service = item[kSecAttrService as String] as? String,
                      service.hasPrefix(servicePrefix) else { return nil }
                return service
            }
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: [
                        "serviceKind": serviceKind,
                        "accountKind": accountKind,
                        "count": String(services.count)
                    ]
                )
            )
            return services
        case errSecItemNotFound:
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: ["serviceKind": serviceKind, "accountKind": accountKind, "count": "0"]
                )
            )
            return []
        case errSecUserCanceled:
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: ["serviceKind": serviceKind, "accountKind": accountKind]
                )
            )
            throw KeychainError.userCancelled
        case errSecAuthFailed:
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: ["serviceKind": serviceKind, "accountKind": accountKind]
                )
            )
            throw KeychainError.authenticationFailed
        case errSecInteractionNotAllowed:
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: ["serviceKind": serviceKind, "accountKind": accountKind]
                )
            )
            throw KeychainError.interactionNotAllowed
        default:
            traceStore?.record(
                category: .operation,
                name: "keychain.listItems.finish",
                metadata: AuthTraceMetadata.statusMetadata(
                    status,
                    extra: ["serviceKind": serviceKind, "accountKind": accountKind]
                )
            )
            throw KeychainError.unhandledError(status)
        }
    }
}
