import Foundation
import LocalAuthentication
import Security

enum ProtectedDataRightIdentifiers {
    static let productionSharedRightIdentifier = "com.cypherair.protected-data.shared-right.v1"
}

protocol ProtectedDataRootSecretStoreProtocol: AnyObject {
    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data

    func deleteRootSecret(identifier: String) throws
    func rootSecretExists(identifier: String) -> Bool

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws
}

final class KeychainProtectedDataRootSecretStore: ProtectedDataRootSecretStoreProtocol {
    private let account: String

    init(account: String = KeychainConstants.defaultAccount) {
        self.account = account
    }

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        var query = baseQuery(identifier: identifier)
        query[kSecValueData as String] = secretData
        query[kSecAttrAccessControl as String] = try policy.createRootSecretAccessControl()

        let status = SecItemAdd(query as CFDictionary, nil)
        try handleMutationStatus(status)
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        var query = baseQuery(identifier: identifier)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = authenticationContext

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
        case errSecInteractionNotAllowed:
            throw KeychainError.interactionNotAllowed
        default:
            throw KeychainError.unhandledError(status)
        }
    }

    func deleteRootSecret(identifier: String) throws {
        let status = SecItemDelete(baseQuery(identifier: identifier) as CFDictionary)
        try handleMutationStatus(status)
    }

    func rootSecretExists(identifier: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        var query = baseQuery(identifier: identifier)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
            || status == errSecInteractionNotAllowed
            || status == errSecAuthFailed
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = currentPolicy
        var originalSecret = try loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticationContext
        )
        defer {
            originalSecret.protectedDataZeroize()
        }

        var query = baseQuery(identifier: identifier)
        query[kSecUseAuthenticationContext as String] = authenticationContext
        let attributes: [String: Any] = [
            kSecAttrAccessControl as String: try newPolicy.createRootSecretAccessControl()
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        try handleMutationStatus(status)

        var verifiedSecret = try loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticationContext
        )
        defer {
            verifiedSecret.protectedDataZeroize()
        }

        guard verifiedSecret == originalSecret else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.rootSecretVerification",
                    defaultValue: "The protected app data root secret could not be verified after updating its access policy."
                )
            )
        }
    }

    private func baseQuery(identifier: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: identifier,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func handleMutationStatus(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw KeychainError.duplicateItem
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
}

protocol ProtectedDataPersistedRightHandle: AnyObject {
    var identifier: String { get }
    func authorize(localizedReason: String) async throws
    func deauthorize() async
    func rawSecretData() async throws -> Data
}

protocol ProtectedDataRightStoreClientProtocol: AnyObject {
    func right(forIdentifier identifier: String) async throws -> any ProtectedDataPersistedRightHandle
    func saveRight(_ right: LARight, identifier: String) async throws -> any ProtectedDataPersistedRightHandle
    func saveRight(_ right: LARight, identifier: String, secret: Data) async throws -> any ProtectedDataPersistedRightHandle
    func removeRight(forIdentifier identifier: String) async throws
}

final class ProtectedDataRightStoreClient: ProtectedDataRightStoreClientProtocol {
    private let rightStore: LARightStore

    init(rightStore: LARightStore = .shared) {
        self.rightStore = rightStore
    }

    func right(forIdentifier identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        let right = try await rightStore.right(forIdentifier: identifier)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: right)
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        let savedRight = try await rightStore.saveRight(right, identifier: identifier)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: savedRight)
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any ProtectedDataPersistedRightHandle {
        let savedRight = try await rightStore.saveRight(right, identifier: identifier, secret: secret)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: savedRight)
    }

    func removeRight(forIdentifier identifier: String) async throws {
        try await rightStore.removeRight(forIdentifier: identifier)
    }
}

private final class LocalAuthenticationPersistedRightHandle: ProtectedDataPersistedRightHandle {
    let identifier: String
    private let right: LAPersistedRight

    init(identifier: String, right: LAPersistedRight) {
        self.identifier = identifier
        self.right = right
    }

    func authorize(localizedReason: String) async throws {
        try await right.authorize(localizedReason: localizedReason)
    }

    func deauthorize() async {
        await right.deauthorize()
    }

    func rawSecretData() async throws -> Data {
        try await right.secret.rawData
    }
}
