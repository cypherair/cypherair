import Foundation
import LocalAuthentication
import Security

enum ProtectedDataRightIdentifiers {
    static let productionSharedRightIdentifier = "com.cypherair.v5.protected-data.shared-right"
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
    private let deviceBindingProvider: any ProtectedDataDeviceBindingProvider

    init(
        account: String = KeychainConstants.defaultAccount,
        deviceBindingProvider: (any ProtectedDataDeviceBindingProvider)? = nil
    ) {
        self.account = account
        self.deviceBindingProvider = deviceBindingProvider ?? HardwareProtectedDataDeviceBindingProvider()
    }

    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws {
        let envelope = try deviceBindingProvider.sealRootSecret(
            secretData,
            sharedRightIdentifier: identifier
        )
        let encodedEnvelope = try ProtectedDataRootSecretEnvelopeCodec.encode(envelope)
        var query = baseQuery(identifier: identifier)
        query[kSecValueData as String] = encodedEnvelope
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
            guard var payload = result as? Data else {
                throw KeychainError.unhandledError(errSecInternalError)
            }
            defer {
                payload.protectedDataZeroize()
            }
            return try openRootSecretPayload(payload, identifier: identifier)
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

    private func openRootSecretPayload(
        _ payload: Data,
        identifier: String
    ) throws -> Data {
        let envelope = try ProtectedDataRootSecretEnvelopeCodec.decode(
            payload,
            expectedSharedRightIdentifier: identifier
        )
        return try deviceBindingProvider.openRootSecret(
            envelope: envelope,
            expectedSharedRightIdentifier: identifier
        )
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
