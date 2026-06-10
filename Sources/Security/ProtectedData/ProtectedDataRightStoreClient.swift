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
    private let deviceBindingProvider: any ProtectedDataDeviceBindingProvider
    private let traceStore: AuthLifecycleTraceStore?

    init(
        account: String = KeychainConstants.defaultAccount,
        supportKeychain: (any KeychainManageable)? = nil,
        deviceBindingProvider: (any ProtectedDataDeviceBindingProvider)? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.account = account
        let supportKeychain = supportKeychain ?? SystemKeychain(traceStore: traceStore)
        self.deviceBindingProvider = deviceBindingProvider ?? HardwareProtectedDataDeviceBindingProvider(
            keychain: supportKeychain,
            account: account,
            traceStore: traceStore
        )
        self.traceStore = traceStore
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
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.save.start",
            metadata: [
                "serviceKind": "protectedDataRootSecret",
                "policy": policy.rawValue,
                "envelopeVersion": String(ProtectedDataRootSecretEnvelope.currentFormatVersion)
            ]
        )
        var query = baseQuery(identifier: identifier)
        query[kSecValueData as String] = encodedEnvelope
        query[kSecAttrAccessControl as String] = try policy.createRootSecretAccessControl()

        let status = SecItemAdd(query as CFDictionary, nil)
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.save.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: [
                    "serviceKind": "protectedDataRootSecret",
                    "policy": policy.rawValue,
                    "envelopeVersion": String(ProtectedDataRootSecretEnvelope.currentFormatVersion)
                ]
            )
        )
        try handleMutationStatus(status)
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.load.start",
            metadata: [
                "serviceKind": "protectedDataRootSecret",
                "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false"
            ]
        )
        var query = baseQuery(identifier: identifier)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = authenticationContext

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.load.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: [
                    "serviceKind": "protectedDataRootSecret",
                    "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false"
                ]
            )
        )

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
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.delete.start",
            metadata: ["serviceKind": "protectedDataRootSecret"]
        )
        let status = SecItemDelete(baseQuery(identifier: identifier) as CFDictionary)
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.delete.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: ["serviceKind": "protectedDataRootSecret"]
            )
        )
        try handleMutationStatus(status)
    }

    func rootSecretExists(identifier: String) -> Bool {
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.exists.start",
            metadata: ["serviceKind": "protectedDataRootSecret", "interactionNotAllowed": "true"]
        )
        let context = LAContext()
        context.interactionNotAllowed = true

        var query = baseQuery(identifier: identifier)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        let exists = status == errSecSuccess
            || status == errSecInteractionNotAllowed
            || status == errSecAuthFailed
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.exists.finish",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: [
                    "serviceKind": "protectedDataRootSecret",
                    "interactionNotAllowed": "true",
                    "exists": exists ? "true" : "false"
                ]
            )
        )
        return exists
    }

    func reprotectRootSecret(
        identifier: String,
        from currentPolicy: AppSessionAuthenticationPolicy,
        to newPolicy: AppSessionAuthenticationPolicy,
        authenticationContext: LAContext
    ) throws {
        _ = currentPolicy
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.reprotect.start",
            metadata: [
                "serviceKind": "protectedDataRootSecret",
                "currentPolicy": currentPolicy.rawValue,
                "newPolicy": newPolicy.rawValue,
                "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false"
            ]
        )
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
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.reprotect.update",
            metadata: AuthTraceMetadata.statusMetadata(
                status,
                extra: [
                    "serviceKind": "protectedDataRootSecret",
                    "newPolicy": newPolicy.rawValue
                ]
            )
        )
        try handleMutationStatus(status)

        var verifiedSecret = try loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticationContext
        )
        defer {
            verifiedSecret.protectedDataZeroize()
        }

        guard verifiedSecret == originalSecret else {
            traceStore?.record(
                category: .operation,
                name: "keychain.rootSecret.reprotect.finish",
                metadata: [
                    "serviceKind": "protectedDataRootSecret",
                    "result": "verificationFailed",
                    "newPolicy": newPolicy.rawValue
                ]
            )
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.rootSecretVerification",
                    defaultValue: "The protected app data root secret could not be verified after updating its access policy."
                )
            )
        }
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.reprotect.finish",
            metadata: [
                "serviceKind": "protectedDataRootSecret",
                "result": "success",
                "newPolicy": newPolicy.rawValue
            ]
        )
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
        do {
            let envelope = try ProtectedDataRootSecretEnvelopeCodec.decode(
                payload,
                expectedSharedRightIdentifier: identifier
            )
            let rootSecret = try deviceBindingProvider.openRootSecret(
                envelope: envelope,
                expectedSharedRightIdentifier: identifier
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.payload.finish",
                metadata: ["result": "success"]
            )
            return rootSecret
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.payload.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
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
