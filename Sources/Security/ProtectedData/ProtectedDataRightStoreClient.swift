import Foundation
import LocalAuthentication
import Security

enum ProtectedDataRightIdentifiers {
    static let productionSharedRightIdentifier = "com.cypherair.protected-data.shared-right.v1"
}

enum ProtectedDataRootSecretStorageFormat: String, Equatable, Sendable {
    case legacyV1Raw
    case envelopeV2
}

struct ProtectedDataRootSecretLoadResult: Equatable, Sendable {
    var secretData: Data
    let storageFormat: ProtectedDataRootSecretStorageFormat
    let didMigrate: Bool
}

protocol ProtectedDataRootSecretStoreProtocol: AnyObject {
    func saveRootSecret(
        _ secretData: Data,
        identifier: String,
        policy: AppSessionAuthenticationPolicy
    ) throws

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        minimumEnvelopeVersion: Int?
    ) throws -> ProtectedDataRootSecretLoadResult

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
    private let supportKeychain: any KeychainManageable
    private let deviceBindingProvider: any ProtectedDataDeviceBindingProvider
    private let formatFloorStore: ProtectedDataRootSecretFormatFloorStore
    private let traceStore: AuthLifecycleTraceStore?

    init(
        account: String = KeychainConstants.defaultAccount,
        supportKeychain: (any KeychainManageable)? = nil,
        deviceBindingProvider: (any ProtectedDataDeviceBindingProvider)? = nil,
        formatFloorStore: ProtectedDataRootSecretFormatFloorStore? = nil,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.account = account
        let supportKeychain = supportKeychain ?? SystemKeychain(traceStore: traceStore)
        self.supportKeychain = supportKeychain
        self.deviceBindingProvider = deviceBindingProvider ?? HardwareProtectedDataDeviceBindingProvider(
            keychain: supportKeychain,
            account: account,
            traceStore: traceStore
        )
        self.formatFloorStore = formatFloorStore ?? ProtectedDataRootSecretFormatFloorStore(
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
        try formatFloorStore.writeMinimumEnvelopeVersion(
            ProtectedDataRootSecretEnvelope.currentFormatVersion,
            sharedRightIdentifier: identifier
        )
    }

    func loadRootSecret(
        identifier: String,
        authenticationContext: LAContext,
        minimumEnvelopeVersion: Int?
    ) throws -> ProtectedDataRootSecretLoadResult {
        traceStore?.record(
            category: .operation,
            name: "keychain.rootSecret.load.start",
            metadata: [
                "serviceKind": "protectedDataRootSecret",
                "interactionNotAllowed": authenticationContext.interactionNotAllowed ? "true" : "false",
                "registryMinimumEnvelopeVersion": minimumEnvelopeVersion.map(String.init) ?? "none"
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
            guard let data = result as? Data else {
                throw KeychainError.unhandledError(errSecInternalError)
            }
            return try openOrMigrateRootSecretPayload(
                data,
                identifier: identifier,
                authenticationContext: authenticationContext,
                minimumEnvelopeVersion: minimumEnvelopeVersion
            )
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
        var originalResult = try loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticationContext,
            minimumEnvelopeVersion: nil
        )
        defer {
            originalResult.secretData.protectedDataZeroize()
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

        var verifiedResult = try loadRootSecret(
            identifier: identifier,
            authenticationContext: authenticationContext,
            minimumEnvelopeVersion: nil
        )
        defer {
            verifiedResult.secretData.protectedDataZeroize()
        }

        guard verifiedResult.secretData == originalResult.secretData else {
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

    private func openOrMigrateRootSecretPayload(
        _ payload: Data,
        identifier: String,
        authenticationContext: LAContext,
        minimumEnvelopeVersion: Int?
    ) throws -> ProtectedDataRootSecretLoadResult {
        let keychainMinimumVersion = try formatFloorStore.readMinimumEnvelopeVersion(
            sharedRightIdentifier: identifier
        )
        let effectiveMinimumVersion = max(minimumEnvelopeVersion ?? 0, keychainMinimumVersion ?? 0)
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.payload.start",
            metadata: [
                "registryMinimumEnvelopeVersion": minimumEnvelopeVersion.map(String.init) ?? "none",
                "keychainMinimumEnvelopeVersion": keychainMinimumVersion.map(String.init) ?? "none",
                "effectiveMinimumEnvelopeVersion": String(effectiveMinimumVersion)
            ]
        )

        if payload.count == ProtectedDataRootSecretEnvelope.expectedRootSecretLength {
            guard effectiveMinimumVersion < ProtectedDataRootSecretEnvelope.currentFormatVersion else {
                traceStore?.record(
                    category: .operation,
                    name: "protectedData.rootSecret.payload.finish",
                    metadata: ["result": "downgradeDetected", "storageFormat": "legacyV1Raw"]
                )
                throw ProtectedDataError.invalidEnvelope("Root-secret payload is legacy v1 after v2 format floor was established.")
            }
            return try migrateLegacyRawRootSecret(
                payload,
                identifier: identifier,
                authenticationContext: authenticationContext
            )
        }

        do {
            let envelope = try ProtectedDataRootSecretEnvelopeCodec.decode(
                payload,
                expectedSharedRightIdentifier: identifier
            )
            var rootSecret = try deviceBindingProvider.openRootSecret(
                envelope: envelope,
                expectedSharedRightIdentifier: identifier
            )
            do {
                try formatFloorStore.writeMinimumEnvelopeVersion(
                    ProtectedDataRootSecretEnvelope.currentFormatVersion,
                    sharedRightIdentifier: identifier
                )
                try deleteLegacyCleanupMarkerIfPresent(authenticationContext: authenticationContext)
            } catch {
                rootSecret.protectedDataZeroize()
                throw error
            }
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.payload.finish",
                metadata: ["result": "success", "storageFormat": "envelopeV2", "didMigrate": "false"]
            )
            return ProtectedDataRootSecretLoadResult(
                secretData: rootSecret,
                storageFormat: .envelopeV2,
                didMigrate: false
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.payload.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    private func migrateLegacyRawRootSecret(
        _ legacySecret: Data,
        identifier: String,
        authenticationContext: LAContext
    ) throws -> ProtectedDataRootSecretLoadResult {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.v2Migration.start",
            metadata: ["storageFormat": "legacyV1Raw"]
        )
        do {
            let envelope = try deviceBindingProvider.sealRootSecret(
                legacySecret,
                sharedRightIdentifier: identifier
            )
            let encodedEnvelope = try ProtectedDataRootSecretEnvelopeCodec.encode(envelope)
            var updateQuery = baseQuery(identifier: identifier)
            updateQuery[kSecUseAuthenticationContext as String] = authenticationContext
            let updateStatus = SecItemUpdate(
                updateQuery as CFDictionary,
                [kSecValueData as String: encodedEnvelope] as CFDictionary
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.v2Migration.update",
                metadata: AuthTraceMetadata.statusMetadata(updateStatus, extra: ["envelopeVersion": "2"])
            )
            try handleMutationStatus(updateStatus)

            var verifiedPayload = try loadRootSecretPayload(
                identifier: identifier,
                authenticationContext: authenticationContext
            )
            defer {
                verifiedPayload.protectedDataZeroize()
            }
            let verifiedEnvelope = try ProtectedDataRootSecretEnvelopeCodec.decode(
                verifiedPayload,
                expectedSharedRightIdentifier: identifier
            )
            var verifiedSecret = try deviceBindingProvider.openRootSecret(
                envelope: verifiedEnvelope,
                expectedSharedRightIdentifier: identifier
            )
            guard verifiedSecret == legacySecret else {
                verifiedSecret.protectedDataZeroize()
                throw ProtectedDataError.internalFailure(
                    String(
                        localized: "error.protectedData.rootSecretMigrationVerification",
                        defaultValue: "The protected app data root secret could not be verified after migration."
                    )
                )
            }
            do {
                try formatFloorStore.writeMinimumEnvelopeVersion(
                    ProtectedDataRootSecretEnvelope.currentFormatVersion,
                    sharedRightIdentifier: identifier
                )
                try deleteLegacyCleanupMarkerIfPresent(authenticationContext: authenticationContext)
            } catch {
                verifiedSecret.protectedDataZeroize()
                throw error
            }
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.v2Migration.finish",
                metadata: ["result": "success", "envelopeVersion": "2"]
            )
            return ProtectedDataRootSecretLoadResult(
                secretData: verifiedSecret,
                storageFormat: .envelopeV2,
                didMigrate: true
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.v2Migration.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    private func loadRootSecretPayload(
        identifier: String,
        authenticationContext: LAContext
    ) throws -> Data {
        var query = baseQuery(identifier: identifier)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = authenticationContext

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        try handleLoadStatus(status)
        guard let data = result as? Data else {
            throw KeychainError.unhandledError(errSecInternalError)
        }
        return data
    }

    private func handleLoadStatus(_ status: OSStatus) throws {
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

    private func deleteLegacyCleanupMarkerIfPresent(authenticationContext: LAContext) throws {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.legacyCleanup.delete.start"
        )
        do {
            try supportKeychain.delete(
                service: KeychainConstants.protectedDataRootSecretLegacyCleanupService,
                account: account,
                authenticationContext: authenticationContext
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyCleanup.delete.finish",
                metadata: ["result": "deleted"]
            )
        } catch where Self.isItemNotFound(error) {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyCleanup.delete.finish",
                metadata: ["result": "missing"]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.legacyCleanup.delete.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError {
            return keychainError == .itemNotFound
        }
        if let mockKeychainError = error as? MockKeychainError {
            switch mockKeychainError {
            case .itemNotFound:
                return true
            case .duplicateItem, .saveFailed, .deleteFailed:
                return false
            }
        }
        return false
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
    private let traceStore: AuthLifecycleTraceStore?

    init(
        rightStore: LARightStore = .shared,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.rightStore = rightStore
        self.traceStore = traceStore
    }

    func right(forIdentifier identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.right.start",
            metadata: ["serviceKind": "legacyRight"]
        )
        do {
            let right = try await rightStore.right(forIdentifier: identifier)
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.right.finish",
                metadata: ["serviceKind": "legacyRight", "result": "success"]
            )
            return LocalAuthenticationPersistedRightHandle(
                identifier: identifier,
                right: right,
                traceStore: traceStore
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.right.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "result": "failed"])
            )
            throw error
        }
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.save.start",
            metadata: ["serviceKind": "legacyRight", "secret": "false"]
        )
        do {
            let savedRight = try await rightStore.saveRight(right, identifier: identifier)
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.save.finish",
                metadata: ["serviceKind": "legacyRight", "secret": "false", "result": "success"]
            )
            return LocalAuthenticationPersistedRightHandle(
                identifier: identifier,
                right: savedRight,
                traceStore: traceStore
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.save.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "secret": "false", "result": "failed"])
            )
            throw error
        }
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any ProtectedDataPersistedRightHandle {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.save.start",
            metadata: ["serviceKind": "legacyRight", "secret": "true"]
        )
        do {
            let savedRight = try await rightStore.saveRight(right, identifier: identifier, secret: secret)
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.save.finish",
                metadata: ["serviceKind": "legacyRight", "secret": "true", "result": "success"]
            )
            return LocalAuthenticationPersistedRightHandle(
                identifier: identifier,
                right: savedRight,
                traceStore: traceStore
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.save.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "secret": "true", "result": "failed"])
            )
            throw error
        }
    }

    func removeRight(forIdentifier identifier: String) async throws {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.remove.start",
            metadata: ["serviceKind": "legacyRight"]
        )
        do {
            try await rightStore.removeRight(forIdentifier: identifier)
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.remove.finish",
                metadata: ["serviceKind": "legacyRight", "result": "success"]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.remove.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "result": "failed"])
            )
            throw error
        }
    }
}

private final class LocalAuthenticationPersistedRightHandle: ProtectedDataPersistedRightHandle {
    let identifier: String
    private let right: LAPersistedRight
    private let traceStore: AuthLifecycleTraceStore?

    init(
        identifier: String,
        right: LAPersistedRight,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.identifier = identifier
        self.right = right
        self.traceStore = traceStore
    }

    func authorize(localizedReason: String) async throws {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.authorize.start",
            metadata: ["serviceKind": "legacyRight"]
        )
        do {
            try await right.authorize(localizedReason: localizedReason)
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.authorize.finish",
                metadata: ["serviceKind": "legacyRight", "result": "success"]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.authorize.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "result": "failed"])
            )
            throw error
        }
    }

    func deauthorize() async {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.deauthorize.start",
            metadata: ["serviceKind": "legacyRight"]
        )
        await right.deauthorize()
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.deauthorize.finish",
            metadata: ["serviceKind": "legacyRight", "result": "success"]
        )
    }

    func rawSecretData() async throws -> Data {
        traceStore?.record(
            category: .operation,
            name: "protectedData.legacyRight.rawSecretData.start",
            metadata: ["serviceKind": "legacyRight"]
        )
        do {
            let data = try await right.secret.rawData
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.rawSecretData.finish",
                metadata: ["serviceKind": "legacyRight", "result": "success"]
            )
            return data
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.legacyRight.rawSecretData.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["serviceKind": "legacyRight", "result": "failed"])
            )
            throw error
        }
    }
}
