import Foundation
import Security

struct SystemSecureEnclaveCustodyKeyStore: SecureEnclaveCustodyKeyStoring {
    private let traceStore: AuthLifecycleTraceStore?

    init(traceStore: AuthLifecycleTraceStore? = nil) {
        self.traceStore = traceStore
    }

    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: reference.applicationTagString)
        traceStore?.record(
            category: .operation,
            name: "secureEnclaveCustody.createKey.start",
            metadata: ["serviceKind": serviceKind]
        )
        let accessControl = try accessPolicy.makeSecAccessControl()
        var privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: reference.applicationTagData,
            kSecAttrAccessControl as String: accessControl
        ]

        #if os(macOS)
        privateKeyAttributes[kSecAttrSynchronizable as String] = false
        #endif

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let mappedError = Self.mapCFError(error, role: reference.role)
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.createKey.finish",
                metadata: [
                    "serviceKind": serviceKind,
                    "result": "failed",
                    "failureCategory": mappedError.failureCategory.rawValue
                ]
            )
            throw mappedError
        }
        do {
            let loaded = try loadedHandle(reference: reference, privateKey: privateKey)
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.createKey.finish",
                metadata: ["serviceKind": serviceKind, "result": "success"]
            )
            return loaded
        } catch {
            let mappedError = error as? SecureEnclaveCustodyHandleError
                ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.createKey.finish",
                metadata: [
                    "serviceKind": serviceKind,
                    "result": "failed",
                    "failureCategory": mappedError.failureCategory.rawValue
                ]
            )
            throw error
        }
    }

    func loadKeys(reference: SecureEnclaveCustodyHandleReference) throws -> [SecureEnclaveCustodyLoadedHandle] {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: reference.applicationTagString)
        traceStore?.record(
            category: .operation,
            name: "secureEnclaveCustody.loadKeys.start",
            metadata: ["serviceKind": serviceKind]
        )
        var query = baseQuery(reference: reference)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            do {
                let loaded: [SecureEnclaveCustodyLoadedHandle]
                if let privateKeys = result as? [SecKey] {
                    loaded = try privateKeys.map { try loadedHandle(reference: reference, privateKey: $0) }
                } else if let result, CFGetTypeID(result) == SecKeyGetTypeID() {
                    loaded = [try loadedHandle(reference: reference, privateKey: result as! SecKey)]
                } else {
                    throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
                }
                traceStore?.record(
                    category: .operation,
                    name: "secureEnclaveCustody.loadKeys.finish",
                    metadata: [
                        "serviceKind": serviceKind,
                        "result": "success",
                        "count": String(loaded.count)
                    ]
                )
                return loaded
            } catch {
                let mappedError = error as? SecureEnclaveCustodyHandleError
                    ?? SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
                traceStore?.record(
                    category: .operation,
                    name: "secureEnclaveCustody.loadKeys.finish",
                    metadata: [
                        "serviceKind": serviceKind,
                        "result": "failed",
                        "failureCategory": mappedError.failureCategory.rawValue
                    ]
                )
                throw error
            }
        case errSecItemNotFound:
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.loadKeys.finish",
                metadata: ["serviceKind": serviceKind, "result": "success", "count": "0"]
            )
            return []
        default:
            let mappedError = Self.mapStatus(status, role: reference.role)
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.loadKeys.finish",
                metadata: [
                    "serviceKind": serviceKind,
                    "result": "failed",
                    "failureCategory": mappedError.failureCategory.rawValue
                ]
            )
            throw mappedError
        }
    }

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws {
        let serviceKind = AuthTraceMetadata.keychainServiceKind(for: reference.applicationTagString)
        traceStore?.record(
            category: .operation,
            name: "secureEnclaveCustody.deleteKey.start",
            metadata: ["serviceKind": serviceKind]
        )
        let status = SecItemDelete(baseQuery(reference: reference) as CFDictionary)
        switch status {
        case errSecSuccess:
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.deleteKey.finish",
                metadata: ["serviceKind": serviceKind, "result": "success"]
            )
            return
        case errSecItemNotFound:
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.deleteKey.finish",
                metadata: [
                    "serviceKind": serviceKind,
                    "result": "failed",
                    "failureCategory": PGPKeyOperationFailureCategory.privateHandleMissing.rawValue
                ]
            )
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        default:
            let mappedError = Self.mapStatus(status, role: reference.role)
            traceStore?.record(
                category: .operation,
                name: "secureEnclaveCustody.deleteKey.finish",
                metadata: [
                    "serviceKind": serviceKind,
                    "result": "failed",
                    "failureCategory": mappedError.failureCategory.rawValue
                ]
            )
            throw mappedError
        }
    }

    private func baseQuery(reference: SecureEnclaveCustodyHandleReference) -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: reference.applicationTagData,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func loadedHandle(
        reference: SecureEnclaveCustodyHandleReference,
        privateKey: SecKey
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        try validatePrivateKeyAttributes(privateKey, role: reference.role)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }

        var error: Unmanaged<CFError>?
        guard let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw Self.mapCFError(error, role: reference.role)
        }
        let binding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyX963: publicData
        )
        return SecureEnclaveCustodyLoadedHandle(
            binding: binding,
            privateKey: privateKey
        )
    }

    private func validatePrivateKeyAttributes(_ privateKey: SecKey, role: PGPPrivateOperationRole) throws {
        guard let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(role)
        }
        guard attributes[kSecAttrKeyType as String] as? String == (kSecAttrKeyTypeECSECPrimeRandom as String),
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              attributes[kSecAttrTokenID as String] as? String == (kSecAttrTokenIDSecureEnclave as String) else {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(role)
        }
    }

    private static func mapCFError(
        _ error: Unmanaged<CFError>?,
        role: PGPPrivateOperationRole
    ) -> SecureEnclaveCustodyHandleError {
        guard let error else {
            return .privateHandleInaccessible(role)
        }
        let cfError = error.takeRetainedValue()
        return mapStatus(OSStatus(CFErrorGetCode(cfError)), role: role)
    }

    private static func mapStatus(_ status: OSStatus, role: PGPPrivateOperationRole) -> SecureEnclaveCustodyHandleError {
        switch status {
        case errSecNotAvailable:
            return .hardwareUnavailable
        case errSecItemNotFound:
            return .privateHandleMissing(role)
        case errSecDuplicateItem:
            return .privateHandleInaccessible(role)
        case errSecUserCanceled:
            return .localAuthenticationCancelled(role)
        case errSecAuthFailed:
            return .localAuthenticationFailed(role)
        case errSecInteractionNotAllowed:
            return .privateHandleUnauthorized(role)
        default:
            return .privateHandleInaccessible(role)
        }
    }
}
