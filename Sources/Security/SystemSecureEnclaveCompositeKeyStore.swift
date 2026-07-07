import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Production composite key store: one `kSecClassGenericPassword` row per
/// (role service, handle-set account) in the data-protection keychain.
/// `kSecValueData` holds the CryptoKit Secure Enclave `dataRepresentation`;
/// `kSecAttrGeneric` carries the component public key so lookup and binding
/// verification never require reconstruction with an authenticated context.
///
/// The use-authorization policy lives INSIDE the enclave key (baked in via
/// `SecAccessControl` at creation); the keychain row itself is a plain
/// this-device-only protected blob.
struct SystemSecureEnclaveCompositeKeyStore: SecureEnclaveCompositeKeyStoring {
    func createKey(
        reference: SecureEnclaveCompositeHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle {
        guard try loadRow(reference: reference) == nil else {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(reference.role)
        }

        let accessControl = try accessPolicy.makeSecAccessControl()
        let privateKey: SecureEnclaveCompositeLoadedHandle.PrivateKey
        let publicKeyRaw: Data
        let blob: Data
        do {
            switch (reference.tier, reference.role) {
            case (.postQuantum, .signing):
                let key = try SecureEnclave.MLDSA65.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .mldsa65Signing(key)
                publicKeyRaw = key.publicKey.rawRepresentation
                blob = key.dataRepresentation
            case (.postQuantum, .keyAgreement):
                let key = try SecureEnclave.MLKEM768.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .mlkem768KeyAgreement(key)
                publicKeyRaw = key.publicKey.rawRepresentation
                blob = key.dataRepresentation
            case (.postQuantumHigh, .signing):
                let key = try SecureEnclave.MLDSA87.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .mldsa87Signing(key)
                publicKeyRaw = key.publicKey.rawRepresentation
                blob = key.dataRepresentation
            case (.postQuantumHigh, .keyAgreement):
                let key = try SecureEnclave.MLKEM1024.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .mlkem1024KeyAgreement(key)
                publicKeyRaw = key.publicKey.rawRepresentation
                blob = key.dataRepresentation
            }
        } catch {
            throw SecureEnclaveCustodyHandleError.hardwareUnavailable
        }

        let binding = try SecureEnclaveCompositeHandlePublicBinding(
            reference: reference,
            publicKeyRaw: publicKeyRaw
        )

        var attributes = Self.baseQuery(reference: reference)
        attributes[kSecValueData as String] = blob
        attributes[kSecAttrGeneric as String] = publicKeyRaw
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #if os(macOS)
        attributes[kSecAttrSynchronizable as String] = false
        #endif

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureEnclaveCustodyOSStatusMapper.handleError(for: status, role: reference.role)
        }

        return SecureEnclaveCompositeLoadedHandle(binding: binding, privateKey: privateKey)
    }

    func loadKey(
        reference: SecureEnclaveCompositeHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCompositeLoadedHandle? {
        guard let row = try loadRow(reference: reference) else {
            return nil
        }
        let binding = try SecureEnclaveCompositeHandlePublicBinding(
            reference: reference,
            publicKeyRaw: row.publicKeyRaw
        )

        let privateKey: SecureEnclaveCompositeLoadedHandle.PrivateKey
        let reconstructedPublicKeyRaw: Data
        do {
            switch (reference.tier, reference.role) {
            case (.postQuantum, .signing):
                let key = try SecureEnclave.MLDSA65.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .mldsa65Signing(key)
                reconstructedPublicKeyRaw = key.publicKey.rawRepresentation
            case (.postQuantum, .keyAgreement):
                let key = try SecureEnclave.MLKEM768.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .mlkem768KeyAgreement(key)
                reconstructedPublicKeyRaw = key.publicKey.rawRepresentation
            case (.postQuantumHigh, .signing):
                let key = try SecureEnclave.MLDSA87.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .mldsa87Signing(key)
                reconstructedPublicKeyRaw = key.publicKey.rawRepresentation
            case (.postQuantumHigh, .keyAgreement):
                let key = try SecureEnclave.MLKEM1024.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .mlkem1024KeyAgreement(key)
                reconstructedPublicKeyRaw = key.publicKey.rawRepresentation
            }
        } catch {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }

        // The stored binding is advisory lookup state; the reconstructed key is
        // authoritative. A divergence means a corrupted or substituted row.
        guard reconstructedPublicKeyRaw == binding.publicKeyRaw else {
            throw SecureEnclaveCustodyHandleError.handlePublicKeyBindingMismatch(reference.role)
        }

        return SecureEnclaveCompositeLoadedHandle(binding: binding, privateKey: privateKey)
    }

    func inventoryBindings() throws -> [SecureEnclaveCompositeHandlePublicBinding] {
        var bindings: [SecureEnclaveCompositeHandlePublicBinding] = []
        for tier in SecureEnclaveCompositeTier.allCases {
            for role in [PGPPrivateOperationRole.signing, .keyAgreement] {
                var query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String:
                        "\(SecureEnclaveCompositeHandleReference.servicePrefix)\(tier.serviceNamespaceSuffix).\(role.rawValue)",
                    kSecUseDataProtectionKeychain as String: true,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitAll
                ]
                #if os(macOS)
                query[kSecAttrSynchronizable as String] = false
                #endif

                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                switch status {
                case errSecSuccess:
                    guard let attributesList = result as? [[String: Any]] else {
                        throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(role)
                    }
                    for attributes in attributesList {
                        guard let account = attributes[kSecAttrAccount as String] as? String,
                              let publicKeyRaw = attributes[kSecAttrGeneric as String] as? Data,
                              let reference = try? SecureEnclaveCompositeHandleReference(
                                  handleSetIdentifier: account,
                                  role: role,
                                  tier: tier
                              ),
                              let binding = try? SecureEnclaveCompositeHandlePublicBinding(
                                  reference: reference,
                                  publicKeyRaw: publicKeyRaw
                              ) else {
                            continue
                        }
                        bindings.append(binding)
                    }
                case errSecItemNotFound:
                    continue
                default:
                    throw SecureEnclaveCustodyOSStatusMapper.handleError(for: status, role: role)
                }
            }
        }
        return bindings
    }

    func deleteKey(reference: SecureEnclaveCompositeHandleReference) throws {
        let status = SecItemDelete(Self.baseQuery(reference: reference) as CFDictionary)
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        default:
            throw SecureEnclaveCustodyOSStatusMapper.handleError(for: status, role: reference.role)
        }
    }

    private struct StoredRow {
        let blob: Data
        let publicKeyRaw: Data
    }

    private func loadRow(reference: SecureEnclaveCompositeHandleReference) throws -> StoredRow? {
        var query = Self.baseQuery(reference: reference)
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let attributes = result as? [String: Any],
                  let blob = attributes[kSecValueData as String] as? Data,
                  let publicKeyRaw = attributes[kSecAttrGeneric as String] as? Data else {
                throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
            }
            return StoredRow(blob: blob, publicKeyRaw: publicKeyRaw)
        case errSecItemNotFound:
            return nil
        default:
            throw SecureEnclaveCustodyOSStatusMapper.handleError(for: status, role: reference.role)
        }
    }

    private static func baseQuery(reference: SecureEnclaveCompositeHandleReference) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: reference.serviceString,
            kSecAttrAccount as String: reference.accountString,
            kSecUseDataProtectionKeychain as String: true
        ]
        #if os(macOS)
        query[kSecAttrSynchronizable as String] = false
        #endif
        return query
    }
}
