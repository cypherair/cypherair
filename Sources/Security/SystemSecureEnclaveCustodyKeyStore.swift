import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Production custody key store: one `kSecClassGenericPassword` row per
/// (tier/role service, handle-set account) in the data-protection keychain.
/// `kSecValueData` holds the CryptoKit Secure Enclave `dataRepresentation`;
/// `kSecAttrGeneric` carries the role's public key so lookup and binding
/// verification never require reconstruction with an authenticated context.
///
/// The use-authorization policy lives INSIDE the enclave key (baked in via
/// `SecAccessControl` at creation); the keychain row itself is a plain
/// this-device-only protected blob.
struct SystemSecureEnclaveCustodyKeyStore: SecureEnclaveCustodyKeyStoring {
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        guard try loadRow(reference: reference) == nil else {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(reference.role)
        }

        let accessControl = try accessPolicy.makeSecAccessControl()
        let privateKey: SecureEnclaveCustodyLoadedHandle.PrivateKey
        let publicKeyRaw: Data
        let blob: Data
        do {
            switch (reference.tier, reference.role) {
            case (.classicalP256, .signing):
                let key = try SecureEnclave.P256.Signing.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .p256Signing(key)
                publicKeyRaw = key.publicKey.x963Representation
                blob = key.dataRepresentation
            case (.classicalP256, .keyAgreement):
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
                privateKey = .p256KeyAgreement(key)
                publicKeyRaw = key.publicKey.x963Representation
                blob = key.dataRepresentation
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

        let binding = try SecureEnclaveCustodyHandlePublicBinding(
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

        return SecureEnclaveCustodyLoadedHandle(binding: binding, privateKey: privateKey)
    }

    func loadKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle? {
        guard let row = try loadRow(reference: reference) else {
            return nil
        }
        let binding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyRaw: row.publicKeyRaw
        )

        let privateKey: SecureEnclaveCustodyLoadedHandle.PrivateKey
        let reconstructedPublicKeyRaw: Data
        do {
            switch (reference.tier, reference.role) {
            case (.classicalP256, .signing):
                let key = try SecureEnclave.P256.Signing.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .p256Signing(key)
                reconstructedPublicKeyRaw = key.publicKey.x963Representation
            case (.classicalP256, .keyAgreement):
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: row.blob,
                    authenticationContext: authenticationContext
                )
                privateKey = .p256KeyAgreement(key)
                reconstructedPublicKeyRaw = key.publicKey.x963Representation
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

        return SecureEnclaveCustodyLoadedHandle(binding: binding, privateKey: privateKey)
    }

    func inventory() throws -> SecureEnclaveCustodyHandleInventory {
        var bindings: [SecureEnclaveCustodyHandlePublicBinding] = []
        var malformedRowCount = 0
        for tier in SecureEnclaveCustodyTier.allCases {
            for role in [PGPPrivateOperationRole.signing, .keyAgreement] {
                var query = Self.namespaceQuery(tier: tier, role: role)
                query[kSecReturnAttributes as String] = true
                query[kSecMatchLimit as String] = kSecMatchLimitAll

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
                              let reference = try? SecureEnclaveCustodyHandleReference(
                                  handleSetIdentifier: account,
                                  role: role,
                                  tier: tier
                              ),
                              let binding = try? SecureEnclaveCustodyHandlePublicBinding(
                                  reference: reference,
                                  publicKeyRaw: publicKeyRaw
                              ) else {
                            malformedRowCount += 1
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
        return SecureEnclaveCustodyHandleInventory(
            bindings: bindings,
            malformedRowCount: malformedRowCount
        )
    }

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws {
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

    func deleteAllKeys(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) throws {
        let status = SecItemDelete(Self.namespaceQuery(tier: tier, role: role) as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw SecureEnclaveCustodyOSStatusMapper.handleError(for: status, role: role)
        }
    }

    private struct StoredRow {
        let blob: Data
        let publicKeyRaw: Data
    }

    private func loadRow(reference: SecureEnclaveCustodyHandleReference) throws -> StoredRow? {
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

    private static func baseQuery(reference: SecureEnclaveCustodyHandleReference) -> [String: Any] {
        var query = namespaceQuery(tier: reference.tier, role: reference.role)
        query[kSecAttrAccount as String] = reference.accountString
        return query
    }

    private static func namespaceQuery(
        tier: SecureEnclaveCustodyTier,
        role: PGPPrivateOperationRole
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String:
                "\(SecureEnclaveCustodyHandleReference.servicePrefix).\(tier.serviceNamespaceSegment).\(role.rawValue)",
            kSecUseDataProtectionKeychain as String: true
        ]
        #if os(macOS)
        query[kSecAttrSynchronizable as String] = false
        #endif
        return query
    }
}
