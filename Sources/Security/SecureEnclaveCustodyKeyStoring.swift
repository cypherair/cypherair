import Foundation
import LocalAuthentication

protocol SecureEnclaveCustodyKeyStoring {
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy
    ) throws -> SecureEnclaveCustodyLoadedHandle

    func loadKeys(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> [SecureEnclaveCustodyLoadedHandle]

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws

    func inventoryKeys() throws -> [SecureEnclaveCustodyHandleInventoryItem]

    func deleteKey(
        applicationTagData: Data,
        roleHint: PGPPrivateOperationRole?
    ) throws
}
