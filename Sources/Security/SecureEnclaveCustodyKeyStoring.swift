import Foundation

protocol SecureEnclaveCustodyKeyStoring {
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy
    ) throws -> SecureEnclaveCustodyLoadedHandle

    func loadKeys(reference: SecureEnclaveCustodyHandleReference) throws -> [SecureEnclaveCustodyLoadedHandle]

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws

    func inventoryKeys() throws -> [SecureEnclaveCustodyHandleInventoryItem]

    func deleteKey(
        applicationTagData: Data,
        roleHint: PGPPrivateOperationRole?
    ) throws
}
