import Foundation

protocol SecureEnclaveCustodyKeyStoring {
    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy
    ) throws -> SecureEnclaveCustodyLoadedHandle

    func loadKeys(reference: SecureEnclaveCustodyHandleReference) throws -> [SecureEnclaveCustodyLoadedHandle]

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws
}
