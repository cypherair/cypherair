import Foundation

final class MockSecureEnclaveCustodyKeyStore: SecureEnclaveCustodyKeyStoring, @unchecked Sendable {
    private var storage: [SecureEnclaveCustodyHandleReference: [SecureEnclaveCustodyLoadedHandle]] = [:]
    private var malformedApplicationTags: Set<Data> = []
    private var publicKeyCounter: UInt8 = 1

    private(set) var createRequests: [
        (reference: SecureEnclaveCustodyHandleReference, accessPolicy: SecureEnclaveCustodyAccessControlPolicy)
    ] = []
    private(set) var deleteRequests: [SecureEnclaveCustodyHandleReference] = []

    var failCreateRole: PGPPrivateOperationRole?
    var failDeleteRole: PGPPrivateOperationRole?
    var failLoadError: SecureEnclaveCustodyHandleError?
    var failInventory = false
    var publicKeyResponses: [Data] = []

    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        createRequests.append((reference, accessPolicy))
        if failCreateRole == reference.role {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }
        if storage[reference]?.isEmpty == false {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }

        let binding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyX963: nextPublicKey()
        )
        let handle = SecureEnclaveCustodyLoadedHandle(
            binding: binding,
            privateKey: nil
        )
        storage[reference] = [handle]
        return handle
    }

    func loadKeys(reference: SecureEnclaveCustodyHandleReference) throws -> [SecureEnclaveCustodyLoadedHandle] {
        if let failLoadError {
            throw failLoadError
        }
        return storage[reference] ?? []
    }

    func deleteKey(reference: SecureEnclaveCustodyHandleReference) throws {
        deleteRequests.append(reference)
        if failDeleteRole == reference.role {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }
        guard storage.removeValue(forKey: reference) != nil else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(reference.role)
        }
    }

    func inventoryKeys() throws -> [SecureEnclaveCustodyHandleInventoryItem] {
        if failInventory {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        let storedItems = storage.flatMap { reference, handles -> [SecureEnclaveCustodyHandleInventoryItem] in
            handles.compactMap { _ in
                SecureEnclaveCustodyHandleInventoryItem(applicationTagData: reference.applicationTagData)
            }
        }
        let malformedItems = malformedApplicationTags.compactMap(SecureEnclaveCustodyHandleInventoryItem.init)
        return storedItems + malformedItems
    }

    func deleteKey(
        applicationTagData: Data,
        roleHint: PGPPrivateOperationRole?
    ) throws {
        if let reference = SecureEnclaveCustodyHandleInventoryItem(applicationTagData: applicationTagData)?.reference {
            try deleteKey(reference: reference)
            return
        }
        let role = roleHint ?? .signing
        if failDeleteRole == role {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(role)
        }
        guard malformedApplicationTags.remove(applicationTagData) != nil else {
            throw SecureEnclaveCustodyHandleError.privateHandleMissing(role)
        }
    }

    func insert(
        _ handle: SecureEnclaveCustodyLoadedHandle,
        for reference: SecureEnclaveCustodyHandleReference? = nil,
        allowingDuplicate: Bool = false
    ) {
        let storageReference = reference ?? handle.reference
        if allowingDuplicate {
            storage[storageReference, default: []].append(handle)
        } else {
            storage[storageReference] = [handle]
        }
    }

    func insertMalformedApplicationTag(_ applicationTagString: String) {
        insertMalformedApplicationTagData(Data(applicationTagString.utf8))
    }

    func insertMalformedApplicationTagData(_ applicationTagData: Data) {
        malformedApplicationTags.insert(applicationTagData)
    }

    func contains(reference: SecureEnclaveCustodyHandleReference) -> Bool {
        storage[reference]?.isEmpty == false
    }

    func containsMalformedApplicationTag(_ applicationTagString: String) -> Bool {
        containsMalformedApplicationTagData(Data(applicationTagString.utf8))
    }

    func containsMalformedApplicationTagData(_ applicationTagData: Data) -> Bool {
        malformedApplicationTags.contains(applicationTagData)
    }

    func storedHandleCount() -> Int {
        storage.values.reduce(0) { $0 + $1.count } + malformedApplicationTags.count
    }

    func applicationTagStrings() -> [String] {
        (
            storage.keys.map(\.applicationTagString)
                + malformedApplicationTags.compactMap { String(data: $0, encoding: .utf8) }
        )
        .sorted()
    }

    func resetCallHistory() {
        createRequests.removeAll()
        deleteRequests.removeAll()
    }

    private func nextPublicKey() -> Data {
        if !publicKeyResponses.isEmpty {
            return publicKeyResponses.removeFirst()
        }
        defer { publicKeyCounter = publicKeyCounter &+ 1 }
        var data = Data([0x04])
        data.append(Data(repeating: publicKeyCounter, count: 64))
        return data
    }
}
