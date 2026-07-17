import Foundation
import LocalAuthentication
@testable import CypherAir

final class MockSecureEnclaveCustodyKeyStore: SecureEnclaveCustodyKeyStoring, @unchecked Sendable {
    private struct Namespace: Hashable {
        let tier: SecureEnclaveCustodyTier
        let role: PGPPrivateOperationRole
    }

    private var storage: [SecureEnclaveCustodyHandleReference: SecureEnclaveCustodyLoadedHandle] = [:]
    private var malformedRows: [Namespace: Int] = [:]
    private var publicKeyCounter: UInt8 = 1

    private(set) var createRequests: [
        (
            reference: SecureEnclaveCustodyHandleReference,
            accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
            authenticationContext: LAContext?
        )
    ] = []
    private(set) var deleteRequests: [SecureEnclaveCustodyHandleReference] = []
    private(set) var loadRequests: [
        (reference: SecureEnclaveCustodyHandleReference, authenticationContext: LAContext?)
    ] = []

    var failCreateRole: PGPPrivateOperationRole?
    var failDeleteRole: PGPPrivateOperationRole?
    var failLoadError: SecureEnclaveCustodyHandleError?
    var failInventory = false
    var failDeleteAllKeys = false
    var publicKeyResponses: [Data] = []
    var onLoadKey: (() -> Void)?

    func createKey(
        reference: SecureEnclaveCustodyHandleReference,
        accessPolicy: SecureEnclaveCustodyAccessControlPolicy,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle {
        createRequests.append((reference, accessPolicy, authenticationContext))
        if failCreateRole == reference.role {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(reference.role)
        }
        if storage[reference] != nil {
            throw SecureEnclaveCustodyHandleError.ambiguousPrivateHandle(reference.role)
        }

        let binding = try SecureEnclaveCustodyHandlePublicBinding(
            reference: reference,
            publicKeyRaw: nextPublicKey(reference: reference)
        )
        let handle = SecureEnclaveCustodyLoadedHandle(
            binding: binding,
            privateKey: nil
        )
        storage[reference] = handle
        return handle
    }

    func loadKey(
        reference: SecureEnclaveCustodyHandleReference,
        authenticationContext: LAContext?
    ) throws -> SecureEnclaveCustodyLoadedHandle? {
        onLoadKey?()
        loadRequests.append((reference, authenticationContext))
        if let failLoadError {
            throw failLoadError
        }
        return storage[reference]
    }

    func inventory() throws -> SecureEnclaveCustodyHandleInventory {
        if failInventory {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(.signing)
        }
        return SecureEnclaveCustodyHandleInventory(
            bindings: storage.values.map(\.binding),
            malformedRowCount: malformedRows.values.reduce(0, +)
        )
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

    func deleteAllKeys(tier: SecureEnclaveCustodyTier, role: PGPPrivateOperationRole) throws {
        if failDeleteAllKeys || failDeleteRole == role {
            throw SecureEnclaveCustodyHandleError.privateHandleInaccessible(role)
        }
        for reference in storage.keys where reference.tier == tier && reference.role == role {
            storage.removeValue(forKey: reference)
        }
        malformedRows[Namespace(tier: tier, role: role)] = nil
    }

    func insert(
        _ handle: SecureEnclaveCustodyLoadedHandle,
        for reference: SecureEnclaveCustodyHandleReference? = nil
    ) {
        storage[reference ?? handle.reference] = handle
    }

    func insertMalformedRow(
        tier: SecureEnclaveCustodyTier = .classicalP256,
        role: PGPPrivateOperationRole = .signing
    ) {
        malformedRows[Namespace(tier: tier, role: role), default: 0] += 1
    }

    func contains(reference: SecureEnclaveCustodyHandleReference) -> Bool {
        storage[reference] != nil
    }

    func storedHandleCount() -> Int {
        storage.count + malformedRows.values.reduce(0, +)
    }

    func storedReferences() -> [SecureEnclaveCustodyHandleReference] {
        Array(storage.keys)
    }

    func resetCallHistory() {
        createRequests.removeAll()
        deleteRequests.removeAll()
        loadRequests.removeAll()
    }

    private func nextPublicKey(reference: SecureEnclaveCustodyHandleReference) -> Data {
        if !publicKeyResponses.isEmpty {
            return publicKeyResponses.removeFirst()
        }
        defer { publicKeyCounter = publicKeyCounter &+ 1 }
        switch reference.tier {
        case .classicalP256:
            var data = Data([0x04])
            data.append(Data(repeating: publicKeyCounter, count: 64))
            return data
        case .postQuantum, .postQuantumHigh:
            let lengths = reference.tier.postQuantumPublicKeyLengths!
            let length = reference.role == .signing ? lengths.signing : lengths.keyAgreement
            return Data(repeating: publicKeyCounter, count: length)
        }
    }
}

final class RecordingLAContext: LAContext {
    var invalidateCount = 0

    override func invalidate() {
        invalidateCount += 1
        super.invalidate()
    }
}
