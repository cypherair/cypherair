import Foundation
import LocalAuthentication

enum ProtectedDataRightIdentifiers {
    static let productionSharedRightIdentifier = "com.cypherair.protected-data.shared-right.v1"
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

    init(rightStore: LARightStore = .shared) {
        self.rightStore = rightStore
    }

    func right(forIdentifier identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        let right = try await rightStore.right(forIdentifier: identifier)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: right)
    }

    func saveRight(_ right: LARight, identifier: String) async throws -> any ProtectedDataPersistedRightHandle {
        let savedRight = try await rightStore.saveRight(right, identifier: identifier)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: savedRight)
    }

    func saveRight(
        _ right: LARight,
        identifier: String,
        secret: Data
    ) async throws -> any ProtectedDataPersistedRightHandle {
        let savedRight = try await rightStore.saveRight(right, identifier: identifier, secret: secret)
        return LocalAuthenticationPersistedRightHandle(identifier: identifier, right: savedRight)
    }

    func removeRight(forIdentifier identifier: String) async throws {
        try await rightStore.removeRight(forIdentifier: identifier)
    }
}

private final class LocalAuthenticationPersistedRightHandle: ProtectedDataPersistedRightHandle {
    let identifier: String
    private let right: LAPersistedRight

    init(identifier: String, right: LAPersistedRight) {
        self.identifier = identifier
        self.right = right
    }

    func authorize(localizedReason: String) async throws {
        try await right.authorize(localizedReason: localizedReason)
    }

    func deauthorize() async {
        await right.deauthorize()
    }

    func rawSecretData() async throws -> Data {
        try await right.secret.rawData
    }
}
