import Foundation
import Sealing

/// The sealed root's public, authenticated metadata: what the unlock needs
/// before any prompt, and where the identity wrapping key lives.
public struct SealedRootMetadata: Codable, Equatable, Sendable {
    public let stretchSalt: Data
    public let stretchParameters: UnlockStretchParameters
    public let identityWrappingKeyBlob: Data
    public let identityWrappingPublicKeyX963: Data

    static let allowedKeys: Set<String> = ["stretchSalt", "stretchParameters", "identityWrappingKeyBlob", "identityWrappingPublicKeyX963"]

    func encoded() throws(VaultError) -> Data {
        do { return try StrictPropertyList.encode(self) } catch { throw .internalFailure("metadata encoding failed") }
    }

    static func decode(_ data: Data) throws(VaultError) -> SealedRootMetadata {
        let metadata: SealedRootMetadata
        do {
            metadata = try StrictPropertyList.decode(SealedRootMetadata.self, from: data, allowedKeys: allowedKeys)
        } catch {
            throw .sealedRootCorrupt
        }
        guard metadata.stretchSalt.count == UnlockStretchParameters.saltLength,
              !metadata.identityWrappingKeyBlob.isEmpty,
              metadata.identityWrappingPublicKeyX963.count == EnclaveSealedEnvelope.ephemeralPublicKeyLength else {
            throw .sealedRootCorrupt
        }
        return metadata
    }
}

/// Where the sealed root row lives. Production is one Keychain row; tests keep
/// it in memory.
public protocol SealedRootStorage: Sendable {
    func load() throws(VaultError) -> Data?
    func replace(_ data: Data) throws(VaultError)
    func delete() throws(VaultError)
}

public struct KeychainSealedRootStorage: SealedRootStorage {
    public static let service = "com.cypherair.vault.sealed-root"
    public static let account = "com.cypherair"

    private let rows: KeychainRows

    public init(service: String = KeychainSealedRootStorage.service) {
        rows = KeychainRows(service: service)
    }

    public func load() throws(VaultError) -> Data? { try rows.read(account: Self.account) }
    public func replace(_ data: Data) throws(VaultError) { try rows.write(account: Self.account, data: data) }
    public func delete() throws(VaultError) { try rows.delete(account: Self.account) }
}
