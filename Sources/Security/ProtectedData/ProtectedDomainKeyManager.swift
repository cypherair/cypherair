import CryptoKit
import Foundation
import Security

struct WrappedDomainMasterKeyRecord: Codable, Equatable, Sendable {
    static let currentFormatVersion = 1
    static let expectedDomainMasterKeyLength = 32
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16

    let formatVersion: Int
    let domainID: ProtectedDataDomainID
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    func validateContract() throws {
        guard formatVersion == Self.currentFormatVersion else {
            throw ProtectedDataError.invalidRegistry("Unsupported WrappedDomainMasterKeyRecord format version \(formatVersion).")
        }
        guard nonce.count == Self.expectedNonceLength else {
            throw ProtectedDataError.invalidNonceLength(nonce.count)
        }
        guard ciphertext.count == Self.expectedDomainMasterKeyLength else {
            throw ProtectedDataError.invalidCiphertextLength(ciphertext.count)
        }
        guard tag.count == Self.expectedAuthenticationTagLength else {
            throw ProtectedDataError.invalidAuthenticationTagLength(tag.count)
        }
    }
}

final class ProtectedDomainKeyManager {
    private let storageRoot: ProtectedDataStorageRoot
    private var unlockedDomainMasterKeys: [ProtectedDataDomainID: Data] = [:]

    init(storageRoot: ProtectedDataStorageRoot) {
        self.storageRoot = storageRoot
    }

    func deriveWrappingRootKey(from rawSecretData: inout Data) throws -> Data {
        defer {
            rawSecretData.protectedDataZeroize()
        }

        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: rawSecretData),
            salt: Data("CypherAir.AppData.WrapRoot.Salt.v1".utf8),
            info: Data("CypherAir.AppData.WrapRoot.Info.v1".utf8),
            outputByteCount: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength
        )

        return key.withUnsafeBytes { Data($0) }
    }

    func deriveDomainWrappingKey(
        from wrappingRootKey: Data,
        domainID: ProtectedDataDomainID
    ) throws -> Data {
        let info = try wrappedDMKKeyInfo(domainID: domainID)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: wrappingRootKey),
            salt: Data("CypherAir.AppData.DomainWrap.Salt.v1".utf8),
            info: info,
            outputByteCount: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength
        )

        return key.withUnsafeBytes { Data($0) }
    }

    func generateDomainMasterKey() throws -> Data {
        try randomData(count: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength)
    }

    func wrapDomainMasterKey(
        _ domainMasterKey: Data,
        for domainID: ProtectedDataDomainID,
        wrappingRootKey: Data
    ) throws -> WrappedDomainMasterKeyRecord {
        guard domainMasterKey.count == WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(domainMasterKey.count)
        }

        var domainWrappingKey = try deriveDomainWrappingKey(from: wrappingRootKey, domainID: domainID)
        defer {
            domainWrappingKey.protectedDataZeroize()
        }

        let nonce = try randomData(count: WrappedDomainMasterKeyRecord.expectedNonceLength)
        let aad = try wrappedDMKAAD(domainID: domainID)

        let sealedBox = try AES.GCM.seal(
            domainMasterKey,
            using: SymmetricKey(data: domainWrappingKey),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )

        return WrappedDomainMasterKeyRecord(
            formatVersion: WrappedDomainMasterKeyRecord.currentFormatVersion,
            domainID: domainID,
            nonce: nonce,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
    }

    func unwrapDomainMasterKey(
        from record: WrappedDomainMasterKeyRecord,
        wrappingRootKey: Data
    ) throws -> Data {
        try record.validateContract()

        var domainWrappingKey = try deriveDomainWrappingKey(from: wrappingRootKey, domainID: record.domainID)
        defer {
            domainWrappingKey.protectedDataZeroize()
        }

        let aad = try wrappedDMKAAD(domainID: record.domainID)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: record.nonce),
            ciphertext: record.ciphertext,
            tag: record.tag
        )
        let domainMasterKey = try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: domainWrappingKey),
            authenticating: aad
        )

        guard domainMasterKey.count == WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(domainMasterKey.count)
        }

        return domainMasterKey
    }

    func writeWrappedDomainMasterKeyRecordTransaction(
        _ record: WrappedDomainMasterKeyRecord,
        wrappingRootKey: Data
    ) throws {
        try storageRoot.validatePersistentStorageContract()
        try storageRoot.ensureDomainDirectoryExists(for: record.domainID)

        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(record)
        let stagedURL = storageRoot.stagedWrappedDomainMasterKeyURL(for: record.domainID)
        let committedURL = storageRoot.committedWrappedDomainMasterKeyURL(for: record.domainID)

        try storageRoot.writeProtectedData(data, to: stagedURL)

        let stagedData = try Data(contentsOf: stagedURL)
        let decoded = try PropertyListDecoder().decode(WrappedDomainMasterKeyRecord.self, from: stagedData)
        var validatedDomainMasterKey = try unwrapDomainMasterKey(from: decoded, wrappingRootKey: wrappingRootKey)
        validatedDomainMasterKey.protectedDataZeroize()

        try storageRoot.promoteStagedFile(from: stagedURL, to: committedURL)
    }

    func loadWrappedDomainMasterKeyRecord(for domainID: ProtectedDataDomainID) throws -> WrappedDomainMasterKeyRecord? {
        try storageRoot.validatePersistentStorageContract()
        let url = storageRoot.committedWrappedDomainMasterKeyURL(for: domainID)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }

        let data = try Data(contentsOf: url)
        let record = try PropertyListDecoder().decode(WrappedDomainMasterKeyRecord.self, from: data)
        try record.validateContract()
        return record
    }

    func cacheUnlockedDomainMasterKey(_ domainMasterKey: Data, for domainID: ProtectedDataDomainID) {
        unlockedDomainMasterKeys[domainID] = domainMasterKey
    }

    func unlockedDomainMasterKey(for domainID: ProtectedDataDomainID) -> Data? {
        unlockedDomainMasterKeys[domainID]
    }

    func clearUnlockedDomainMasterKeys() {
        for domainID in unlockedDomainMasterKeys.keys {
            unlockedDomainMasterKeys[domainID]?.protectedDataZeroize()
        }
        unlockedDomainMasterKeys.removeAll()
    }

    var hasUnlockedDomainMasterKeys: Bool {
        !unlockedDomainMasterKeys.isEmpty
    }

    private func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }

        guard status == errSecSuccess else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.randomFailure",
                    defaultValue: "A secure random-number operation failed while preparing protected app data."
                )
            )
        }

        return data
    }

    private func wrappedDMKKeyInfo(domainID: ProtectedDataDomainID) throws -> Data {
        guard let domainIDData = domainID.rawValue.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.domainIdentifierEncoding",
                    defaultValue: "A ProtectedData domain identifier could not be encoded."
                )
            )
        }

        var info = Data("CADMKKI1".utf8)
        info.append(1)
        info.append(UInt16(domainIDData.count).bigEndianData)
        info.append(domainIDData)
        return info
    }

    private func wrappedDMKAAD(domainID: ProtectedDataDomainID) throws -> Data {
        guard let domainIDData = domainID.rawValue.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.domainIdentifierEncoding",
                    defaultValue: "A ProtectedData domain identifier could not be encoded."
                )
            )
        }

        var aad = Data("CADMKAD1".utf8)
        aad.append(1)
        aad.append(UInt16(domainIDData.count).bigEndianData)
        aad.append(domainIDData)
        aad.append(UInt8(WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength))
        return aad
    }
}

private extension UInt16 {
    var bigEndianData: Data {
        withUnsafeBytes(of: bigEndian) { Data($0) }
    }
}
