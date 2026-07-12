import CryptoKit
import Foundation
import Security
import os

/// Self-describing envelope that seals a 32-byte per-domain master key under the
/// HKDF-derived domain wrapping key (AES-256-GCM). Follows the same envelope
/// discipline as `PrivateKeyEnvelope` / `ProtectedDataRootSecretEnvelope`: a magic,
/// algorithm identifier, and AAD version are stored and bound into the AES-GCM AAD,
/// and decoding rejects any unknown or missing field.
///
/// Domain-separated from the ECDH envelopes by its own magic (`CADMKV2`) and AAD
/// prefix (`CADMKAD2`) so a wrapped-DMK blob can never be misread as another format.
///
/// SECURITY-CRITICAL: Changes to this file require human review.
/// See SECURITY.md Section 3 and Section 10.
struct WrappedDomainMasterKeyRecord: Codable, Equatable, Sendable {
    static let magic = "CADMKV2"
    static let currentFormatVersion = 2
    static let currentAADVersion = 2
    static let algorithmID = "aes-256-gcm-hkdf-sha256-v1"
    static let expectedDomainMasterKeyLength = 32
    static let expectedNonceLength = 12
    static let expectedAuthenticationTagLength = 16

    let magic: String
    let formatVersion: Int
    let algorithmID: String
    let aadVersion: Int
    let domainID: ProtectedDataDomainID
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    func validateContract() throws {
        guard magic == Self.magic else {
            throw ProtectedDataError.invalidEnvelope("Unsupported wrapped domain master key record magic.")
        }
        guard formatVersion == Self.currentFormatVersion else {
            throw ProtectedDataError.invalidEnvelope("Unsupported wrapped domain master key record format version \(formatVersion).")
        }
        guard algorithmID == Self.algorithmID else {
            throw ProtectedDataError.invalidEnvelope("Unsupported wrapped domain master key record algorithm.")
        }
        guard aadVersion == Self.currentAADVersion else {
            throw ProtectedDataError.invalidEnvelope("Unsupported wrapped domain master key record AAD version \(aadVersion).")
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

/// Codec for `WrappedDomainMasterKeyRecord`.
///
/// Owns the record's binary-plist encoding, strict decoding (exactly the allowed
/// keys), and the AES-256-GCM seal/open under a caller-supplied domain wrapping key.
/// The wrapping-key derivation itself stays in `ProtectedDomainKeyManager`, which
/// holds the wrapping-root / per-domain HKDF material.
enum WrappedDomainMasterKeyRecordCodec {
    private static let allowedKeys: Set<String> = [
        "magic",
        "formatVersion",
        "algorithmID",
        "aadVersion",
        "domainID",
        "nonce",
        "ciphertext",
        "tag"
    ]

    static func encode(_ record: WrappedDomainMasterKeyRecord) throws -> Data {
        try record.validateContract()
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(record)
    }

    static func decode(_ data: Data) throws -> WrappedDomainMasterKeyRecord {
        try validateNoUnsupportedKeys(in: data)
        let record = try PropertyListDecoder().decode(WrappedDomainMasterKeyRecord.self, from: data)
        try record.validateContract()
        return record
    }

    static func seal(
        domainMasterKey: Data,
        domainID: ProtectedDataDomainID,
        domainWrappingKey: Data
    ) throws -> WrappedDomainMasterKeyRecord {
        guard domainMasterKey.count == WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength else {
            throw ProtectedDataError.invalidDomainMasterKeyLength(domainMasterKey.count)
        }

        let nonce = try protectedDataRandomBytes(count: WrappedDomainMasterKeyRecord.expectedNonceLength)
        let aad = try wrappedDMKAAD(domainID: domainID)
        let sealedBox = try AES.GCM.seal(
            domainMasterKey,
            using: SymmetricKey(data: domainWrappingKey),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )

        let record = WrappedDomainMasterKeyRecord(
            magic: WrappedDomainMasterKeyRecord.magic,
            formatVersion: WrappedDomainMasterKeyRecord.currentFormatVersion,
            algorithmID: WrappedDomainMasterKeyRecord.algorithmID,
            aadVersion: WrappedDomainMasterKeyRecord.currentAADVersion,
            domainID: domainID,
            nonce: nonce,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
        try record.validateContract()
        return record
    }

    static func open(
        record: WrappedDomainMasterKeyRecord,
        domainWrappingKey: Data
    ) throws -> Data {
        try record.validateContract()

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

    private static func wrappedDMKAAD(domainID: ProtectedDataDomainID) throws -> Data {
        guard let magicData = WrappedDomainMasterKeyRecord.magic.data(using: .utf8),
              let algorithmData = WrappedDomainMasterKeyRecord.algorithmID.data(using: .utf8),
              let domainIDData = domainID.rawValue.data(using: .utf8) else {
            throw ProtectedDataError.internalFailure(
                String(
                    localized: "error.protectedData.domainIdentifierEncoding",
                    defaultValue: "A ProtectedData domain identifier could not be encoded."
                )
            )
        }

        var aad = Data("CADMKAD2".utf8)
        aad.append(UInt8(WrappedDomainMasterKeyRecord.currentFormatVersion))
        aad.append(UInt8(WrappedDomainMasterKeyRecord.currentAADVersion))
        aad.append(UInt16(magicData.count).bigEndianData)
        aad.append(magicData)
        aad.append(UInt16(algorithmData.count).bigEndianData)
        aad.append(algorithmData)
        aad.append(UInt16(domainIDData.count).bigEndianData)
        aad.append(domainIDData)
        aad.append(UInt8(WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength))
        return aad
    }

    private static func validateNoUnsupportedKeys(in data: Data) throws {
        guard let keys = try EnvelopePlistInspector.topLevelKeys(in: data) else {
            throw ProtectedDataError.invalidEnvelope("Wrapped domain master key record is not a dictionary.")
        }
        guard keys == allowedKeys else {
            throw ProtectedDataError.invalidEnvelope("Wrapped domain master key record contains unsupported or missing fields.")
        }
    }
}

final class ProtectedDomainKeyManager {
    private let storageRoot: ProtectedDataStorageRoot
    private let keychain: any KeychainManageable
    private let account: String
    /// Decrypted per-domain master keys, guarded by an unfair lock (issue #610):
    /// every caller runs on the main actor today, but nothing enforces that, so
    /// the lock makes cache reads, writes, and relock zeroization safe by
    /// construction instead of by convention. Compile-time isolation of the
    /// whole custody layer is #502 Track B scope.
    private let unlockedDomainMasterKeys = OSAllocatedUnfairLock<[ProtectedDataDomainID: Data]>(initialState: [:])

    init(
        storageRoot: ProtectedDataStorageRoot,
        keychain: any KeychainManageable = SystemKeychain(),
        account: String = KeychainConstants.defaultAccount
    ) {
        self.storageRoot = storageRoot
        self.keychain = keychain
        self.account = account
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
        try protectedDataRandomBytes(count: WrappedDomainMasterKeyRecord.expectedDomainMasterKeyLength)
    }

    func wrapDomainMasterKey(
        _ domainMasterKey: Data,
        for domainID: ProtectedDataDomainID,
        wrappingRootKey: Data
    ) throws -> WrappedDomainMasterKeyRecord {
        var domainWrappingKey = try deriveDomainWrappingKey(from: wrappingRootKey, domainID: domainID)
        defer {
            domainWrappingKey.protectedDataZeroize()
        }

        return try WrappedDomainMasterKeyRecordCodec.seal(
            domainMasterKey: domainMasterKey,
            domainID: domainID,
            domainWrappingKey: domainWrappingKey
        )
    }

    func unwrapDomainMasterKey(
        from record: WrappedDomainMasterKeyRecord,
        wrappingRootKey: Data
    ) throws -> Data {
        var domainWrappingKey = try deriveDomainWrappingKey(from: wrappingRootKey, domainID: record.domainID)
        defer {
            domainWrappingKey.protectedDataZeroize()
        }

        return try WrappedDomainMasterKeyRecordCodec.open(
            record: record,
            domainWrappingKey: domainWrappingKey
        )
    }

    func writeWrappedDomainMasterKeyRecordTransaction(
        _ record: WrappedDomainMasterKeyRecord,
        wrappingRootKey: Data
    ) throws {
        try storageRoot.validatePersistentStorageContract()
        let data = try WrappedDomainMasterKeyRecordCodec.encode(record)
        let stagedService = KeychainConstants.stagedProtectedDataDomainKeyService(domainID: record.domainID)
        let committedService = KeychainConstants.protectedDataDomainKeyService(domainID: record.domainID)

        try deleteKeychainRowIfPresent(service: stagedService)
        try keychain.save(
            data,
            service: stagedService,
            account: account,
            accessControl: nil
        )

        let stagedData = try keychain.load(
            service: stagedService,
            account: account,
            authenticationContext: nil
        )
        let decoded = try WrappedDomainMasterKeyRecordCodec.decode(stagedData)
        var validatedDomainMasterKey = try unwrapDomainMasterKey(from: decoded, wrappingRootKey: wrappingRootKey)
        validatedDomainMasterKey.protectedDataZeroize()

        try saveOrUpdateKeychainRow(
            stagedData,
            service: committedService
        )
        try keychain.delete(
            service: stagedService,
            account: account,
            authenticationContext: nil
        )
    }

    func loadWrappedDomainMasterKeyRecord(for domainID: ProtectedDataDomainID) throws -> WrappedDomainMasterKeyRecord? {
        try storageRoot.validatePersistentStorageContract()
        let service = KeychainConstants.protectedDataDomainKeyService(domainID: domainID)
        let data: Data
        do {
            data = try keychain.load(
                service: service,
                account: account,
                authenticationContext: nil
            )
        } catch where KeychainFailureClassifier.isItemNotFound(error) {
            return nil
        } catch {
            throw error
        }

        return try WrappedDomainMasterKeyRecordCodec.decode(data)
    }

    func deleteWrappedDomainMasterKeyRecords(for domainID: ProtectedDataDomainID) throws {
        try storageRoot.validatePersistentStorageContract()
        try deleteKeychainRowIfPresent(
            service: KeychainConstants.stagedProtectedDataDomainKeyService(domainID: domainID)
        )
        try deleteKeychainRowIfPresent(
            service: KeychainConstants.protectedDataDomainKeyService(domainID: domainID)
        )
    }

    func hasAnyPersistedDomainKeyRecord() throws -> Bool {
        try !keychain.listItems(
            servicePrefix: KeychainConstants.protectedDataDomainKeyServicePrefix,
            account: account,
            authenticationContext: nil
        ).isEmpty
    }

    func cacheUnlockedDomainMasterKey(_ domainMasterKey: Data, for domainID: ProtectedDataDomainID) {
        unlockedDomainMasterKeys.withLock { $0[domainID] = domainMasterKey }
    }

    func unlockedDomainMasterKey(for domainID: ProtectedDataDomainID) -> Data? {
        unlockedDomainMasterKeys.withLock { $0[domainID] }
    }

    func clearUnlockedDomainMasterKeys() {
        unlockedDomainMasterKeys.withLock { keys in
            for domainID in keys.keys {
                keys[domainID]?.protectedDataZeroize()
            }
            keys.removeAll()
        }
    }

    var hasUnlockedDomainMasterKeys: Bool {
        unlockedDomainMasterKeys.withLock { !$0.isEmpty }
    }

    private func saveOrUpdateKeychainRow(_ data: Data, service: String) throws {
        do {
            try keychain.save(
                data,
                service: service,
                account: account,
                accessControl: nil
            )
        } catch where KeychainFailureClassifier.isDuplicateItem(error) {
            try keychain.update(
                data,
                service: service,
                account: account,
                authenticationContext: nil
            )
        }
    }

    private func deleteKeychainRowIfPresent(service: String) throws {
        do {
            try keychain.delete(
                service: service,
                account: account,
                authenticationContext: nil
            )
        } catch where KeychainFailureClassifier.isItemNotFound(error) {
            return
        }
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
}

/// Fills `count` cryptographically secure random bytes for the ProtectedData
/// wrapping paths. File-scoped so both `ProtectedDomainKeyManager` (domain master
/// key generation) and `WrappedDomainMasterKeyRecordCodec` (nonces) share one
/// implementation while keeping the ProtectedData-domain error and message.
private func protectedDataRandomBytes(count: Int) throws -> Data {
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
