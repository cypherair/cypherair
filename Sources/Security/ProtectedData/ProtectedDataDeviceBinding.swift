import CryptoKit
import Foundation
import Security

protocol ProtectedDataDeviceBindingProvider {
    var keyIdentifier: String { get }

    func sealRootSecret(
        _ rootSecret: Data,
        sharedRightIdentifier: String
    ) throws -> ProtectedDataRootSecretEnvelope

    func openRootSecret(
        envelope: ProtectedDataRootSecretEnvelope,
        expectedSharedRightIdentifier: String
    ) throws -> Data

    func bindingKeyExists() -> Bool
    func deleteBindingKey() throws
}

enum ProtectedDataDeviceBindingConstants {
    static let keyIdentifier = KeychainConstants.protectedDataDeviceBindingKeyService
}

struct HardwareProtectedDataDeviceBindingProvider: ProtectedDataDeviceBindingProvider {
    let keyIdentifier = ProtectedDataDeviceBindingConstants.keyIdentifier

    private let keychain: any KeychainManageable
    private let account: String
    private let traceStore: AuthLifecycleTraceStore?

    init(
        keychain: any KeychainManageable = SystemKeychain(),
        account: String = KeychainConstants.defaultAccount,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.keychain = keychain
        self.account = account
        self.traceStore = traceStore
    }

    func sealRootSecret(
        _ rootSecret: Data,
        sharedRightIdentifier: String
    ) throws -> ProtectedDataRootSecretEnvelope {
        traceStore?.record(
            category: .operation,
            name: "protectedData.deviceBinding.seal.start",
            metadata: ["keyIdentifier": "protectedData"]
        )
        do {
            let key = try loadOrCreateKey()
            let envelope = try ProtectedDataRootSecretEnvelopeCodec.seal(
                rootSecret: rootSecret,
                sharedRightIdentifier: sharedRightIdentifier,
                deviceBindingKeyIdentifier: keyIdentifier,
                deviceBindingPublicKeyX963: key.publicKey.x963Representation
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.deviceBinding.seal.finish",
                metadata: ["result": "success", "envelopeVersion": "2"]
            )
            return envelope
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.deviceBinding.seal.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    func openRootSecret(
        envelope: ProtectedDataRootSecretEnvelope,
        expectedSharedRightIdentifier: String
    ) throws -> Data {
        traceStore?.record(
            category: .operation,
            name: "protectedData.deviceBinding.open.start",
            metadata: ["envelopeVersion": String(envelope.formatVersion)]
        )
        do {
            let key = try loadKey()
            guard envelope.deviceBindingKeyIdentifier == keyIdentifier else {
                throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier mismatch.")
            }
            guard envelope.deviceBindingPublicKeyX963 == key.publicKey.x963Representation else {
                throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding public key mismatch.")
            }
            let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: envelope.ephemeralPublicKeyX963
            )
            let sharedSecret = try key.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let rootSecret = try ProtectedDataRootSecretEnvelopeCodec.open(
                envelope: envelope,
                sharedSecret: sharedSecret,
                expectedSharedRightIdentifier: expectedSharedRightIdentifier
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.deviceBinding.open.finish",
                metadata: ["result": "success", "envelopeVersion": String(envelope.formatVersion)]
            )
            return rootSecret
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.deviceBinding.open.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["result": "failed", "envelopeVersion": String(envelope.formatVersion)]
                )
            )
            throw error
        }
    }

    func bindingKeyExists() -> Bool {
        keychain.exists(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: account,
            authenticationContext: nil
        )
    }

    func deleteBindingKey() throws {
        try keychain.delete(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: account,
            authenticationContext: nil
        )
    }

    private func loadOrCreateKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        do {
            return try loadKey()
        } catch let error as KeychainError where error == .itemNotFound {
            return try createAndPersistKey()
        }
    }

    private func loadKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        let data = try keychain.load(
            service: KeychainConstants.protectedDataDeviceBindingKeyService,
            account: account,
            authenticationContext: nil
        )
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
    }

    private func createAndPersistKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            if let error = error?.takeRetainedValue() {
                throw error
            }
            throw SecureEnclaveError.accessControlCreationFailed
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
        do {
            try keychain.save(
                key.dataRepresentation,
                service: KeychainConstants.protectedDataDeviceBindingKeyService,
                account: account,
                accessControl: nil
            )
        } catch KeychainError.duplicateItem {
            return try loadKey()
        }
        return key
    }
}

final class MockProtectedDataDeviceBindingProvider: ProtectedDataDeviceBindingProvider, @unchecked Sendable {
    let keyIdentifier: String
    var sealError: Error?
    var openError: Error?
    var deleteError: Error?
    private var privateKey: P256.KeyAgreement.PrivateKey?

    init(keyIdentifier: String = ProtectedDataDeviceBindingConstants.keyIdentifier) {
        self.keyIdentifier = keyIdentifier
    }

    func sealRootSecret(
        _ rootSecret: Data,
        sharedRightIdentifier: String
    ) throws -> ProtectedDataRootSecretEnvelope {
        if let sealError {
            self.sealError = nil
            throw sealError
        }
        let privateKey = try loadOrCreateKey()
        return try ProtectedDataRootSecretEnvelopeCodec.seal(
            rootSecret: rootSecret,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: keyIdentifier,
            deviceBindingPublicKeyX963: privateKey.publicKey.x963Representation
        )
    }

    func openRootSecret(
        envelope: ProtectedDataRootSecretEnvelope,
        expectedSharedRightIdentifier: String
    ) throws -> Data {
        if let openError {
            self.openError = nil
            throw openError
        }
        guard let privateKey else {
            throw KeychainError.itemNotFound
        }
        guard envelope.deviceBindingKeyIdentifier == keyIdentifier else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier mismatch.")
        }
        guard envelope.deviceBindingPublicKeyX963 == privateKey.publicKey.x963Representation else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding public key mismatch.")
        }
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: envelope.ephemeralPublicKeyX963
        )
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try ProtectedDataRootSecretEnvelopeCodec.open(
            envelope: envelope,
            sharedSecret: sharedSecret,
            expectedSharedRightIdentifier: expectedSharedRightIdentifier
        )
    }

    func bindingKeyExists() -> Bool {
        privateKey != nil
    }

    func deleteBindingKey() throws {
        if let deleteError {
            self.deleteError = nil
            throw deleteError
        }
        privateKey = nil
    }

    private func loadOrCreateKey() throws -> P256.KeyAgreement.PrivateKey {
        if let privateKey {
            return privateKey
        }
        let key = P256.KeyAgreement.PrivateKey()
        privateKey = key
        return key
    }
}

struct ProtectedDataRootSecretFormatFloorMarker: Codable, Equatable, Sendable {
    static let magic = "CAPDSEF2"

    let magic: String
    let sharedRightIdentifier: String
    let minimumEnvelopeVersion: Int

    static func marker(sharedRightIdentifier: String, minimumEnvelopeVersion: Int) -> Self {
        ProtectedDataRootSecretFormatFloorMarker(
            magic: magic,
            sharedRightIdentifier: sharedRightIdentifier,
            minimumEnvelopeVersion: minimumEnvelopeVersion
        )
    }

    func validate(expectedSharedRightIdentifier: String) throws {
        guard magic == Self.magic else {
            throw ProtectedDataError.invalidEnvelope("Invalid root-secret format-floor marker magic.")
        }
        guard sharedRightIdentifier == expectedSharedRightIdentifier else {
            throw ProtectedDataError.invalidEnvelope("Root-secret format-floor marker shared-right identifier mismatch.")
        }
        guard minimumEnvelopeVersion >= ProtectedDataRootSecretEnvelope.currentFormatVersion else {
            throw ProtectedDataError.invalidEnvelope("Root-secret format-floor marker is below the supported envelope version.")
        }
    }
}

final class ProtectedDataRootSecretFormatFloorStore {
    private let keychain: any KeychainManageable
    private let account: String
    private let traceStore: AuthLifecycleTraceStore?

    init(
        keychain: any KeychainManageable = SystemKeychain(),
        account: String = KeychainConstants.defaultAccount,
        traceStore: AuthLifecycleTraceStore? = nil
    ) {
        self.keychain = keychain
        self.account = account
        self.traceStore = traceStore
    }

    func readMinimumEnvelopeVersion(sharedRightIdentifier: String) throws -> Int? {
        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.formatFloor.load.start"
        )
        do {
            let data = try keychain.load(
                service: KeychainConstants.protectedDataRootSecretFormatFloorService,
                account: account,
                authenticationContext: nil
            )
            let marker = try PropertyListDecoder().decode(
                ProtectedDataRootSecretFormatFloorMarker.self,
                from: data
            )
            try marker.validate(expectedSharedRightIdentifier: sharedRightIdentifier)
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.formatFloor.load.finish",
                metadata: ["result": "success", "minimumEnvelopeVersion": String(marker.minimumEnvelopeVersion)]
            )
            return marker.minimumEnvelopeVersion
        } catch where Self.isItemNotFound(error) {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.formatFloor.load.finish",
                metadata: ["result": "missing"]
            )
            return nil
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.formatFloor.load.finish",
                metadata: AuthTraceMetadata.errorMetadata(error, extra: ["result": "failed"])
            )
            throw error
        }
    }

    func writeMinimumEnvelopeVersion(
        _ version: Int,
        sharedRightIdentifier: String
    ) throws {
        let marker = ProtectedDataRootSecretFormatFloorMarker.marker(
            sharedRightIdentifier: sharedRightIdentifier,
            minimumEnvelopeVersion: version
        )
        try marker.validate(expectedSharedRightIdentifier: sharedRightIdentifier)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(marker)

        traceStore?.record(
            category: .operation,
            name: "protectedData.rootSecret.formatFloor.save.start",
            metadata: ["minimumEnvelopeVersion": String(version)]
        )
        do {
            try? keychain.delete(
                service: KeychainConstants.protectedDataRootSecretFormatFloorService,
                account: account,
                authenticationContext: nil
            )
            try keychain.save(
                data,
                service: KeychainConstants.protectedDataRootSecretFormatFloorService,
                account: account,
                accessControl: nil
            )
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.formatFloor.save.finish",
                metadata: ["result": "success", "minimumEnvelopeVersion": String(version)]
            )
        } catch {
            traceStore?.record(
                category: .operation,
                name: "protectedData.rootSecret.formatFloor.save.finish",
                metadata: AuthTraceMetadata.errorMetadata(
                    error,
                    extra: ["result": "failed", "minimumEnvelopeVersion": String(version)]
                )
            )
            throw error
        }
    }

    func deleteMarker() throws {
        try keychain.delete(
            service: KeychainConstants.protectedDataRootSecretFormatFloorService,
            account: account,
            authenticationContext: nil
        )
    }

    private static func isItemNotFound(_ error: Error) -> Bool {
        if let keychainError = error as? KeychainError {
            return keychainError == .itemNotFound
        }
        if let mockKeychainError = error as? MockKeychainError {
            switch mockKeychainError {
            case .itemNotFound:
                return true
            case .duplicateItem, .saveFailed, .deleteFailed:
                return false
            }
        }
        return false
    }
}
