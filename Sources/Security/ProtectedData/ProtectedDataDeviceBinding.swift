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
        } catch where KeychainFailureClassifier.isItemNotFound(error) {
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
        } catch where KeychainFailureClassifier.isDuplicateItem(error) {
            return try loadKey()
        }
        return key
    }
}

