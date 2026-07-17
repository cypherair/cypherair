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
}

enum ProtectedDataDeviceBindingConstants {
    static let keyIdentifier = KeychainConstants.protectedDataDeviceBindingKeyService
}

struct HardwareProtectedDataDeviceBindingProvider: ProtectedDataDeviceBindingProvider {
    let keyIdentifier = ProtectedDataDeviceBindingConstants.keyIdentifier

    func sealRootSecret(
        _ rootSecret: Data,
        sharedRightIdentifier: String
    ) throws -> ProtectedDataRootSecretEnvelope {
        let key = try createBindingKey()
        return try ProtectedDataRootSecretEnvelopeCodec.seal(
            rootSecret: rootSecret,
            sharedRightIdentifier: sharedRightIdentifier,
            deviceBindingKeyIdentifier: keyIdentifier,
            deviceBindingKeyData: key.dataRepresentation,
            deviceBindingPublicKeyX963: key.publicKey.x963Representation
        )
    }

    func openRootSecret(
        envelope: ProtectedDataRootSecretEnvelope,
        expectedSharedRightIdentifier: String
    ) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        guard envelope.deviceBindingKeyIdentifier == keyIdentifier else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier mismatch.")
        }
        // Reconstruct the Secure Enclave handle from the folded key material in the
        // envelope itself — no separate persisted key item. Fail closed unless the
        // reconstructed public key matches the bound public key before any ECDH.
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: envelope.deviceBindingKeyData
        )
        guard envelope.deviceBindingPublicKeyX963 == key.publicKey.x963Representation else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding public key mismatch.")
        }
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: envelope.ephemeralPublicKeyX963
        )
        let sharedSecret = try key.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try ProtectedDataRootSecretEnvelopeCodec.open(
            envelope: envelope,
            sharedSecret: sharedSecret,
            expectedSharedRightIdentifier: expectedSharedRightIdentifier
        )
    }

    /// Creates a fresh ProtectedData device-binding Secure Enclave key. The key is not
    /// persisted to its own Keychain row; its `dataRepresentation` is folded into the
    /// root-secret envelope, which is the single self-contained persisted row.
    private func createBindingKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
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
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: accessControl
        )
    }
}
