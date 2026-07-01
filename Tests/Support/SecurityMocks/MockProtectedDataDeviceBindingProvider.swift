import CryptoKit
import Foundation
@testable import CypherAir

final class MockProtectedDataDeviceBindingProvider: ProtectedDataDeviceBindingProvider, @unchecked Sendable {
    let keyIdentifier: String
    var sealError: MockKeychainError?
    var openError: MockKeychainError?
    var deleteError: MockKeychainError?
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
            deviceBindingKeyData: privateKey.rawRepresentation,
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
        guard envelope.deviceBindingKeyIdentifier == keyIdentifier else {
            throw ProtectedDataError.invalidEnvelope("Root-secret envelope device-binding key identifier mismatch.")
        }
        // Reconstruct the (software) binding key from the folded envelope material,
        // mirroring the hardware provider's single-row reconstruction.
        let privateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: envelope.deviceBindingKeyData
        )
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
