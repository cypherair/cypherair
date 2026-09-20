import CryptoKit
import Foundation
import LocalAuthentication
import Sealing

/// The real Secure Enclave through CryptoKit.
public struct HardwareEnclave: Enclave {
    public init() {}

    public var isAvailable: Bool { SecureEnclave.isAvailable }

    public func makeKeyAgreementKey(
        policy: EnclaveAccessPolicy,
        credential: borrowing SensitiveBuffer,
        context: LAContext
    ) throws -> any EnclaveKeyAgreementKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        guard policy.requiresCredential else { throw VaultError.internalFailure("key-agreement keys always carry a credential") }
        try context.present(credential: credential)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false,
            accessControl: try policy.makeAccessControl(),
            authenticationContext: context
        )
        return HardwareKeyAgreementKey(key: key)
    }

    public func keyAgreementKey(
        from blob: Data,
        credential: borrowing SensitiveBuffer,
        context: LAContext
    ) throws -> any EnclaveKeyAgreementKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        try context.present(credential: credential)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob,
            authenticationContext: context
        )
        return HardwareKeyAgreementKey(key: key)
    }
}

struct HardwareKeyAgreementKey: EnclaveKeyAgreementKey {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    var dataRepresentation: Data { key.dataRepresentation }
    var publicKeyX963: Data { key.publicKey.x963Representation }

    func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963))
    }
}
