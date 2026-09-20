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

extension HardwareEnclave {
    public func makeCustodyKey(type: CustodyKeyType, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        guard type.policy.requiresCredential else { throw VaultError.internalFailure("this key type carries no credential") }
        try context.present(credential: credential)
        return try HardwareCustodyKey(type: type, accessControl: try type.policy.makeAccessControl(), context: context)
    }

    public func makeCredentialFreeCustodyKey(type: CustodyKeyType, context: LAContext) throws -> any EnclaveCustodyKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        guard !type.policy.requiresCredential else { throw VaultError.internalFailure("this key type requires a credential") }
        return try HardwareCustodyKey(type: type, accessControl: try type.policy.makeAccessControl(), context: context)
    }

    public func custodyKey(type: CustodyKeyType, from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        guard type.policy.requiresCredential else { throw VaultError.internalFailure("this key type carries no credential") }
        try context.present(credential: credential)
        return try HardwareCustodyKey(type: type, blob: blob, context: context)
    }

    public func credentialFreeCustodyKey(type: CustodyKeyType, from blob: Data, context: LAContext) throws -> any EnclaveCustodyKey {
        guard isAvailable else { throw VaultError.enclaveUnavailable }
        guard !type.policy.requiresCredential else { throw VaultError.internalFailure("this key type requires a credential") }
        return try HardwareCustodyKey(type: type, blob: blob, context: context)
    }
}

struct HardwareCustodyKey: EnclaveCustodyKey {
    enum Key {
        case p256Signing(SecureEnclave.P256.Signing.PrivateKey)
        case p256KeyAgreement(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case mldsa65(SecureEnclave.MLDSA65.PrivateKey)
        case mldsa87(SecureEnclave.MLDSA87.PrivateKey)
        case mlkem768(SecureEnclave.MLKEM768.PrivateKey)
        case mlkem1024(SecureEnclave.MLKEM1024.PrivateKey)
    }

    let type: CustodyKeyType
    let key: Key

    init(type: CustodyKeyType, accessControl: SecAccessControl, context: LAContext) throws {
        self.type = type
        switch type {
        case .p256Signing: key = .p256Signing(try .init(accessControl: accessControl, authenticationContext: context))
        case .p256KeyAgreement: key = .p256KeyAgreement(try .init(compactRepresentable: false, accessControl: accessControl, authenticationContext: context))
        case .mldsa65: key = .mldsa65(try .init(accessControl: accessControl, authenticationContext: context))
        case .mldsa87: key = .mldsa87(try .init(accessControl: accessControl, authenticationContext: context))
        case .mlkem768: key = .mlkem768(try .init(accessControl: accessControl, authenticationContext: context))
        case .mlkem1024: key = .mlkem1024(try .init(accessControl: accessControl, authenticationContext: context))
        }
    }

    init(type: CustodyKeyType, blob: Data, context: LAContext) throws {
        self.type = type
        switch type {
        case .p256Signing: key = .p256Signing(try .init(dataRepresentation: blob, authenticationContext: context))
        case .p256KeyAgreement: key = .p256KeyAgreement(try .init(dataRepresentation: blob, authenticationContext: context))
        case .mldsa65: key = .mldsa65(try .init(dataRepresentation: blob, authenticationContext: context))
        case .mldsa87: key = .mldsa87(try .init(dataRepresentation: blob, authenticationContext: context))
        case .mlkem768: key = .mlkem768(try .init(dataRepresentation: blob, authenticationContext: context))
        case .mlkem1024: key = .mlkem1024(try .init(dataRepresentation: blob, authenticationContext: context))
        }
    }

    var dataRepresentation: Data {
        switch key {
        case .p256Signing(let k): k.dataRepresentation
        case .p256KeyAgreement(let k): k.dataRepresentation
        case .mldsa65(let k): k.dataRepresentation
        case .mldsa87(let k): k.dataRepresentation
        case .mlkem768(let k): k.dataRepresentation
        case .mlkem1024(let k): k.dataRepresentation
        }
    }

    var publicKeyRaw: Data {
        switch key {
        case .p256Signing(let k): k.publicKey.x963Representation
        case .p256KeyAgreement(let k): k.publicKey.x963Representation
        case .mldsa65(let k): k.publicKey.rawRepresentation
        case .mldsa87(let k): k.publicKey.rawRepresentation
        case .mlkem768(let k): k.publicKey.rawRepresentation
        case .mlkem1024(let k): k.publicKey.rawRepresentation
        }
    }

    func signature(for input: Data) throws -> Data {
        switch key {
        case .p256Signing(let k):
            guard let digest = RawSHA256Digest(input) else { throw VaultError.internalFailure("digest length") }
            return try k.signature(for: digest).rawRepresentation
        case .mldsa65(let k): return try k.signature(for: input)
        case .mldsa87(let k): return try k.signature(for: input)
        default: throw VaultError.internalFailure("key type cannot sign")
        }
    }

    func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SensitiveBuffer {
        guard case .p256KeyAgreement(let k) = key else { throw VaultError.internalFailure("key type cannot agree") }
        return try k.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963)).sensitiveBytes()
    }

    func decapsulate(_ ciphertext: Data) throws -> SensitiveBuffer {
        switch key {
        case .mlkem768(let k): return try k.decapsulate(ciphertext).sensitiveBytes()
        case .mlkem1024(let k): return try k.decapsulate(ciphertext).sensitiveBytes()
        default: throw VaultError.internalFailure("key type cannot decapsulate")
        }
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
