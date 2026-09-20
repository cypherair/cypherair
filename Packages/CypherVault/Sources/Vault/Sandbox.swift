import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import os

// The sandbox composition: a vault that never touches hardware, the Keychain,
// or Argon2id. Every value lives in memory and dies with the process. It exists
// for the tutorial sandbox and for test hosts, never for user data.

/// Software keys standing in for the enclave. Blobs carry the key material and
/// a hash of the credential the key was created under, so a wrong credential is
/// refused the way the hardware refuses it.
public final class SoftwareEnclave: Enclave, Sendable {
    struct KeyAgreementBlob: Codable {
        let raw: Data
        let policy: String
        let credentialHash: Data?
    }

    struct CustodyBlob: Codable {
        let type: CustodyKeyType
        let key: Data
        let credentialHash: Data?
    }

    public init() {}

    public var isAvailable: Bool { true }

    public func makeKeyAgreementKey(policy: EnclaveAccessPolicy, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        guard policy.requiresCredential else { throw VaultError.internalFailure("key-agreement keys always carry a credential") }
        let key = P256.KeyAgreement.PrivateKey()
        let blob = try JSONEncoder().encode(KeyAgreementBlob(raw: key.rawRepresentation, policy: policy.rawValue, credentialHash: Self.hash(credential)))
        return SoftwareKeyAgreementKey(key: key, blob: blob)
    }

    public func keyAgreementKey(from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        let decoded = try JSONDecoder().decode(KeyAgreementBlob.self, from: blob)
        guard decoded.credentialHash == Self.hash(credential) else { throw Self.refused }
        return SoftwareKeyAgreementKey(key: try P256.KeyAgreement.PrivateKey(rawRepresentation: decoded.raw), blob: blob)
    }

    public func makeCustodyKey(type: CustodyKeyType, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        guard type.policy.requiresCredential else { throw VaultError.internalFailure("this key type carries no credential") }
        return try SoftwareCustodyKey(type: type, credentialHash: Self.hash(credential))
    }

    public func makeCredentialFreeCustodyKey(type: CustodyKeyType, context: LAContext) throws -> any EnclaveCustodyKey {
        guard !type.policy.requiresCredential else { throw VaultError.internalFailure("this key type requires a credential") }
        return try SoftwareCustodyKey(type: type, credentialHash: nil)
    }

    public func custodyKey(type: CustodyKeyType, from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveCustodyKey {
        let decoded = try JSONDecoder().decode(CustodyBlob.self, from: blob)
        guard decoded.type == type, decoded.credentialHash == Self.hash(credential) else { throw Self.refused }
        return try SoftwareCustodyKey(type: type, serialized: decoded.key, credentialHash: decoded.credentialHash)
    }

    public func credentialFreeCustodyKey(type: CustodyKeyType, from blob: Data, context: LAContext) throws -> any EnclaveCustodyKey {
        let decoded = try JSONDecoder().decode(CustodyBlob.self, from: blob)
        guard decoded.type == type, decoded.credentialHash == nil else { throw Self.refused }
        return try SoftwareCustodyKey(type: type, serialized: decoded.key, credentialHash: nil)
    }

    /// The same error CryptoTokenKit reports for a wrong application password.
    private static var refused: NSError {
        NSError(domain: "CryptoTokenKit", code: -3, userInfo: [NSDebugDescriptionErrorKey: "software enclave: credential refused"])
    }

    private static func hash(_ credential: borrowing SensitiveBuffer) -> Data {
        credential.withUnsafeBytes { Data(SHA256.hash(data: $0)) }
    }
}

struct SoftwareKeyAgreementKey: EnclaveKeyAgreementKey {
    let key: P256.KeyAgreement.PrivateKey
    let blob: Data

    var dataRepresentation: Data { blob }
    var publicKeyX963: Data { key.publicKey.x963Representation }

    func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963))
    }
}

struct SoftwareCustodyKey: EnclaveCustodyKey {
    enum Key {
        case p256Signing(P256.Signing.PrivateKey)
        case p256KeyAgreement(P256.KeyAgreement.PrivateKey)
        case mldsa65(MLDSA65.PrivateKey)
        case mldsa87(MLDSA87.PrivateKey)
        case mlkem768(MLKEM768.PrivateKey)
        case mlkem1024(MLKEM1024.PrivateKey)
    }

    let type: CustodyKeyType
    let key: Key
    let credentialHash: Data?

    init(type: CustodyKeyType, credentialHash: Data?) throws {
        self.type = type
        self.credentialHash = credentialHash
        switch type {
        case .p256Signing: key = .p256Signing(P256.Signing.PrivateKey())
        case .p256KeyAgreement: key = .p256KeyAgreement(P256.KeyAgreement.PrivateKey())
        case .mldsa65: key = .mldsa65(try MLDSA65.PrivateKey())
        case .mldsa87: key = .mldsa87(try MLDSA87.PrivateKey())
        case .mlkem768: key = .mlkem768(try MLKEM768.PrivateKey())
        case .mlkem1024: key = .mlkem1024(try MLKEM1024.PrivateKey())
        }
    }

    init(type: CustodyKeyType, serialized: Data, credentialHash: Data?) throws {
        self.type = type
        self.credentialHash = credentialHash
        switch type {
        case .p256Signing: key = .p256Signing(try P256.Signing.PrivateKey(rawRepresentation: serialized))
        case .p256KeyAgreement: key = .p256KeyAgreement(try P256.KeyAgreement.PrivateKey(rawRepresentation: serialized))
        case .mldsa65: key = .mldsa65(try MLDSA65.PrivateKey(integrityCheckedRepresentation: serialized))
        case .mldsa87: key = .mldsa87(try MLDSA87.PrivateKey(integrityCheckedRepresentation: serialized))
        case .mlkem768: key = .mlkem768(try MLKEM768.PrivateKey(integrityCheckedRepresentation: serialized))
        case .mlkem1024: key = .mlkem1024(try MLKEM1024.PrivateKey(integrityCheckedRepresentation: serialized))
        }
    }

    private var serialized: Data {
        switch key {
        case .p256Signing(let k): k.rawRepresentation
        case .p256KeyAgreement(let k): k.rawRepresentation
        case .mldsa65(let k): k.integrityCheckedRepresentation
        case .mldsa87(let k): k.integrityCheckedRepresentation
        case .mlkem768(let k): k.integrityCheckedRepresentation
        case .mlkem1024(let k): k.integrityCheckedRepresentation
        }
    }

    var dataRepresentation: Data {
        try! JSONEncoder().encode(SoftwareEnclave.CustodyBlob(type: type, key: serialized, credentialHash: credentialHash))
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
        let secret = try k.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963))
        return SensitiveBuffer(count: 32) { destination in secret.withUnsafeBytes { destination.copyMemory(from: $0) } }
    }

    func decapsulate(_ ciphertext: Data) throws -> SensitiveBuffer {
        let secret: SymmetricKey
        switch key {
        case .mlkem768(let k): secret = try k.decapsulate(ciphertext)
        case .mlkem1024(let k): secret = try k.decapsulate(ciphertext)
        default: throw VaultError.internalFailure("key type cannot decapsulate")
        }
        return SensitiveBuffer(count: secret.bitCount / 8) { destination in secret.withUnsafeBytes { destination.copyMemory(from: $0) } }
    }
}

/// Rows held in a dictionary. Nothing reaches the Keychain.
public final class InMemoryRowStore: RowStore, @unchecked Sendable {
    private let rows = OSAllocatedUnfairLock<[String: (data: Data, attribute: Data?)]>(initialState: [:])

    public init() {}

    public func read(account: String) throws(VaultError) -> Data? { rows.withLock { $0[account]?.data } }

    public func write(account: String, data: Data, attribute: Data?) throws(VaultError) { rows.withLock { $0[account] = (data, attribute) } }

    public func delete(account: String) throws(VaultError) { rows.withLock { $0[account] = nil } }

    public func accounts() throws(VaultError) -> [(account: String, attribute: Data?)] {
        rows.withLock { $0.map { ($0.key, $0.value.attribute) }.sorted { $0.0 < $1.0 } }
    }

    public func removeAll() { rows.withLock { $0.removeAll() } }
}

/// One SHA-256 over the passphrase and salt: no memory-hard work, for a vault
/// whose contents never outlive the process.
public struct SandboxStretcher: PassphraseStretcher {
    public init() {}

    public func stretch(passphrase: borrowing SensitiveBuffer, salt: Data, parameters: UnlockStretchParameters) throws -> SensitiveBuffer {
        var hasher = SHA256()
        passphrase.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        hasher.update(data: salt)
        let digest = Data(hasher.finalize())
        return SensitiveBuffer(count: digest.count) { $0.copyBytes(from: digest) }
    }
}

/// Presence that is never asked for.
public struct NoPromptAuthenticator: Authenticator {
    public init() {}

    public func authenticate(context: LAContext, reason: String) async throws(VaultError) {}
}
