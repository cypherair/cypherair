import CryptoKit
import Foundation
import LocalAuthentication
import Sealing
import Vault
import os

/// A software enclave for the unit lane. Records every policy it creates a key
/// under and refuses to use a password-protected key without the credential it
/// was created with, mirroring what the real enclave does.
public final class FakeEnclave: Enclave, @unchecked Sendable {
    public struct Blob: Codable {
        let raw: Data
        let policy: String
        let credentialHash: Data?
    }

    private let state = OSAllocatedUnfairLock(initialState: (created: [EnclaveAccessPolicy](), available: true))

    public init() {}

    public var isAvailable: Bool {
        get { state.withLock { $0.available } }
        set { state.withLock { $0.available = newValue } }
    }

    public var createdPolicies: [EnclaveAccessPolicy] { state.withLock { $0.created } }

    public func makeKeyAgreementKey(policy: EnclaveAccessPolicy, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        guard policy.requiresCredential else { throw VaultError.internalFailure("key-agreement keys always carry a credential") }
        let key = P256.KeyAgreement.PrivateKey()
        let blob = try JSONEncoder().encode(Blob(raw: key.rawRepresentation, policy: policy.rawValue, credentialHash: Self.hash(credential)))
        state.withLock { $0.created.append(policy) }
        return FakeKey(key: key, blob: blob)
    }

    public func keyAgreementKey(from blob: Data, credential: borrowing SensitiveBuffer, context: LAContext) throws -> any EnclaveKeyAgreementKey {
        let decoded = try JSONDecoder().decode(Blob.self, from: blob)
        guard decoded.credentialHash == Self.hash(credential) else {
            throw NSError(domain: "CryptoTokenKit", code: -3, userInfo: [NSDebugDescriptionErrorKey: "fake enclave: unable to compute shared secret"])
        }
        return FakeKey(key: try P256.KeyAgreement.PrivateKey(rawRepresentation: decoded.raw), blob: blob)
    }

    private static func hash(_ credential: borrowing SensitiveBuffer) -> Data {
        credential.withUnsafeBytes { Data(SHA256.hash(data: $0)) }
    }

    struct FakeKey: EnclaveKeyAgreementKey {
        let key: P256.KeyAgreement.PrivateKey
        let blob: Data
        var dataRepresentation: Data { blob }
        var publicKeyX963: Data { key.publicKey.x963Representation }
        func sharedSecret(withEphemeralPublicKeyX963 x963: Data) throws -> SharedSecret {
            try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963))
        }
    }
}

public final class InMemoryRowStore: RowStore, @unchecked Sendable {
    private let rows = OSAllocatedUnfairLock<[String: (data: Data, attribute: Data?)]>(initialState: [:])
    public init() {}
    public func read(account: String) throws(VaultError) -> Data? { rows.withLock { $0[account]?.data } }
    public func write(account: String, data: Data, attribute: Data?) throws(VaultError) { rows.withLock { $0[account] = (data, attribute) } }
    public func delete(account: String) throws(VaultError) { rows.withLock { $0[account] = nil } }
    public func accounts() throws(VaultError) -> [(account: String, attribute: Data?)] {
        rows.withLock { $0.map { ($0.key, $0.value.attribute) }.sorted { $0.0 < $1.0 } }
    }
    /// Flips one byte of a row's value, for damage tests.
    public func corrupt(account: String) {
        rows.withLock { if var row = $0[account], !row.data.isEmpty { row.data[row.data.count / 2] ^= 0xFF; $0[account] = row } }
    }
}

/// SHA-256 over passphrase and salt: deterministic and instant, for tests only.
public struct FakeStretcher: PassphraseStretcher {
    public init() {}
    public func stretch(passphrase: borrowing SensitiveBuffer, salt: Data, parameters: UnlockStretchParameters) throws -> SensitiveBuffer {
        var hasher = SHA256()
        passphrase.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        hasher.update(data: salt)
        let digest = Data(hasher.finalize())
        return SensitiveBuffer(count: digest.count) { $0.copyBytes(from: digest) }
    }
}

/// Never prompts; counts how often it was asked.
public final class CountingAuthenticator: Authenticator, @unchecked Sendable {
    private let count = OSAllocatedUnfairLock(initialState: 0)
    public var failure: VaultError?
    public init() {}
    public var prompts: Int { count.withLock { $0 } }
    public func authenticate(context: LAContext, reason: String) async throws(VaultError) {
        count.withLock { $0 += 1 }
        if let failure { throw failure }
    }
}

public extension SensitiveBuffer {
    static func text(_ string: String) -> SensitiveBuffer {
        let bytes = Array(string.utf8)
        return SensitiveBuffer(count: bytes.count) { $0.copyBytes(from: bytes) }
    }
}
