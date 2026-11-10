import CryptoKit
import Foundation
import Sealing
import Vault

public enum CustodyTier: String, CaseIterable, Hashable, Sendable, Codable {
    case classicalP256 = "p256"
    case postQuantum = "post-quantum"
    case postQuantumHigh = "post-quantum-high"

    public func keyType(for role: CustodyRole) -> CustodyKeyType {
        switch (self, role) {
        case (.classicalP256, .signing): .p256Signing
        case (.classicalP256, .keyAgreement): .p256KeyAgreement
        case (.postQuantum, .signing): .mldsa65
        case (.postQuantum, .keyAgreement): .mlkem768
        case (.postQuantumHigh, .signing): .mldsa87
        case (.postQuantumHigh, .keyAgreement): .mlkem1024
        }
    }

    /// Whether `publicKeyRaw` has the shape of this tier's key for `role`: an
    /// uncompressed X9.63 point for P-256, the raw key's length for ML-DSA and ML-KEM.
    public func acceptsPublicKey(_ publicKeyRaw: Data, role: CustodyRole) -> Bool {
        switch (self, role) {
        case (.classicalP256, _): Self.isUncompressedP256Point(publicKeyRaw)
        case (.postQuantum, .signing): publicKeyRaw.count == 1952
        case (.postQuantum, .keyAgreement): publicKeyRaw.count == 1184
        case (.postQuantumHigh, .signing): publicKeyRaw.count == 2592
        case (.postQuantumHigh, .keyAgreement): publicKeyRaw.count == 1568
        }
    }

    static func isUncompressedP256Point(_ data: Data) -> Bool {
        guard data.count == 65, data.first == 0x04 else { return false }
        return data.dropFirst().contains { $0 != 0 }
    }
}

public enum CustodyRole: String, CaseIterable, Hashable, Sendable, Codable {
    case signing
    case keyAgreement
}

public enum CustodyError: Error, Equatable, Sendable {
    case invalidPublicKey(CustodyRole)
    case invalidPeerPublicKey(CustodyRole)
    case hardwareUnavailable
    case locked
    /// A device-bound key needs a biometric approval; a presence approval may
    /// have been satisfied by the passcode.
    case approvalKindMismatch
    case approvalEnded
    case localAuthenticationCancelled(CustodyRole)
    case localAuthenticationFailed(CustodyRole)
    case localAuthenticationUnavailable(CustodyRole)
    case privateHandleInaccessible(CustodyRole)
    case privateHandleUnauthorized(CustodyRole)
    case privateOperationRoleMismatch(expected: CustodyRole, actual: CustodyRole)
    case handlePublicKeyBindingMismatch(CustodyRole)

    static func fromEnclave(_ error: any Error, role: CustodyRole) -> CustodyError {
        let mapped = (error as? VaultError) ?? VaultError.fromEnclaveOperation(error)
        switch mapped {
        case .authenticationCancelled: return .localAuthenticationCancelled(role)
        case .authenticationFailed: return .localAuthenticationFailed(role)
        case .authenticationUnavailable: return .localAuthenticationUnavailable(role)
        case .enclaveUnavailable: return .hardwareUnavailable
        case .locked: return .locked
        case .passphraseRejected: return .privateHandleUnauthorized(role)
        default: return .privateHandleInaccessible(role)
        }
    }
}

/// A custody key reconstructed or created in the enclave under an approval,
/// with the checks every private operation runs before the enclave is asked.
public struct LoadedCustodyHandle {
    public let tier: CustodyTier
    public let role: CustodyRole
    /// The public key the handle answers for. For a loaded handle it is the
    /// one the caller expected, and the enclave key's own public key matched it.
    public let publicKey: Data
    let key: any EnclaveCustodyKey

    /// The enclave key's blob, inert off this device. The caller stores it
    /// inside the sealed key list; it has no row.
    public var blob: Data { key.dataRepresentation }

    /// P-256 ECDSA over a 32-byte SHA-256 digest, self-verified against the
    /// public key, returned as r and s.
    public func signDigest(_ digest: Data) throws(CustodyError) -> (r: Data, s: Data) {
        guard role == .signing else { throw .privateOperationRoleMismatch(expected: .signing, actual: role) }
        guard tier == .classicalP256, let rawDigest = RawSHA256Digest(digest) else {
            throw .privateHandleInaccessible(.signing)
        }
        let raw: Data
        do { raw = try key.signature(for: digest) } catch { throw CustodyError.fromEnclave(error, role: .signing) }
        guard raw.count == 64,
              let verifier = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw),
              verifier.isValidSignature(signature, for: rawDigest) else {
            throw .privateHandleInaccessible(.signing)
        }
        return (Data(raw.prefix(32)), Data(raw.suffix(32)))
    }

    /// ML-DSA over `message`, self-verified against the public key.
    public func signMessage(_ message: Data) throws(CustodyError) -> Data {
        guard role == .signing else { throw .privateOperationRoleMismatch(expected: .signing, actual: role) }
        let signature: Data
        do { signature = try key.signature(for: message) } catch { throw CustodyError.fromEnclave(error, role: .signing) }
        let valid: Bool
        switch tier {
        case .postQuantum: valid = (try? MLDSA65.PublicKey(rawRepresentation: publicKey))?.isValidSignature(signature, for: message) ?? false
        case .postQuantumHigh: valid = (try? MLDSA87.PublicKey(rawRepresentation: publicKey))?.isValidSignature(signature, for: message) ?? false
        case .classicalP256: valid = false
        }
        guard valid else { throw .privateHandleInaccessible(.signing) }
        return signature
    }

    /// P-256 ECDH with the message's ephemeral key, after checking the request
    /// names this handle's own public key.
    public func sharedSecret(recipientPublicKeyX963: Data, ephemeralPublicKeyX963: Data) throws(CustodyError) -> SensitiveBuffer {
        guard role == .keyAgreement else { throw .privateOperationRoleMismatch(expected: .keyAgreement, actual: role) }
        guard recipientPublicKeyX963 == publicKey else { throw .handlePublicKeyBindingMismatch(.keyAgreement) }
        guard CustodyTier.isUncompressedP256Point(ephemeralPublicKeyX963) else { throw .invalidPeerPublicKey(.keyAgreement) }
        let secret: SensitiveBuffer
        do { secret = try key.sharedSecret(withEphemeralPublicKeyX963: ephemeralPublicKeyX963) } catch { throw CustodyError.fromEnclave(error, role: .keyAgreement) }
        guard secret.count == 32, secret.withUnsafeBytes({ $0.contains { $0 != 0 } }) else { throw .privateHandleInaccessible(.keyAgreement) }
        return secret
    }

    /// ML-KEM decapsulation of `ciphertext`.
    public func decapsulate(_ ciphertext: Data) throws(CustodyError) -> SensitiveBuffer {
        guard role == .keyAgreement else { throw .privateOperationRoleMismatch(expected: .keyAgreement, actual: role) }
        do { return try key.decapsulate(ciphertext) } catch { throw CustodyError.fromEnclave(error, role: .keyAgreement) }
    }
}

/// Device-bound custody keys. The store keeps nothing: a new pair comes back
/// with its two blobs for the caller to keep inside the sealed key list, and a
/// handle is loaded from a blob the caller hands in. The tier comes from the
/// certificate's shape, the role from the operation.
public struct CustodyKeyStore: Sendable {
    private let enclave: any Enclave

    public init(enclave: any Enclave) {
        self.enclave = enclave
    }

    /// Creates both keys of a new device-bound key under the operation's
    /// biometric approval, with the identity credential of the session that
    /// gave it. Blocking.
    public func createPair(tier: CustodyTier, approval: OperationApproval) throws(CustodyError) -> (signing: LoadedCustodyHandle, keyAgreement: LoadedCustodyHandle) {
        try Self.check(approval)
        let signing = try create(tier: tier, role: .signing, approval: approval)
        let keyAgreement = try create(tier: tier, role: .keyAgreement, approval: approval)
        return (signing, keyAgreement)
    }

    /// Reconstructs one key from its blob under the operation's biometric
    /// approval, and refuses it unless the enclave key's own public key is the
    /// one the caller expects. Blocking.
    public func loadHandle(
        role: CustodyRole,
        tier: CustodyTier,
        blob: Data,
        expectedPublicKey: Data,
        approval: OperationApproval
    ) throws(CustodyError) -> LoadedCustodyHandle {
        try Self.check(approval)
        guard tier.acceptsPublicKey(expectedPublicKey, role: role) else { throw .invalidPublicKey(role) }
        let type = tier.keyType(for: role)
        let key: any EnclaveCustodyKey
        do {
            if type.policy.requiresCredential {
                key = try approval.session.withIdentityCredential { credential in
                    try enclave.custodyKey(type: type, from: blob, credential: credential, context: approval.context)
                }
            } else {
                key = try enclave.credentialFreeCustodyKey(type: type, from: blob, context: approval.context)
            }
        } catch {
            throw CustodyError.fromEnclave(error, role: role)
        }
        guard key.publicKeyRaw == expectedPublicKey else { throw .handlePublicKeyBindingMismatch(role) }
        return LoadedCustodyHandle(tier: tier, role: role, publicKey: expectedPublicKey, key: key)
    }

    private static func check(_ approval: OperationApproval) throws(CustodyError) {
        do {
            try approval.checkUsable()
        } catch {
            throw error == .approvalEnded ? .approvalEnded : .locked
        }
        guard approval.kind == .biometrics else { throw .approvalKindMismatch }
    }

    private func create(tier: CustodyTier, role: CustodyRole, approval: OperationApproval) throws(CustodyError) -> LoadedCustodyHandle {
        let type = tier.keyType(for: role)
        let key: any EnclaveCustodyKey
        do {
            if type.policy.requiresCredential {
                key = try approval.session.withIdentityCredential { credential in
                    try enclave.makeCustodyKey(type: type, credential: credential, context: approval.context)
                }
            } else {
                key = try enclave.makeCredentialFreeCustodyKey(type: type, context: approval.context)
            }
        } catch {
            throw CustodyError.fromEnclave(error, role: role)
        }
        guard tier.acceptsPublicKey(key.publicKeyRaw, role: role) else { throw .invalidPublicKey(role) }
        return LoadedCustodyHandle(tier: tier, role: role, publicKey: key.publicKeyRaw, key: key)
    }
}
