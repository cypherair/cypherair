import CryptoKit
import Foundation
import LocalAuthentication
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

    /// Public key lengths for the post-quantum tiers; P-256 uses the X9.63 shape.
    public var postQuantumPublicKeyLengths: (signing: Int, keyAgreement: Int)? {
        switch self {
        case .classicalP256: nil
        case .postQuantum: (signing: 1952, keyAgreement: 1184)
        case .postQuantumHigh: (signing: 2592, keyAgreement: 1568)
        }
    }

    /// Lengths of the classical scalars sealed as the split-custody half.
    public var splitCustodyClassicalSecretLengths: (signing: Int, keyAgreement: Int)? {
        switch self {
        case .classicalP256: nil
        case .postQuantum: (signing: 32, keyAgreement: 32)
        case .postQuantumHigh: (signing: 57, keyAgreement: 56)
        }
    }
}

public enum CustodyRole: String, CaseIterable, Hashable, Sendable, Codable {
    case signing
    case keyAgreement
}

public enum CustodyError: Error, Equatable, Sendable {
    case invalidHandleSetIdentifier
    case invalidPublicKey(CustodyRole)
    case invalidPeerPublicKey(CustodyRole)
    case hardwareUnavailable
    case locked
    case localAuthenticationCancelled(CustodyRole)
    case localAuthenticationFailed(CustodyRole)
    case localAuthenticationUnavailable(CustodyRole)
    case privateHandleMissing(CustodyRole)
    case privateHandleInaccessible(CustodyRole)
    case privateHandleUnauthorized(CustodyRole)
    case ambiguousPrivateHandle(CustodyRole)
    case privateOperationRoleMismatch(expected: CustodyRole, actual: CustodyRole)
    case handlePublicKeyBindingMismatch(CustodyRole)
    case partialHandlePair
    case cleanupOrRollbackFailed
    case storage(String)

    static func fromEnclave(_ error: any Error, role: CustodyRole) -> CustodyError {
        let mapped = (error as? VaultError) ?? VaultError.fromEnclaveOperation(error)
        switch mapped {
        case .authenticationCancelled: return .localAuthenticationCancelled(role)
        case .authenticationFailed: return .localAuthenticationFailed(role)
        case .authenticationUnavailable: return .localAuthenticationUnavailable(role)
        case .enclaveUnavailable: return .hardwareUnavailable
        case .locked: return .locked
        case .passphraseRejected: return .privateHandleUnauthorized(role)
        case .storage(let reason): return .storage(reason)
        default: return .privateHandleInaccessible(role)
        }
    }
}

/// One custody key's row: a random handle-set identifier shared by the pair, a
/// role, and a tier. Never a fingerprint.
public struct CustodyHandleReference: Hashable, Sendable {
    public let handleSetIdentifier: String
    public let role: CustodyRole
    public let tier: CustodyTier

    public init(handleSetIdentifier: String, role: CustodyRole, tier: CustodyTier) throws(CustodyError) {
        guard Self.isValidHandleSetIdentifier(handleSetIdentifier) else { throw .invalidHandleSetIdentifier }
        self.handleSetIdentifier = handleSetIdentifier
        self.role = role
        self.tier = tier
    }

    public var keyType: CustodyKeyType { tier.keyType(for: role) }

    public static func generateHandleSetIdentifier() throws(CustodyError) -> String {
        do {
            return try Randomness.bytes(count: 16).map { String(format: "%02x", $0) }.joined()
        } catch {
            throw .storage("randomness unavailable")
        }
    }

    public static func isValidHandleSetIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        return value.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }
}

/// A reference plus the public key its row advertises, readable without any
/// prompt. Lookup and binding checks run on this; the enclave key is
/// authoritative once loaded.
public struct CustodyPublicBinding: Hashable, Sendable {
    public static let p256X963PublicKeyByteCount = 65

    public let reference: CustodyHandleReference
    public let publicKeyRaw: Data

    public init(reference: CustodyHandleReference, publicKeyRaw: Data) throws(CustodyError) {
        guard Self.hasExpectedPublicKeyShape(publicKeyRaw, role: reference.role, tier: reference.tier) else {
            throw .invalidPublicKey(reference.role)
        }
        self.reference = reference
        self.publicKeyRaw = publicKeyRaw
    }

    public var role: CustodyRole { reference.role }

    public static func hasExpectedPublicKeyShape(_ publicKeyRaw: Data, role: CustodyRole, tier: CustodyTier) -> Bool {
        switch tier {
        case .classicalP256:
            return hasUncompressedP256X963PublicKeyShape(publicKeyRaw)
        case .postQuantum, .postQuantumHigh:
            guard let lengths = tier.postQuantumPublicKeyLengths else { return false }
            return publicKeyRaw.count == (role == .signing ? lengths.signing : lengths.keyAgreement)
        }
    }

    public static func hasUncompressedP256X963PublicKeyShape(_ data: Data) -> Bool {
        guard data.count == p256X963PublicKeyByteCount, data.first == 0x04 else { return false }
        return data.dropFirst().contains { $0 != 0 }
    }
}

/// The signing and key-agreement bindings of one identity: same handle-set
/// identifier, same tier, distinct public keys.
public struct CustodyHandlePair: Hashable, Sendable {
    public let signing: CustodyPublicBinding
    public let keyAgreement: CustodyPublicBinding

    public init(signing: CustodyPublicBinding, keyAgreement: CustodyPublicBinding) throws(CustodyError) {
        guard signing.role == .signing else { throw .privateOperationRoleMismatch(expected: .signing, actual: signing.role) }
        guard keyAgreement.role == .keyAgreement else { throw .privateOperationRoleMismatch(expected: .keyAgreement, actual: keyAgreement.role) }
        guard signing.reference.handleSetIdentifier == keyAgreement.reference.handleSetIdentifier,
              signing.reference.tier == keyAgreement.reference.tier,
              signing.publicKeyRaw != keyAgreement.publicKeyRaw else {
            throw .handlePublicKeyBindingMismatch(.keyAgreement)
        }
        self.signing = signing
        self.keyAgreement = keyAgreement
    }

    public var handleSetIdentifier: String { signing.reference.handleSetIdentifier }
    public var tier: CustodyTier { signing.reference.tier }
    public var references: [CustodyHandleReference] { [signing.reference, keyAgreement.reference] }
}

public struct CustodyInventory: Sendable {
    public let bindings: [CustodyPublicBinding]
    public let malformedRowCount: Int
    public var totalRowCount: Int { bindings.count + malformedRowCount }
}

/// A custody key reconstructed in the enclave with the caller's context, with
/// the checks every private operation runs before the enclave is asked.
public struct LoadedCustodyHandle {
    public let binding: CustodyPublicBinding
    let key: any EnclaveCustodyKey

    public var reference: CustodyHandleReference { binding.reference }
    public var role: CustodyRole { binding.role }

    /// P-256 ECDSA over a 32-byte SHA-256 digest, self-verified against the
    /// binding, returned as r and s.
    public func signDigest(_ digest: Data) throws(CustodyError) -> (r: Data, s: Data) {
        guard role == .signing else { throw .privateOperationRoleMismatch(expected: .signing, actual: role) }
        guard binding.reference.tier == .classicalP256, let rawDigest = RawSHA256Digest(digest) else {
            throw .privateHandleInaccessible(.signing)
        }
        let raw: Data
        do { raw = try key.signature(for: digest) } catch { throw CustodyError.fromEnclave(error, role: .signing) }
        guard raw.count == 64,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: binding.publicKeyRaw),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw),
              publicKey.isValidSignature(signature, for: rawDigest) else {
            throw .privateHandleInaccessible(.signing)
        }
        return (Data(raw.prefix(32)), Data(raw.suffix(32)))
    }

    /// ML-DSA over `message`, self-verified against the binding.
    public func signMessage(_ message: Data) throws(CustodyError) -> Data {
        guard role == .signing else { throw .privateOperationRoleMismatch(expected: .signing, actual: role) }
        let signature: Data
        do { signature = try key.signature(for: message) } catch { throw CustodyError.fromEnclave(error, role: .signing) }
        let valid: Bool
        switch binding.reference.tier {
        case .postQuantum: valid = (try? MLDSA65.PublicKey(rawRepresentation: binding.publicKeyRaw))?.isValidSignature(signature, for: message) ?? false
        case .postQuantumHigh: valid = (try? MLDSA87.PublicKey(rawRepresentation: binding.publicKeyRaw))?.isValidSignature(signature, for: message) ?? false
        case .classicalP256: valid = false
        }
        guard valid else { throw .privateHandleInaccessible(.signing) }
        return signature
    }

    /// P-256 ECDH with the message's ephemeral key, after checking the request
    /// names this handle's own public key.
    public func sharedSecret(recipientPublicKeyX963: Data, ephemeralPublicKeyX963: Data) throws(CustodyError) -> SensitiveBuffer {
        guard role == .keyAgreement else { throw .privateOperationRoleMismatch(expected: .keyAgreement, actual: role) }
        guard recipientPublicKeyX963 == binding.publicKeyRaw else { throw .handlePublicKeyBindingMismatch(.keyAgreement) }
        guard CustodyPublicBinding.hasUncompressedP256X963PublicKeyShape(ephemeralPublicKeyX963) else { throw .invalidPeerPublicKey(.keyAgreement) }
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

/// Device-bound custody keys: one row per key under a service per tier and
/// role, the public key in the row's attribute, the enclave blob as its value.
public struct CustodyKeyStore: Sendable {
    public static let servicePrefix = "com.cypherair.vault.custody"

    private let enclave: any Enclave
    private let rows: @Sendable (CustodyTier, CustodyRole) -> any RowStore

    public init(enclave: any Enclave, rows: @escaping @Sendable (CustodyTier, CustodyRole) -> any RowStore) {
        self.enclave = enclave
        self.rows = rows
    }

    public static func keychain(enclave: any Enclave) -> CustodyKeyStore {
        CustodyKeyStore(enclave: enclave) { tier, role in
            KeychainRowStore(service: "\(servicePrefix).\(tier.rawValue).\(role.rawValue)")
        }
    }

    /// Creates both keys of a new identity under one fresh handle-set
    /// identifier. Failure after the first key removes it again. Blocking while
    /// the enclave works; the caller's context should already be authenticated.
    public func createPair(tier: CustodyTier, session: UnlockedSession, context: LAContext) throws(CustodyError) -> (signing: LoadedCustodyHandle, keyAgreement: LoadedCustodyHandle) {
        let identifier = try CustodyHandleReference.generateHandleSetIdentifier()
        let signingReference = try CustodyHandleReference(handleSetIdentifier: identifier, role: .signing, tier: tier)
        let keyAgreementReference = try CustodyHandleReference(handleSetIdentifier: identifier, role: .keyAgreement, tier: tier)
        let signing = try create(signingReference, session: session, context: context)
        do {
            let keyAgreement = try create(keyAgreementReference, session: session, context: context)
            return (signing, keyAgreement)
        } catch {
            do { try delete([signingReference, keyAgreementReference]) } catch { throw .cleanupOrRollbackFailed }
            throw error
        }
    }

    /// Reconstructs one key, checking the row's advertised public key against
    /// what the caller expects and against the enclave's own answer.
    public func loadHandle(reference: CustodyHandleReference, expectedPublicKeyRaw: Data, session: UnlockedSession, context: LAContext) throws(CustodyError) -> LoadedCustodyHandle {
        guard CustodyPublicBinding.hasExpectedPublicKeyShape(expectedPublicKeyRaw, role: reference.role, tier: reference.tier) else {
            throw .invalidPublicKey(reference.role)
        }
        let store = rows(reference.tier, reference.role)
        let blob: Data?
        do { blob = try store.read(account: reference.handleSetIdentifier) } catch { throw .storage("read failed") }
        guard let blob else { throw .privateHandleMissing(reference.role) }
        let key: any EnclaveCustodyKey
        do {
            key = try reconstruct(reference.keyType, blob: blob, session: session, context: context)
        } catch {
            throw CustodyError.fromEnclave(error, role: reference.role)
        }
        guard key.publicKeyRaw == expectedPublicKeyRaw else { throw .handlePublicKeyBindingMismatch(reference.role) }
        return LoadedCustodyHandle(binding: try CustodyPublicBinding(reference: reference, publicKeyRaw: expectedPublicKeyRaw), key: key)
    }

    /// Finds the one pair whose advertised public keys match, without any prompt.
    public func locatePair(tier: CustodyTier, signingPublicKeyRaw: Data, keyAgreementPublicKeyRaw: Data) throws(CustodyError) -> CustodyHandlePair {
        guard CustodyPublicBinding.hasExpectedPublicKeyShape(signingPublicKeyRaw, role: .signing, tier: tier) else { throw .invalidPublicKey(.signing) }
        guard CustodyPublicBinding.hasExpectedPublicKeyShape(keyAgreementPublicKeyRaw, role: .keyAgreement, tier: tier) else { throw .invalidPublicKey(.keyAgreement) }
        var matches: [CustodyHandlePair] = []
        let groups = Dictionary(grouping: try inventory(tiers: [tier]).bindings, by: \.reference.handleSetIdentifier)
        for group in groups.values {
            let signing = group.first { $0.role == .signing }
            let keyAgreement = group.first { $0.role == .keyAgreement }
            switch (signing, keyAgreement) {
            case (.some(let s), .some(let k)):
                switch (s.publicKeyRaw == signingPublicKeyRaw, k.publicKeyRaw == keyAgreementPublicKeyRaw) {
                case (true, true): matches.append(try CustodyHandlePair(signing: s, keyAgreement: k))
                case (true, false): throw .handlePublicKeyBindingMismatch(.keyAgreement)
                case (false, true): throw .handlePublicKeyBindingMismatch(.signing)
                case (false, false): continue
                }
            case (.some(let s), nil) where s.publicKeyRaw == signingPublicKeyRaw: throw .partialHandlePair
            case (nil, .some(let k)) where k.publicKeyRaw == keyAgreementPublicKeyRaw: throw .partialHandlePair
            default: continue
            }
        }
        guard !matches.isEmpty else { throw .privateHandleMissing(.signing) }
        guard matches.count == 1 else { throw .ambiguousPrivateHandle(.signing) }
        return matches[0]
    }

    /// Every row's binding across the given tiers, no prompt, plus how many
    /// rows no longer decode to a valid binding.
    public func inventory(tiers: [CustodyTier] = CustodyTier.allCases) throws(CustodyError) -> CustodyInventory {
        var bindings: [CustodyPublicBinding] = []
        var malformed = 0
        for tier in tiers {
            for role in CustodyRole.allCases {
                let accounts: [(account: String, attribute: Data?)]
                do { accounts = try rows(tier, role).accounts() } catch { throw .storage("list failed") }
                for (account, attribute) in accounts {
                    guard let attribute,
                          let reference = try? CustodyHandleReference(handleSetIdentifier: account, role: role, tier: tier),
                          let binding = try? CustodyPublicBinding(reference: reference, publicKeyRaw: attribute) else {
                        malformed += 1
                        continue
                    }
                    bindings.append(binding)
                }
            }
        }
        return CustodyInventory(bindings: bindings, malformedRowCount: malformed)
    }

    public func deletePair(_ pair: CustodyHandlePair) throws(CustodyError) {
        try delete(pair.references)
    }

    /// Removes every custody row of every tier and role. Part of Reset All Local Data.
    public func deleteAll() throws(CustodyError) {
        for tier in CustodyTier.allCases {
            for role in CustodyRole.allCases {
                let store = rows(tier, role)
                do {
                    for (account, _) in try store.accounts() { try store.delete(account: account) }
                } catch {
                    throw .cleanupOrRollbackFailed
                }
            }
        }
    }

    private func create(_ reference: CustodyHandleReference, session: UnlockedSession, context: LAContext) throws(CustodyError) -> LoadedCustodyHandle {
        let store = rows(reference.tier, reference.role)
        do {
            guard try store.read(account: reference.handleSetIdentifier) == nil else { throw CustodyError.ambiguousPrivateHandle(reference.role) }
        } catch let error as CustodyError {
            throw error
        } catch {
            throw .storage("read failed")
        }
        let key: any EnclaveCustodyKey
        do {
            let type = reference.keyType
            key = type.policy.requiresCredential
                ? try session.withIdentityCredential { credential in try enclave.makeCustodyKey(type: type, credential: credential, context: context) }
                : try enclave.makeCredentialFreeCustodyKey(type: type, context: context)
        } catch {
            throw CustodyError.fromEnclave(error, role: reference.role)
        }
        let binding = try CustodyPublicBinding(reference: reference, publicKeyRaw: key.publicKeyRaw)
        do { try store.write(account: reference.handleSetIdentifier, data: key.dataRepresentation, attribute: key.publicKeyRaw) } catch { throw .storage("write failed") }
        return LoadedCustodyHandle(binding: binding, key: key)
    }

    private func reconstruct(_ type: CustodyKeyType, blob: Data, session: UnlockedSession, context: LAContext) throws -> any EnclaveCustodyKey {
        if type.policy.requiresCredential {
            try session.withIdentityCredential { credential in try enclave.custodyKey(type: type, from: blob, credential: credential, context: context) }
        } else {
            try enclave.credentialFreeCustodyKey(type: type, from: blob, context: context)
        }
    }

    private func delete(_ references: [CustodyHandleReference]) throws(CustodyError) {
        for reference in references {
            do { try rows(reference.tier, reference.role).delete(account: reference.handleSetIdentifier) } catch { throw .storage("delete failed") }
        }
    }
}
