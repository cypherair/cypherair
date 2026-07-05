import CryptoKit
import Foundation

/// Identity of one Secure Enclave composite (post-quantum) private-key blob in
/// the data-protection keychain. Composite handles reuse the custody handle-set
/// vocabulary: one set identifier binds the ML-DSA-65 signing key and the
/// ML-KEM-768 key-agreement key of a single Device-Bound Post-Quantum identity.
///
/// Unlike P-256 custody handles (SecKey items, `kSecClassKey`), CryptoKit's
/// Secure Enclave post-quantum keys persist as opaque `dataRepresentation`
/// blobs, so composite handles live in `kSecClassGenericPassword` rows:
/// service encodes the role, account is the handle-set identifier, and
/// `kSecAttrGeneric` carries the component public key for non-prompting lookup.
struct SecureEnclaveCompositeHandleReference: Hashable, Sendable {
    static let servicePrefix = "\(KeychainConstants.prefix).secure-enclave-composite"

    let handleSetIdentifier: String
    let role: PGPPrivateOperationRole

    init(handleSetIdentifier: String, role: PGPPrivateOperationRole) throws {
        guard SecureEnclaveCompositeHandleReference.isValidHandleSetIdentifier(handleSetIdentifier) else {
            throw SecureEnclaveCustodyHandleError.invalidHandleSetIdentifier
        }
        self.handleSetIdentifier = handleSetIdentifier
        self.role = role
    }

    var serviceString: String {
        "\(Self.servicePrefix).\(role.rawValue)"
    }

    var accountString: String {
        handleSetIdentifier
    }

    static func isValidHandleSetIdentifier(_ identifier: String) -> Bool {
        !identifier.isEmpty && identifier.allSatisfy { $0.isHexDigit }
    }

    static func role(forServiceString service: String) -> PGPPrivateOperationRole? {
        let prefix = "\(servicePrefix)."
        guard service.hasPrefix(prefix) else {
            return nil
        }
        return PGPPrivateOperationRole(rawValue: String(service.dropFirst(prefix.count)))
    }
}

/// Public binding of one composite handle: the FIPS 204/203 raw public key the
/// certificate carries for this role, used to locate and verify handles without
/// touching the private blob.
struct SecureEnclaveCompositeHandlePublicBinding: Hashable, Sendable {
    static let mldsa65PublicKeyLength = 1952
    static let mlkem768PublicKeyLength = 1184

    let reference: SecureEnclaveCompositeHandleReference
    let publicKeyRaw: Data

    init(
        reference: SecureEnclaveCompositeHandleReference,
        publicKeyRaw: Data
    ) throws {
        guard Self.hasExpectedPublicKeyShape(publicKeyRaw, role: reference.role) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }
        self.reference = reference
        self.publicKeyRaw = publicKeyRaw
    }

    static func hasExpectedPublicKeyShape(_ publicKeyRaw: Data, role: PGPPrivateOperationRole) -> Bool {
        switch role {
        case .signing:
            return publicKeyRaw.count == mldsa65PublicKeyLength
        case .keyAgreement:
            return publicKeyRaw.count == mlkem768PublicKeyLength
        }
    }
}

/// The two public bindings of one Device-Bound Post-Quantum identity.
struct SecureEnclaveCompositeHandlePair: Hashable, Sendable {
    let signing: SecureEnclaveCompositeHandlePublicBinding
    let keyAgreement: SecureEnclaveCompositeHandlePublicBinding

    init(
        signing: SecureEnclaveCompositeHandlePublicBinding,
        keyAgreement: SecureEnclaveCompositeHandlePublicBinding
    ) throws {
        guard signing.reference.role == .signing,
              keyAgreement.reference.role == .keyAgreement,
              signing.reference.handleSetIdentifier == keyAgreement.reference.handleSetIdentifier else {
            throw SecureEnclaveCustodyHandleError.partialHandlePair
        }
        self.signing = signing
        self.keyAgreement = keyAgreement
    }

    var handleSetIdentifier: String {
        signing.reference.handleSetIdentifier
    }

    var references: [SecureEnclaveCompositeHandleReference] {
        [signing.reference, keyAgreement.reference]
    }
}

/// A reconstructed CryptoKit Secure Enclave post-quantum private key for one
/// role, validated against its stored public binding. The private key never
/// leaves the Secure Enclave; the reconstructed value is a handle whose
/// operations the enclave gates through the access policy baked in at creation.
struct SecureEnclaveCompositeLoadedHandle {
    enum PrivateKey {
        case mldsa65Signing(SecureEnclave.MLDSA65.PrivateKey)
        case mlkem768KeyAgreement(SecureEnclave.MLKEM768.PrivateKey)
    }

    let binding: SecureEnclaveCompositeHandlePublicBinding
    let privateKey: PrivateKey

    var reference: SecureEnclaveCompositeHandleReference {
        binding.reference
    }

    var role: PGPPrivateOperationRole {
        binding.reference.role
    }
}

/// Both reconstructed handles of one identity, produced inside a single
/// authorized operation window at generation time.
struct SecureEnclaveCompositeLoadedHandlePair {
    let signing: SecureEnclaveCompositeLoadedHandle
    let keyAgreement: SecureEnclaveCompositeLoadedHandle

    init(
        signing: SecureEnclaveCompositeLoadedHandle,
        keyAgreement: SecureEnclaveCompositeLoadedHandle
    ) throws {
        guard signing.role == .signing,
              keyAgreement.role == .keyAgreement,
              signing.reference.handleSetIdentifier == keyAgreement.reference.handleSetIdentifier else {
            throw SecureEnclaveCustodyHandleError.partialHandlePair
        }
        self.signing = signing
        self.keyAgreement = keyAgreement
    }
}
