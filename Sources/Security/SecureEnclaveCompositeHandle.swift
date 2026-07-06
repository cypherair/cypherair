import CryptoKit
import Foundation

/// The RFC 9980 composite parameter-set tier of a split-custody Secure Enclave
/// key set. It selects which CryptoKit Secure Enclave key types back the two
/// component handles, their FIPS 204/203 public-key byte lengths, and the
/// keychain service namespace — so the two tiers never collide.
///
/// `.postQuantum` keeps the original, suffix-less keychain namespace, so
/// existing Device-Bound Post-Quantum handles are byte-identical after this
/// tier axis was introduced.
enum SecureEnclaveCompositeTier: String, CaseIterable, Hashable, Sendable {
    /// ML-DSA-65 + ML-KEM-768 (Device-Bound Post-Quantum).
    case postQuantum
    /// ML-DSA-87 + ML-KEM-1024 (Device-Bound Post-Quantum · High).
    case postQuantumHigh

    /// FIPS 204 ML-DSA verification-key length for this tier's signing handle.
    var signingPublicKeyLength: Int {
        switch self {
        case .postQuantum: 1952
        case .postQuantumHigh: 2592
        }
    }

    /// FIPS 203 ML-KEM encapsulation-key length for this tier's key-agreement handle.
    var keyAgreementPublicKeyLength: Int {
        switch self {
        case .postQuantum: 1184
        case .postQuantumHigh: 1568
        }
    }

    /// Raw byte length of the classical signing component secret Rust generates
    /// and this app seals: a 32-byte Ed25519 scalar, or a 57-byte Ed448 scalar.
    var classicalSigningSecretLength: Int {
        switch self {
        case .postQuantum: 32
        case .postQuantumHigh: 57
        }
    }

    /// Raw byte length of the classical key-agreement component secret: a
    /// 32-byte X25519 scalar, or a 56-byte X448 scalar.
    var classicalKeyAgreementSecretLength: Int {
        switch self {
        case .postQuantum: 32
        case .postQuantumHigh: 56
        }
    }

    /// Keychain service-prefix suffix. Empty for `.postQuantum` so its handles
    /// keep their original namespace; distinct for `.postQuantumHigh`.
    var serviceNamespaceSuffix: String {
        switch self {
        case .postQuantum: ""
        case .postQuantumHigh: ".high"
        }
    }
}

extension PGPKeyConfiguration.Identity {
    /// The Secure Enclave composite (split-custody) tier this key family runs
    /// on, or nil for every non-composite or software-custody family. This is
    /// the single dispatch key for routing, generation, and deletion of
    /// device-bound post-quantum keys: an exhaustive switch, so adding a family
    /// forces the author to classify it (a missing arm fails to compile), and
    /// the software post-quantum families deliberately map to nil so they never
    /// reach the Secure Enclave custody paths.
    var deviceBoundCompositeTier: SecureEnclaveCompositeTier? {
        switch self {
        case .deviceBoundPostQuantumV6:
            return .postQuantum
        case .deviceBoundPostQuantumHighV6:
            return .postQuantumHigh
        case .compatibleSoftwareV4, .modernSoftwareV6, .modernHighSoftwareV6,
             .postQuantumSoftwareV6, .postQuantumHighSoftwareV6,
             .compatibleP256V4, .modernP256V6:
            return nil
        }
    }
}

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
    let tier: SecureEnclaveCompositeTier

    init(
        handleSetIdentifier: String,
        role: PGPPrivateOperationRole,
        tier: SecureEnclaveCompositeTier = .postQuantum
    ) throws {
        guard SecureEnclaveCompositeHandleReference.isValidHandleSetIdentifier(handleSetIdentifier) else {
            throw SecureEnclaveCustodyHandleError.invalidHandleSetIdentifier
        }
        self.handleSetIdentifier = handleSetIdentifier
        self.role = role
        self.tier = tier
    }

    var serviceString: String {
        "\(Self.servicePrefix)\(tier.serviceNamespaceSuffix).\(role.rawValue)"
    }

    var accountString: String {
        handleSetIdentifier
    }

    static func isValidHandleSetIdentifier(_ identifier: String) -> Bool {
        !identifier.isEmpty && identifier.allSatisfy { $0.isHexDigit }
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
        guard Self.hasExpectedPublicKeyShape(
            publicKeyRaw,
            role: reference.role,
            tier: reference.tier
        ) else {
            throw SecureEnclaveCustodyHandleError.invalidPublicKey(reference.role)
        }
        self.reference = reference
        self.publicKeyRaw = publicKeyRaw
    }

    static func hasExpectedPublicKeyShape(
        _ publicKeyRaw: Data,
        role: PGPPrivateOperationRole,
        tier: SecureEnclaveCompositeTier = .postQuantum
    ) -> Bool {
        switch role {
        case .signing:
            return publicKeyRaw.count == tier.signingPublicKeyLength
        case .keyAgreement:
            return publicKeyRaw.count == tier.keyAgreementPublicKeyLength
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
        case mldsa87Signing(SecureEnclave.MLDSA87.PrivateKey)
        case mlkem1024KeyAgreement(SecureEnclave.MLKEM1024.PrivateKey)
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
