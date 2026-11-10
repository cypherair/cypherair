import Foundation

/// One of the user's keys, as computed from its certificate at unlock.
public struct Key: Identifiable, Sendable, Equatable {
    /// Valid within one unlocked session. It is not the fingerprint, so an
    /// error or a log that carries it names no key.
    public struct ID: Hashable, Sendable {
        let value: UUID
    }

    public let id: ID
    public let name: String?
    public let email: String?
    public let fingerprint: String
    public let custody: Custody
    /// Only when the certificate is one of the shapes this app makes.
    public let shape: KeyShape?
    public let version: Int
    public let primary: Algorithm
    public let encryption: Algorithm?
    /// The creation time inside the key. For a key the app made it is the
    /// stamp, which lies up to 45 days early on purpose.
    public let created: Date
    /// The real moment the key was made or imported on this device.
    public let added: Date
    public let expires: Date?
    public let status: KeyStatus
    public let isDefault: Bool
    public let isBackedUp: Bool
    public let isQuantumSafe: Bool
}

public enum Custody: Sendable {
    case portable
    case deviceBound
}

/// The certificate shapes this app makes.
public enum KeyShape: Sendable {
    case v4Curve25519
    case v4P256
    case v6Curve25519
    case v6P256
    case v6Curve448
    case v6MlDsa65
    case v6MlDsa87
}

/// The real algorithm and size of a key, for every key.
public struct Algorithm: Sendable, Equatable {
    public enum Kind: Sendable {
        case rsa, dsa, elGamal, edDsaLegacy, ecdsa, ecdh, ed25519, x25519, ed448, x448
        case mlDsa65Ed25519, mlDsa87Ed448, mlKem768X25519, mlKem1024X448
        case unknown
    }

    public enum Curve: Sendable {
        case none, ed25519, curve25519, nistP256, nistP384, nistP521
        case brainpoolP256, brainpoolP384, brainpoolP512
        case unknown
    }

    public let kind: Kind
    public let curve: Curve
    /// Zero where a size says nothing.
    public let bits: Int
}

public enum KeyStatus: Sendable {
    case valid
    case expired
    case revoked
    case unusable
}

/// A period counted from the key's stamp, never a date: a date counted from
/// today would give away the real moment the stamp hides.
public enum Expiry: Sendable, Equatable {
    case never
    case after(days: Int)
}
