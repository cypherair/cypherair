import CryptoKit
import Foundation

/// The two session values and the per-domain keys, all HKDF-SHA256 over the
/// root secret with distinct labels. Nothing derived here is ever stored.
public enum RootDerivations {
    public static let rootSecretLength = 32
    public static let identityCredentialLength = 32

    /// The key every protected-data domain key is derived from.
    public static func wrappingRootKey(rootSecret: borrowing SensitiveBuffer) -> SymmetricKey {
        derive(from: rootSecret, label: "CypherAir vault v1: wrapping root key")
    }

    /// The application password of every identity key.
    public static func identityCredential(rootSecret: borrowing SensitiveBuffer) -> SensitiveBuffer {
        let key = derive(from: rootSecret, label: "CypherAir vault v1: identity credential")
        return SensitiveBuffer(count: identityCredentialLength) { destination in
            key.withUnsafeBytes { destination.copyMemory(from: $0) }
        }
    }

    /// One domain's key. `domain` is the domain's fixed identifier.
    public static func domainKey(wrappingRootKey: SymmetricKey, domain: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: wrappingRootKey,
            salt: Data(),
            info: Data("CypherAir vault v1: domain key: \(domain)".utf8),
            outputByteCount: 32
        )
    }

    private static func derive(from rootSecret: borrowing SensitiveBuffer, label: String) -> SymmetricKey {
        let material = rootSecret.withUnsafeBytes { SymmetricKey(data: $0) }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: material,
            salt: Data(),
            info: Data(label.utf8),
            outputByteCount: 32
        )
    }
}
