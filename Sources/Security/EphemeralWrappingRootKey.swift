import Foundation
import Security

/// Per-session wrapping root key for ephemeral sandbox ProtectedData domains
/// (the guided tutorial container and the DEBUG UI-test container).
///
/// Always drawn from `SecRandomCopyBytes` — a sandbox root key must satisfy the
/// same secure-random constraint as production key material even though it
/// only ever protects throwaway sandbox data. The owning container is
/// responsible for zeroizing the returned key when its session ends.
enum EphemeralWrappingRootKey {
    /// The secure random source reported failure; the sandbox must not start.
    struct RandomSourceFailure: Error {}

    static let byteCount = 32

    static func generate() throws -> Data {
        var key = Data(count: byteCount)
        let status = key.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, byteCount, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw RandomSourceFailure()
        }
        return key
    }
}
