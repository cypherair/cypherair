import Vault

public enum StoreError: Error, Equatable, Sendable {
    /// The volume cannot provide complete file protection; nothing is written.
    case fileProtectionUnsupported
    case fileProtectionVerificationFailed
    /// The file or row does not exist.
    case missing
    /// The file or row exists but does not authenticate or decode.
    case damaged
    case invalidFingerprint
    case io(String)
    case vault(VaultError)
    case internalFailure(String)
}
