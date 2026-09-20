import Foundation
import LocalAuthentication

/// Failures of the vault, as stable categories. A refused passphrase, a failed
/// presence check, and a damaged sealed root are three different facts and stay
/// three different cases.
public enum VaultError: Error, Equatable, Sendable {
    case enclaveUnavailable
    case noSealedRoot
    case sealedRootCorrupt
    /// The enclave refused the operation because the application password was
    /// wrong: the passphrase does not match.
    case passphraseRejected
    case authenticationCancelled
    case authenticationFailed
    case authenticationUnavailable
    /// The session was relocked; its keys are gone.
    case locked
    case storage(String)
    case internalFailure(String)

    /// Maps an error thrown by the enclave or by local authentication during an
    /// operation on a password-protected key.
    public static func fromEnclaveOperation(_ error: any Error) -> VaultError {
        let nsError = error as NSError
        if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
            return fromLocalAuthentication(code)
        }
        if nsError.domain == "CryptoTokenKit", nsError.code == -3 {
            return .passphraseRejected
        }
        return .internalFailure("enclave operation failed")
    }

    public static func fromLocalAuthentication(_ code: LAError.Code) -> VaultError {
        switch code {
        case .userCancel, .appCancel, .systemCancel:
            .authenticationCancelled
        case .authenticationFailed, .userFallback, .notInteractive:
            .authenticationFailed
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet:
            .authenticationUnavailable
        default:
            .authenticationFailed
        }
    }
}
