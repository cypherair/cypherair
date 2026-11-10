internal import Stores
internal import Vault

/// The mapping from the vault's errors. A refused passphrase, a failed
/// approval and damaged storage stay three different cases.
extension CoreError {
    init(_ error: VaultError) {
        self = switch error {
        case .passphraseRejected: .wrongPassphrase
        case .authenticationCancelled: .cancelled
        case .authenticationFailed: .authenticationFailed
        case .authenticationUnavailable, .enclaveUnavailable: .authenticationUnavailable
        case .locked: .locked
        case .noSealedRoot, .sealedRootCorrupt: .storageDamaged
        case .storage: .storageFailed
        case .internalFailure: .internalFailure
        }
    }

    /// Unlock sorts a sealed file that cannot be used into the damage report.
    /// Here a store error is damage that appeared later, or a sealed secret
    /// that does not open. Step 2 of the private-key path reports material
    /// that fails `SealedSecret.check` as `keyMaterialMissing` itself.
    init(_ error: StoreError) {
        self = switch error {
        case .missing, .damaged, .otherVersion: .storageDamaged
        case .fileProtectionUnsupported, .fileProtectionVerificationFailed, .io: .storageFailed
        case .vault(let error): CoreError(error)
        case .internalFailure: .internalFailure
        }
    }

    init(_ error: CustodyError) {
        self = switch error {
        case .locked: .locked
        case .localAuthenticationCancelled: .cancelled
        case .localAuthenticationFailed: .authenticationFailed
        case .localAuthenticationUnavailable, .hardwareUnavailable: .authenticationUnavailable
        case .privateHandleInaccessible, .privateHandleUnauthorized, .handlePublicKeyBindingMismatch, .invalidPeerPublicKey: .deviceKeyFailed
        case .invalidPublicKey, .approvalKindMismatch, .privateOperationRoleMismatch: .internalFailure
        }
    }
}
