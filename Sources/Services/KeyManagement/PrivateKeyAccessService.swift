import Foundation

/// Owns Secure Enclave reconstruction and secret-certificate-material unwrap for callers.
final class PrivateKeyAccessService {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore
    private let authenticationPromptCoordinator: AuthenticationPromptCoordinator

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore,
        authenticationPromptCoordinator: AuthenticationPromptCoordinator
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
        self.authenticationPromptCoordinator = authenticationPromptCoordinator
    }

    /// Triggers device authentication and returns the unwrapped secret certificate material.
    /// Callers must zeroize the returned data after use.
    func unwrapPrivateKey(fingerprint: String) throws -> Data {
        try authenticationPromptCoordinator.withOperationPrompt {
            let bundle = try bundleStore.loadBundle(fingerprint: fingerprint)
            let handle = try secureEnclave.reconstructKey(from: bundle.seKeyData)
            return try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
        }
    }
}
