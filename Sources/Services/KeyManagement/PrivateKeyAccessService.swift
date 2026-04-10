import Foundation

/// Owns Secure Enclave reconstruction and raw private-key unwrap for callers.
final class PrivateKeyAccessService {
    private let secureEnclave: any SecureEnclaveManageable
    private let bundleStore: KeyBundleStore

    init(
        secureEnclave: any SecureEnclaveManageable,
        bundleStore: KeyBundleStore
    ) {
        self.secureEnclave = secureEnclave
        self.bundleStore = bundleStore
    }

    /// Triggers device authentication and returns raw private-key bytes.
    /// Callers must zeroize the returned data after use.
    func unwrapPrivateKey(fingerprint: String) throws -> Data {
        let bundle = try bundleStore.loadBundle(fingerprint: fingerprint)
        let handle = try secureEnclave.reconstructKey(from: bundle.seKeyData)
        return try secureEnclave.unwrap(bundle: bundle, using: handle, fingerprint: fingerprint)
    }
}
