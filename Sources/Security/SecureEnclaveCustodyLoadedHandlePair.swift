import Foundation

/// Both reconstructed handles of one identity, produced inside a single
/// authorized operation window at generation time.
struct SecureEnclaveCustodyLoadedHandlePair {
    let signing: SecureEnclaveCustodyLoadedHandle
    let keyAgreement: SecureEnclaveCustodyLoadedHandle

    init(signing: SecureEnclaveCustodyLoadedHandle, keyAgreement: SecureEnclaveCustodyLoadedHandle) throws {
        _ = try SecureEnclaveCustodyHandlePair(
            signing: signing.binding,
            keyAgreement: keyAgreement.binding
        )
        self.signing = signing
        self.keyAgreement = keyAgreement
    }
}
