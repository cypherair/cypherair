import Foundation

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
